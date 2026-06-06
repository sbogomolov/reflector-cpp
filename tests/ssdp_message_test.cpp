#include "reflector/ssdp_message.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

using namespace reflector;

namespace {

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

std::string_view AsText(const std::vector<std::byte>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

} // namespace

TEST(SsdpMessageTest, ClassifiesMSearchAsSearch) {
    const auto payload = Bytes(
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n");
    EXPECT_EQ(ClassifySsdpMessage(payload), SsdpMessageKind::Search);
}

TEST(SsdpMessageTest, ClassifiesNotifyAsAdvertisement) {
    const auto payload = Bytes(
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:alive\r\n\r\n");
    EXPECT_EQ(ClassifySsdpMessage(payload), SsdpMessageKind::Advertisement);
}

TEST(SsdpMessageTest, RejectsHttpResponseStatusLine) {
    // The unicast M-SEARCH response: its own message type, never relayed on the multicast channel.
    const auto payload = Bytes("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n");
    EXPECT_EQ(ClassifySsdpMessage(payload), std::nullopt);
}

TEST(SsdpMessageTest, RejectsPayloadTooShortForToken) {
    EXPECT_EQ(ClassifySsdpMessage(Bytes("M-SE")), std::nullopt);
    // "NOTIFY" (6 bytes) is one short of the 7-byte "NOTIFY " token, so it is rejected on length.
    EXPECT_EQ(ClassifySsdpMessage(Bytes("NOTIFY")), std::nullopt);
    EXPECT_EQ(ClassifySsdpMessage(std::span<const std::byte>{}), std::nullopt);
}

TEST(SsdpMessageTest, RejectsLowercaseMethodToken) {
    // Match is case-sensitive against the uppercase spec literals.
    EXPECT_EQ(ClassifySsdpMessage(Bytes("m-search * HTTP/1.1\r\n")), std::nullopt);
}

TEST(SsdpMessageTest, RejectsMethodTokenWithoutTrailingSpace) {
    // The trailing space separates the method from the request URI; without it the leading bytes are
    // not a start-line method token.
    EXPECT_EQ(ClassifySsdpMessage(Bytes("NOTIFYING * HTTP/1.1\r\n")), std::nullopt);
    // Exactly the token's length but the seventh byte is 'X', not a space — rejected on content, not
    // by the length guard (the too-short case is covered separately above).
    EXPECT_EQ(ClassifySsdpMessage(Bytes("NOTIFYX")), std::nullopt);
}

TEST(SsdpMessageTest, ParsesMxHeaderValue) {
    const auto payload = Bytes(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMX: 4\r\nST: ssdp:all\r\n\r\n");
    EXPECT_EQ(ParseMSearchMx(payload), 4);
}

TEST(SsdpMessageTest, ClampsMxToOneToFive) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: 0\r\n\r\n")), 1);
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: 9\r\n\r\n")), 5);
}

TEST(SsdpMessageTest, ReturnsNulloptWhenMxAbsentOrUnparseable) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")), std::nullopt);
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: abc\r\n\r\n")), std::nullopt);
}

TEST(SsdpMessageTest, ParsesMxHeaderNameCaseInsensitively) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nmx: 2\r\n\r\n")), 2);
}

// --- DIAL service classification ---

TEST(SsdpMessageTest, DetectsTheDialServiceUrn) {
    const auto payload = Bytes(
        "HTTP/1.1 200 OK\r\n"
        "LOCATION: http://192.168.1.5:8008/dd.xml\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(payload));
}

TEST(SsdpMessageTest, DialServiceUrnMatchIsCaseInsensitive) {
    const auto payload = Bytes(
        "NOTIFY * HTTP/1.1\r\nNT: URN:Dial-Multiscreen-Org:Service:Dial:1\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(payload));
}

TEST(SsdpMessageTest, RejectsNonDialServiceMessages) {
    const auto payload = Bytes(
        "NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n");
    EXPECT_FALSE(IsDialServiceMessage(payload));
    EXPECT_FALSE(IsDialServiceMessage(std::span<const std::byte>{}));
}

// --- LOCATION authority parse ---

TEST(SsdpMessageTest, ParsesLocationAuthorityWithPort) {
    const auto payload = Bytes(
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.5:8008/dd.xml\r\n\r\n");
    const auto location = ParseDialLocationAuthority(payload);
    ASSERT_TRUE(location.has_value());
    EXPECT_EQ(location->endpoint, (IpEndpoint{IpAddress::FromString("192.168.1.5").value(), 8008}));
    EXPECT_EQ(AsText(payload).substr(location->offset, location->length), "192.168.1.5:8008");
}

TEST(SsdpMessageTest, ParsesPortLessLocationDefaultingTo80) {
    // An absolute http URL may omit the port (RFC 3986); the device is then on :80 and the authority span
    // covers just the host, so the SSDP path still splices a reflector "addr:port" over it.
    const auto payload = Bytes(
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.5/dd.xml\r\n\r\n");
    const auto location = ParseDialLocationAuthority(payload);
    ASSERT_TRUE(location.has_value());
    EXPECT_EQ(location->endpoint, (IpEndpoint{IpAddress::FromString("192.168.1.5").value(), 80}));
    EXPECT_EQ(AsText(payload).substr(location->offset, location->length), "192.168.1.5");
}

TEST(SsdpMessageTest, ParsesLocationHeaderNameCaseInsensitively) {
    const auto payload = Bytes(
        "HTTP/1.1 200 OK\r\nlocation: http://10.0.0.2:8009/setup.xml\r\n\r\n");  // lowercase header name
    const auto location = ParseDialLocationAuthority(payload);
    ASSERT_TRUE(location.has_value());
    EXPECT_EQ(location->endpoint, (IpEndpoint{IpAddress::FromString("10.0.0.2").value(), 8009}));
}

TEST(SsdpMessageTest, LocationAuthorityNulloptWithoutLocationHeader) {
    const auto payload = Bytes(
        "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\n\r\n");
    EXPECT_EQ(ParseDialLocationAuthority(payload), std::nullopt);
}

TEST(SsdpMessageTest, LocationAuthorityRejectsMalformed) {
    EXPECT_EQ(ParseDialLocationAuthority(Bytes("LOCATION: ftp://192.168.1.5:8008/\r\n\r\n")),
        std::nullopt);  // non-http scheme
    EXPECT_EQ(ParseDialLocationAuthority(Bytes("LOCATION: http://192.168.1.5:bad/\r\n\r\n")),
        std::nullopt);  // non-numeric port
    EXPECT_EQ(ParseDialLocationAuthority(Bytes("LOCATION: http://not-an-ip:8008/\r\n\r\n")),
        std::nullopt);  // host is not an IP literal
}

TEST(SsdpMessageTest, LogsWhenLocationIsPresentButUnparseable) {
    const ScopedMinLogLevel level{LogLevel::Info};
    // The LOCATION header is there but its URL can't be rewritten (here: a hostname, not an IPv4 literal).
    // That is anomalous and is surfaced, with the offending URL, so the dropped rewrite is visible.
    const std::string output = CaptureStdout([&] {
        EXPECT_EQ(ParseDialLocationAuthority(Bytes("LOCATION: http://mytv.local:8008/dd.xml\r\n\r\n")),
            std::nullopt);
    });
    EXPECT_NE(output.find("mytv.local:8008"), std::string::npos) << output;
}

TEST(SsdpMessageTest, DoesNotLogWhenLocationHeaderIsAbsent) {
    const ScopedMinLogLevel level{LogLevel::Info};
    // A DIAL ssdp:byebye legitimately carries no LOCATION; the absence is normal and must stay silent.
    const std::string output = CaptureStdout([&] {
        EXPECT_EQ(ParseDialLocationAuthority(Bytes(
            "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:byebye\r\n\r\n")),
            std::nullopt);
    });
    EXPECT_EQ(output.find("LOCATION"), std::string::npos) << output;
}

TEST(SsdpMessageTest, DialServiceUrnMatchIsVersionAgnostic) {
    // The needle is the URN prefix with the ":1" dropped, so an unversioned URN and any version both match.
    EXPECT_TRUE(IsDialServiceMessage(Bytes(
        "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial\r\n\r\n")));     // no version
    EXPECT_TRUE(IsDialServiceMessage(Bytes(
        "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:2\r\n\r\n")));   // version 2
}

TEST(SsdpMessageTest, EmptyLocationValueReturnsNulloptSilently) {
    const ScopedMinLogLevel level{LogLevel::Info};
    // A LOCATION header with an empty (whitespace-only) value: nullopt, and NOT the unparseable-URL log
    // (there is no URL to name) — that path is distinct from a present-but-malformed URL.
    const std::string output = CaptureStdout([&] {
        EXPECT_EQ(ParseDialLocationAuthority(Bytes("HTTP/1.1 200 OK\r\nLOCATION:   \r\n\r\n")), std::nullopt);
    });
    EXPECT_EQ(output.find("not a rewritable"), std::string::npos) << output;
}

TEST(SsdpMessageTest, UsesTheFirstLocationHeader) {
    const auto payload = Bytes(
        "HTTP/1.1 200 OK\r\n"
        "LOCATION: http://192.168.1.5:8008/dd.xml\r\n"
        "LOCATION: http://10.0.0.9:9000/other.xml\r\n\r\n");
    const auto location = ParseDialLocationAuthority(payload);
    ASSERT_TRUE(location.has_value());
    EXPECT_EQ(location->endpoint, (IpEndpoint{IpAddress::FromString("192.168.1.5").value(), 8008}));  // first wins
}
