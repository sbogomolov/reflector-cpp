#include "reflector/ssdp_message.h"

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
