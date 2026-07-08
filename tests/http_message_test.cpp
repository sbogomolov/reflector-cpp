#include "reflector/http_message.h"

#include <gtest/gtest.h>

#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "reflector/util/delegate.h"

namespace {
using namespace reflector;

// Device and Reflector are the two ends of every rewrite here: the device's own address and the reflector
// listener that stands in for it (what a client on another subnet reaches). Responses swap Device->Reflector
// (Application-URL / Location); requests swap Reflector->Device (Host). A client's own address never appears
// in a rewritten header, so there is no Client endpoint.

// A device endpoint as captured: the LG TV on the IoT segment.
IpEndpoint Device(uint16_t port) {
    return IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), port};
}

// The reflector authority advertised to the client (a source_if address + an ephemeral listener port).
IpEndpoint Reflector(uint16_t port) {
    return IpEndpoint{IpAddress::FromV4Bytes(192, 168, 1, 2), port};
}

// Records every authority the framer offers it, and replaces `from` with `to`. The named rewriters below fix
// `from`/`to` per leg, so a test can assert both the substitution and which authorities were surfaced.
struct RecordingRewrite {
    RecordingRewrite(IpEndpoint from, IpEndpoint to) : from_{from}, to_{to} {}

    std::optional<IpEndpoint> operator()(const IpEndpoint& found) {
        seen.push_back(found);
        if (found == from_) {
            return to_;
        }
        return std::nullopt;
    }

    std::vector<IpEndpoint> seen;

private:
    IpEndpoint from_;
    IpEndpoint to_;
};

// The response leg: a device's URL headers (Application-URL, Location) carry its own REST endpoint, swapped
// for the reflector listener that stands in for it.
struct UrlRewrite : RecordingRewrite {
    UrlRewrite() : RecordingRewrite{Device(36866), Reflector(54321)} {}
};

// The request leg: the client's Host is the reflector listener it connected to (it never learns the device's
// address), swapped back to the device's own authority.
struct HostRewrite : RecordingRewrite {
    HostRewrite() : RecordingRewrite{Reflector(40000), Device(1461)} {}
};

// Binds a stateful test rewrite functor as a (non-owning) EndpointRewrite delegate; the functor must outlive
// the HttpFraming, which it does within each test's scope.
template <typename Rewrite>
HttpFraming::EndpointRewrite AsRewrite(Rewrite& rewrite) {
    return CreateDelegate<&Rewrite::operator()>(&rewrite);
}

// Drives Feed the way an owner would: keeps a receive buffer, appends each "read", and drains via Feed —
// forwarding header then body — until Feed consumes nothing more, retaining the unconsumed tail. `out`
// accumulates everything forwarded; `ok` goes false if Feed reports a malformed message.
struct Driver {
    explicit Driver(HttpFraming& f) : framing{&f} {}

    HttpFraming* framing;
    std::string buffer;
    std::string out;
    bool ok = true;

    void Read(std::string_view chunk) {
        if (!ok) {
            return;
        }
        buffer += chunk;
        std::string_view in{buffer};
        while (!in.empty()) {
            const auto r = framing->Feed(in);
            if (!r) {
                ok = false;
                return;
            }
            if (r->consumed == 0) {
                break;  // needs more bytes (an incomplete header)
            }
            out += r->header;
            out += r->body;
            in.remove_prefix(r->consumed);
        }
        buffer.erase(0, buffer.size() - in.size());  // keep only the unconsumed tail
    }
};

} // namespace

namespace reflector {

TEST(ParseAuthorityTest, BareHostPortReturnsEndpointAndSpan) {
    const std::string_view value = "10.1.3.80:36866";
    const auto a = ParseAuthority(value, /*bare=*/true);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->endpoint, Device(36866));
    EXPECT_EQ(value.substr(a->offset, a->length), "10.1.3.80:36866");
}

TEST(ParseAuthorityTest, BareHostWithoutPortDefaultsTo80) {
    const std::string_view value = "10.1.3.80";  // a Host header may omit the port (RFC 9110 7.2)
    const auto a = ParseAuthority(value, /*bare=*/true);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->endpoint, Device(80));
    EXPECT_EQ(value.substr(a->offset, a->length), "10.1.3.80");
}

TEST(ParseAuthorityTest, UrlAuthorityExcludesSchemeAndPath) {
    const std::string_view value = "http://10.1.3.80:36866/apps/Netflix";
    const auto a = ParseAuthority(value, /*bare=*/false);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->endpoint, Device(36866));
    EXPECT_EQ(value.substr(a->offset, a->length), "10.1.3.80:36866");
}

TEST(ParseAuthorityTest, UrlWithoutPortDefaultsTo80) {
    const std::string_view value = "http://10.1.3.80/dd.xml";  // an absolute http URL may omit the port
    const auto a = ParseAuthority(value, /*bare=*/false);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->endpoint, Device(80));
    EXPECT_EQ(value.substr(a->offset, a->length), "10.1.3.80");
}

TEST(ParseAuthorityTest, RejectsNonHttpAndMalformed) {
    EXPECT_FALSE(ParseAuthority("10.1.3.80:8008/x", /*bare=*/false).has_value());  // no http:// scheme
    EXPECT_FALSE(ParseAuthority("ahead http://10.1.3.80:8008/", /*bare=*/false).has_value());  // scheme not at the start
    EXPECT_FALSE(ParseAuthority("10.1.3.80:notaport", /*bare=*/true).has_value());  // colon, non-numeric port
    EXPECT_FALSE(ParseAuthority("10.1.3.80:80x", /*bare=*/true).has_value());       // trailing junk after the port
    EXPECT_FALSE(ParseAuthority("10.1.3.80:", /*bare=*/true).has_value());          // trailing colon, no port digits
    EXPECT_FALSE(ParseAuthority("10.1.3.80:0", /*bare=*/true).has_value());         // port 0 is invalid
    EXPECT_FALSE(ParseAuthority("10.1.3.80:99999", /*bare=*/true).has_value());     // port out of range
    EXPECT_FALSE(ParseAuthority("not-an-ip:8008", /*bare=*/true).has_value());      // host is not an IPv4 literal
}

TEST(ParseAuthorityTest, TerminatesAuthorityAtQueryOrFragment) {
    // A pathless URL with a query or fragment: the authority ends at '?'/'#' (RFC 3986), so the
    // host:port still parses and rewrites instead of folding the query into the port field.
    const auto query = ParseAuthority("http://10.1.3.80:8008?token=x", /*bare=*/false);
    ASSERT_TRUE(query.has_value());
    EXPECT_EQ(query->endpoint, Device(8008));
    EXPECT_EQ(std::string_view{"http://10.1.3.80:8008?token=x"}.substr(query->offset, query->length),
        "10.1.3.80:8008");

    const auto fragment = ParseAuthority("http://10.1.3.80#frag", /*bare=*/false);
    ASSERT_TRUE(fragment.has_value());
    EXPECT_EQ(fragment->endpoint, Device(80));
}

TEST(ParseAuthorityTest, AcceptsCaseInsensitiveHttpScheme) {
    const std::string_view value = "HTTP://10.1.3.80:8008/dd.xml";  // the scheme is case-insensitive (RFC 3986)
    const auto a = ParseAuthority(value, /*bare=*/false);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->endpoint, Device(8008));
    EXPECT_EQ(value.substr(a->offset, a->length), "10.1.3.80:8008");
}

TEST(HttpFramingTest, RewritesPortLessApplicationUrl) {
    // A device whose REST server is on port 80 advertises a port-less Application-URL; it is still parsed
    // (port 80 implied) and rewritten to the reflector listener.
    RecordingRewrite rewrite{Device(80), Reflector(54321)};
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read("HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.3.80/apps\r\nContent-Length: 0\r\n\r\n");
    EXPECT_TRUE(d.ok);
    EXPECT_NE(d.out.find("Application-URL: http://192.168.1.2:54321/apps"), std::string::npos) << d.out;
    EXPECT_EQ(d.out.find("10.1.3.80"), std::string::npos) << d.out;  // device authority fully spliced out
}

TEST(HttpFramingTest, ForwardsUnchangedWhenNothingIsRewritten) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    const std::string msg{
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 3\r\n\r\n"
        "abc"};
    d.Read(msg);
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out, msg);
    EXPECT_TRUE(rewrite.seen.empty());
}

TEST(HttpFramingTest, HeaderIsRewrittenCopyBodyIsAZeroCopySliceOfInput) {
    // Locks the two-view contract: `header` is the rewritten copy (in HttpFraming's scratch), `body` points
    // straight into the fed input, and `consumed` covers the whole message.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    const std::string msg =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 3\r\n\r\n"
        "abc";
    const auto r = framing.Feed(msg);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->body, "abc");
    EXPECT_EQ(r->body.data(), msg.data() + (msg.size() - 3));  // zero-copy: points at "abc" within the input
    EXPECT_EQ(r->header,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 3\r\n\r\n");
    EXPECT_EQ(r->consumed, msg.size());
}

TEST(HttpFramingTest, IncompleteHeaderConsumesNothing) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    const auto r = framing.Feed(
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->consumed, 0u);
    EXPECT_TRUE(r->header.empty());
    EXPECT_TRUE(r->body.empty());
}

TEST(HttpFramingTest, ReassemblesHeaderBlockSplitAcrossFeeds) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:368");
    EXPECT_TRUE(d.out.empty());  // header still accumulating -> nothing forwarded yet
    d.Read(
        "66/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 0\r\n\r\n");
}

TEST(HttpFramingContentLengthTest, RewritesApplicationUrlAndForwardsBodyVerbatim) {
    const std::string body =
        "<?xml version=\"1.0\"?>"
        "<root><device><friendlyName>LG TV</friendlyName>"
        "<X_DIALEX_AppsListURL>/WebOS_Dial/apps</X_DIALEX_AppsListURL></device></root>";
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);

    const std::string expected =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    EXPECT_EQ(d.out, expected);
    ASSERT_EQ(rewrite.seen.size(), 1u);
    EXPECT_EQ(rewrite.seen[0], (IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), 36866}));
}

TEST(HttpFramingContentLengthTest, MatchesApplicationUrlHeaderNameCaseInsensitively) {
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "application-url: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "application-url: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 0\r\n\r\n");
}

TEST(HttpFramingContentLengthTest, ReassemblesBodySplitAcrossFeeds) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n\r\n"
        "ab");
    d.Read("cde");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n\r\n"
        "abcde");
}

TEST(HttpFramingContentLengthTest, ContinuingBodyFeedCarriesNoHeader) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    const auto r1 = framing.Feed(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n\r\n"
        "ab");
    ASSERT_TRUE(r1.has_value());
    EXPECT_FALSE(r1->header.empty());  // the first feed carries the (rewritten) header
    EXPECT_EQ(r1->body, "ab");
    const auto r2 = framing.Feed("cde");
    ASSERT_TRUE(r2.has_value());
    EXPECT_TRUE(r2->header.empty());   // continuing the body: header already sent
    EXPECT_EQ(r2->body, "cde");
    EXPECT_EQ(r2->consumed, 3u);
}

TEST(HttpFramingMiscTest, ForwardsABodyLargerThanTheHeaderCap) {
    // The header cap bounds the header block; the body is a view into the owner's buffer, never copied or
    // capped by the framer, so a body well past MAX_HEADER_BYTES forwards intact.
    const std::string body(4 * 1024, 'x');
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out, message);
}

TEST(HttpFramingChunkedTest, RewritesUppercaseLocationAndForwardsChunksVerbatim) {
    const std::string message =
        "HTTP/1.1 201 Created\r\n"
        "LOCATION: http://10.1.3.80:36866/apps/YouTube/run\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "1a\r\n<service><ok>true</ok></s>\r\n"
        "0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);

    EXPECT_EQ(d.out,
        "HTTP/1.1 201 Created\r\n"
        "LOCATION: http://192.168.1.2:54321/apps/YouTube/run\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "1a\r\n<service><ok>true</ok></s>\r\n"
        "0\r\n\r\n");
}

TEST(HttpFramingChunkedTest, ReassemblesChunkBoundariesSplitAcrossFeeds) {
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nab");
    d.Read(
        "cde\r\n"
        "0\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nabcde\r\n"
        "0\r\n\r\n");
}

TEST(HttpFramingMiscTest, RewritesRequestHostFromReflectorToDevice) {
    // The request leg: the client sends Host = the reflector listener it connected to (it never learns the
    // device's real address), and the framer swaps it back to the device's own authority.
    const std::string message =
        "GET / HTTP/1.1\r\n"
        "Host: 192.168.1.2:40000\r\n"
        "Connection: keep-alive\r\n\r\n";
    HostRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Request);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out,
        "GET / HTTP/1.1\r\n"
        "Host: 10.1.3.80:1461\r\n"
        "Connection: keep-alive\r\n\r\n");
    ASSERT_EQ(rewrite.seen.size(), 1u);
    EXPECT_EQ(rewrite.seen[0], Reflector(40000));  // the framer surfaced the request's Host authority
}

TEST(HttpFramingMiscTest, RefusesOversizedHeaderBlock) {
    // A header block past MAX_HEADER_BYTES (2 KB) with no terminator is malformed: the framer refuses it so
    // the owner closes — the bound on a peer that never sends the blank line.
    std::string message =
        "GET / HTTP/1.1\r\n"
        "X-Pad: ";
    message.append(3 * 1024, 'a');  // exceeds the header cap, no terminating blank line
    HostRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Request);
    Driver d{framing};
    d.Read(message);
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, RefusesOverCapHeaderEvenWhenTerminated) {
    // The cap must not depend on TCP segmentation: a fully terminated header block past the cap,
    // delivered in one read, is refused just like an unterminated one — otherwise a coalesced read
    // could slip a header through that a byte-at-a-time one could not.
    std::string message =
        "HTTP/1.1 200 OK\r\n"
        "X-Pad: ";
    message.append(3 * 1024, 'a');
    message.append("\r\n\r\n");  // terminated, but the block is over the cap
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, RefusesConflictingContentLengths) {
    // Two differing Content-Length headers are a request-smuggling vector (RFC 9112 6.3): refuse
    // rather than pick a last-wins length that a downstream peer might frame differently.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Content-Length: 100\r\n\r\n");
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, AllowsIdenticalDuplicateContentLength) {
    // Identical repeats agree on the framing, so they are tolerated (only a conflict is fatal).
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi");
    EXPECT_TRUE(d.ok);
    EXPECT_TRUE(d.out.ends_with("hi"));
}

TEST(HttpFramingMiscTest, RefusesHeadRequest) {
    // A HEAD response is bodyless but may still carry Content-Length, which this framer would await
    // as phantom body bytes and desync the keep-alive stream. Refuse HEAD at the request side.
    HostRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Request);
    Driver d{framing};
    d.Read(
        "HEAD / HTTP/1.1\r\n"
        "Host: 192.168.1.2:40000\r\n\r\n");
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, FramesTwoPipelinedKeepAliveMessages) {
    const std::string first =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi";
    const std::string second =
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(first + second);
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n\r\n");
    EXPECT_EQ(rewrite.seen.size(), 2u);  // both messages' Application-URL headers surfaced
}

TEST(HttpFramingTest, EmitsAMessageThenCarriesAPartialNextHeader) {
    // A pipelined read whose boundary lands mid the *second* message's header, right after the first was
    // rewritten. The first read forwards msg1 and leaves msg2's partial header unconsumed (it stays in the
    // owner's buffer); the second read completes and rewrites msg2.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://10.1.3.80:36");  // msg2 header split mid-value
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi");
    d.Read("866/run\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://192.168.1.2:54321/run\r\n\r\n");
    EXPECT_EQ(rewrite.seen.size(), 2u);
}

TEST(HttpFramingTest, RewritesMultipleAuthorityHeadersInOneMessage) {
    // Two target headers in one block: each is spliced in place, and the first edit (which shifts the rest of
    // header_) must not throw off the scan of the second.
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Location: http://10.1.3.80:36866/apps/YouTube\r\n"
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Location: http://192.168.1.2:54321/apps/YouTube\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_EQ(rewrite.seen.size(), 2u);
}

TEST(HttpFramingTest, ScanDoesNotShortCircuitWhenAnEarlierHeaderIsAccepted) {
    // Two URL headers in one message: the rewrite accepts the FIRST (Device(36866) -> Reflector) and
    // declines the SECOND (a different device authority it doesn't own). The scan must visit BOTH headers
    // (no short-circuit after the accepted splice), splicing the first and leaving the second verbatim, and
    // still consume the whole message. This is the http_message half of the dial_proxy "second URL fails"
    // partial-rewrite-then-Abort case: there the framer must still surface the second (unroutable) authority
    // so the owner can drop the connection rather than leak it.
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"     // owned -> spliced
        "Location: http://10.1.3.80:40000/apps/YouTube\r\n"   // NOT owned -> declined, left verbatim
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;  // only swaps 10.1.3.80:36866
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    const auto r = framing.Feed(message);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->consumed, message.size());  // the whole message consumed despite the second decline
    EXPECT_EQ(r->header,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"  // first spliced
        "Location: http://10.1.3.80:40000/apps/YouTube\r\n"   // second left verbatim
        "Content-Length: 0\r\n\r\n");
    ASSERT_EQ(rewrite.seen.size(), 2u);                       // BOTH headers surfaced — no short-circuit
    EXPECT_EQ(rewrite.seen[0], Device(36866));
    EXPECT_EQ(rewrite.seen[1], (IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), 40000}));
}

TEST(HttpFramingTest, LeavesAuthorityUnchangedWhenRewriteDeclines) {
    // ParseAuthority surfaces a valid IP:port, but the rewrite returns nullopt for an endpoint it doesn't own.
    // The header passes through untouched, yet the endpoint was offered — distinguishing this from a value the
    // framer never parsed.
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:9999/apps\r\n"
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;  // only swaps 10.1.3.80:36866
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out, message);
    ASSERT_EQ(rewrite.seen.size(), 1u);
    EXPECT_EQ(rewrite.seen[0], Device(9999));
}

TEST(HttpFramingTest, LeavesHostnameUrlAuthorityUnchanged) {
    // Only an IPv4 host:port is a target; a hostname authority is not parseable as an IP, so it is never
    // surfaced and passes through verbatim.
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://dial.example.com:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out, message);
    EXPECT_TRUE(rewrite.seen.empty());
}

TEST(HttpFramingTest, LeavesNonHttpUrlsUnchanged) {
    // A URL whose scheme is not http:// is out of scope — it is not surfaced and passes through verbatim.
    // (A port-less http URL, by contrast, IS in scope now — see RewritesPortLessApplicationUrl.)
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: https://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out, message);
    EXPECT_TRUE(rewrite.seen.empty());
}

TEST(HttpFramingChunkedTest, ChunkedTakesPrecedenceOverContentLength) {
    // RFC 7230 3.3.3: with both present, Transfer-Encoding: chunked wins and Content-Length is ignored. The
    // (deliberately wrong) Content-Length must not bound the body — a following pipelined message proves msg1
    // ended at the chunk terminator, since only then is msg2 framed and its Application-URL rewritten.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 999\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nabcde\r\n"
        "0\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 999\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nabcde\r\n"
        "0\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    ASSERT_EQ(rewrite.seen.size(), 1u);  // msg2 was framed — only possible if chunked, not CL=999, ended msg1
}

TEST(HttpFramingChunkedTest, TreatsChunkedCodingCaseInsensitivelyInACodingList) {
    // RFC 7230: the transfer-coding name is case-insensitive and chunked may end a coding list. "gzip, CHUNKED"
    // must frame as chunked — otherwise the chunk bytes would be misread as the next message's header.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: gzip, CHUNKED\r\n\r\n"
        "3\r\nabc\r\n"
        "0\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: gzip, CHUNKED\r\n\r\n"
        "3\r\nabc\r\n"
        "0\r\n\r\n");
}

TEST(HttpFramingChunkedTest, DropsChunkExtensionsWhenSizingButForwardsThemVerbatim) {
    // A chunk-size line may carry ";ext" parameters; they are ignored for the size but, like all body bytes,
    // forwarded unchanged.
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "3;name=value\r\nabc\r\n"
        "0\r\n\r\n";
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_EQ(d.out, message);
}

TEST(HttpFramingMiscTest, RefusesMalformedContentLength) {
    // A Content-Length whose value isn't a number is malformed: reject the message so the owner closes, rather
    // than guess a body length.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: not-a-number\r\n\r\n");
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, RefusesContentLengthWithTrailingJunk) {
    // from_chars stops at the first non-digit and reports success, so a lenient parse would read "5abc" as 5
    // and frame a 5-byte body, mis-parsing the trailing "abc" as the next message. Require the whole value to
    // be the number: reject so the owner closes (matching ParseAuthority's port strictness).
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5abc\r\n\r\nhello");
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, AcceptsContentLengthWithTrailingWhitespace) {
    // Trailing OWS after the number is legal (RFC 7230 §3.2.4) and must NOT be mistaken for junk: the value is
    // still 5, and the body frames normally.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5 \r\n\r\nhello");
    EXPECT_TRUE(d.ok);
    EXPECT_TRUE(d.out.ends_with("\r\n\r\nhello")) << d.out;  // the 5-byte body forwarded in full
}

TEST(HttpFramingMiscTest, RefusesMalformedChunkSize) {
    // A chunk-size line that isn't valid hex is malformed: reject so the owner closes.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "zz\r\n");
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingMiscTest, RefusesChunkSizeThatWouldOverflowTheFramer) {
    // SIZE_MAX and SIZE_MAX-1 parse as valid hex, but adding the chunk's trailing CRLF would wrap
    // chunk_remaining_ to 1 or 0 and desynchronize the framer: reject so the owner closes.
    for (const size_t chunk_size : {std::numeric_limits<size_t>::max(),
                                    std::numeric_limits<size_t>::max() - 1}) {
        UrlRewrite rewrite;
        HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
        Driver d{framing};
        d.Read(std::format("HTTP/1.1 200 OK\r\n"
                           "Transfer-Encoding: chunked\r\n\r\n"
                           "{:x}\r\n",
                           chunk_size));
        EXPECT_FALSE(d.ok);
    }
}

TEST(HttpFramingChunkedTest, AcceptsTheLargestFrameableChunkSize) {
    // SIZE_MAX-2 is the boundary: chunk DATA + CRLF fits size_t exactly, so the guard must not
    // over-reject it and the chunk bytes stream through opaquely.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(std::format("HTTP/1.1 200 OK\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n"
                       "{:x}\r\ndata",
                       std::numeric_limits<size_t>::max() - 2));
    EXPECT_TRUE(d.ok);
    EXPECT_TRUE(d.out.ends_with("data"));
}

TEST(HttpFramingMiscTest, RefusesOversizedChunkSizeLine) {
    // A chunk-size line that never reaches its CRLF is bounded like the header block: past the cap, reject.
    std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n";
    message.append(300, 'a');  // a chunk-size line well past MAX_CHUNK_LINE_BYTES (256), no CRLF
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingTest, RewritesMultipleHeadersThenFramesTheNextMessage) {
    // Combines two stressors: msg1 carries two length-changing splices (Application-URL + Location) and a
    // body, then a second message follows. The next message must frame from the right offset — consumed
    // tracks the original input bytes, not the grown rewritten header.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Location: http://10.1.3.80:36866/apps/YouTube\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Location: http://192.168.1.2:54321/apps/YouTube\r\n"
        "Content-Length: 2\r\n\r\n"
        "hi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n\r\n");
    EXPECT_EQ(rewrite.seen.size(), 3u);  // two splices in msg1, one in msg2
}

TEST(HttpFramingChunkedTest, FramesMultipleChunksThenTheNextMessage) {
    // A chunked body with more than one data chunk, then a following message. Each chunk's size line, data,
    // and trailing CRLF must be consumed in turn, the 0-chunk must end the body, and only then is the next
    // message's header framed and rewritten.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "3\r\nabc\r\n"
        "5\r\nhello\r\n"
        "0\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "3\r\nabc\r\n"
        "5\r\nhello\r\n"
        "0\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    ASSERT_EQ(rewrite.seen.size(), 1u);  // only msg2's Application-URL — proves msg1 ended at the 0-chunk
}

TEST(HttpFramingChunkedTest, ForwardsChunkedTrailersVerbatim) {
    // A trailer section after the last chunk (RFC 7230 §4.1) is relayed opaquely: forwarded byte-for-byte,
    // the empty line ends the body, and a following pipelined message is then framed and its URL rewritten.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "0\r\n"
        "X-Checksum: abc123\r\n"
        "X-Signature: deadbeef\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "0\r\n"
        "X-Checksum: abc123\r\n"
        "X-Signature: deadbeef\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 0\r\n\r\n");
    ASSERT_EQ(rewrite.seen.size(), 1u);  // only msg2's Application-URL — proves the trailers ended msg1 cleanly
}

TEST(HttpFramingChunkedTest, ReassemblesChunkedTrailerSplitAcrossFeeds) {
    // The trailer section can arrive in arbitrary fragments — mid trailer-field line, and mid the closing
    // CRLF. The framer holds an unterminated line for the next feed and still forwards everything verbatim.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "0\r\n"
        "X-Che");               // trailer field split mid-line
    d.Read("cksum: abc123\r");  // line continues; its own CRLF is split across this feed and the next
    d.Read("\n\r");             // field CRLF completes, and the closing CRLF is split too
    d.Read("\n");               // closing CRLF completes — the empty line ends the body
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "0\r\n"
        "X-Checksum: abc123\r\n\r\n");
}

TEST(HttpFramingMiscTest, RefusesOversizedTrailerLine) {
    // A trailer line that never reaches its CRLF is bounded like the chunk-size line: past the cap, reject.
    std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n";
    message.append(HttpFraming::MAX_TRAILER_LINE_BYTES + 1, 'a');  // a trailer line past the cap, no CRLF
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(message);
    EXPECT_FALSE(d.ok);
}

TEST(HttpFramingCloseDelimitedTest, StreamsResponseWithNoLengthAsBodyUntilClose) {
    // A response with neither Content-Length nor chunked encoding (HTTP/1.0, or HTTP/1.1 Connection: close) is
    // close-delimited (RFC 7230 §3.3.3 rule 7): the body streams opaquely across feeds with no in-band end —
    // the owner ends it at connection close. The header is still rewritten; body bytes that resemble a new
    // status line stay body, never re-framed (the mis-framing bug this fixes).
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.0 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n\r\n"
        "<dial>part1");
    d.Read("HTTP/1.1 still body\r\npart2");  // header-looking bytes inside the body stay body
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out,
        "HTTP/1.0 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n\r\n"
        "<dial>part1HTTP/1.1 still body\r\npart2");
    ASSERT_EQ(rewrite.seen.size(), 1u);  // only the real header's Application-URL — the body is never re-scanned
}

TEST(HttpFramingCloseDelimitedTest, RequestWithNoLengthIsBodylessNotCloseDelimited) {
    // A request with neither Content-Length nor chunked encoding has a zero-length body (RFC 7230 §3.3.3
    // rule 6) — NOT close-delimited. Two pipelined requests must both frame; a close-delimited first would
    // swallow the second as its body.
    HostRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Request);
    Driver d{framing};
    d.Read(
        "GET /a HTTP/1.1\r\nHost: 192.168.1.2:40000\r\n\r\n"
        "GET /b HTTP/1.1\r\nHost: 192.168.1.2:40000\r\n\r\n");
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(d.out,
        "GET /a HTTP/1.1\r\nHost: 10.1.3.80:1461\r\n\r\n"
        "GET /b HTTP/1.1\r\nHost: 10.1.3.80:1461\r\n\r\n");
    EXPECT_EQ(rewrite.seen.size(), 2u);  // both framed — the first request was not close-delimited
}

TEST(HttpFramingCloseDelimitedTest, BodylessStatusResponsesAreNotCloseDelimited) {
    // 1xx/204/304 responses are bodyless even with no Content-Length (RFC 7230 §3.3.3 rule 1), so they must
    // NOT be treated as close-delimited: a following pipelined response on the same connection still frames.
    const auto check = [](std::string_view status_line) {
        UrlRewrite rewrite;
        HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
        Driver d{framing};
        d.Read(std::string{status_line} +
            "\r\nApplication-URL: http://10.1.3.80:36866/apps\r\n\r\n"
            "HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.3.80:36866/apps\r\nContent-Length: 0\r\n\r\n");
        EXPECT_TRUE(d.ok) << status_line;
        EXPECT_EQ(rewrite.seen.size(), 2u) << status_line;  // both framed — the status did not swallow #2 as body
    };
    check("HTTP/1.1 204 No Content");
    check("HTTP/1.1 304 Not Modified");
    check("HTTP/1.1 100 Continue");
}

TEST(HttpFramingCloseDelimitedTest, BodylessStatusWithContentLengthHasNoBody) {
    // RFC 7230 §3.3.3 rule 1 overrides the framing headers: a 304 that (wrongly) carries a Content-Length is
    // still bodyless. The CL must frame no phantom body, or it would swallow the start of the next response.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 304 Not Modified\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 50\r\n\r\n"
        "HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.3.80:36866/apps\r\nContent-Length: 0\r\n\r\n");
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(rewrite.seen.size(), 2u);  // both framed — the 304's Content-Length framed no body
}

TEST(HttpFramingCloseDelimitedTest, ExplicitZeroContentLengthResponseIsNotCloseDelimited) {
    // Content-Length: 0 is an explicit empty body, distinct from the "no length header" case — it must stay
    // bodyless, so a following pipelined response frames rather than being swallowed.
    UrlRewrite rewrite;
    HttpFraming framing(AsRewrite(rewrite), HttpFraming::MessageType::Response);
    Driver d{framing};
    d.Read(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.3.80:36866/apps\r\nContent-Length: 0\r\n\r\n"
        "HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.3.80:36866/apps\r\nContent-Length: 0\r\n\r\n");
    EXPECT_TRUE(d.ok);
    EXPECT_EQ(rewrite.seen.size(), 2u);  // both framed — CL:0 is bodyless, not close-delimited
}

}  // namespace reflector
