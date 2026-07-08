#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "reflector/ip_endpoint.h"
#include "reflector/util/delegate.h"

namespace reflector {

// An HTTP authority ("host:port", or a bare "host" when the port is omitted) parsed out of a header value
// or URL, with its byte span within that value so a caller can splice a replacement over exactly that text.
// An omitted port defaults to 80 (the http scheme default, RFC 3986); `length` then covers just the host.
// Shared by HttpFraming (Host / Application-URL / Location on the TCP path) and the SSDP LOCATION rewrite.
struct Authority {
    IpEndpoint endpoint;
    size_t offset;  // start of the "host[:port]" substring within the parsed value
    size_t length;  // its length, so the replacement is spliced over exactly the authority text
};

// Parses the authority from a header value. `bare` (a Host value) treats the whole value as the authority;
// otherwise (an Application-URL / Location / SSDP LOCATION value) it expects an "http://host[:port]..." URL.
// nullopt when there is no http scheme/authority, a host that is not an IPv4 literal, or a malformed explicit
// port. A missing port is not an error — it defaults to 80.
[[nodiscard]] std::optional<Authority> ParseAuthority(std::string_view value, bool bare);

// Per-direction incremental HTTP/1.1 framing + authority-header rewrite. The owner reads into its own
// buffer and feeds a contiguous view; HttpFraming copies only the header (to rewrite Host / Application-URL
// / Location authorities), leaves the body in place, and reports back what to forward and how much of the
// input it consumed. The owner forwards `header` then `body` (e.g. one writev) and drops `consumed` bytes
// from its buffer. The header is copied because rewriting changes it; the body is a zero-copy slice of the
// fed input. Each Feed yields at most one message's worth — a complete header plus as much of its body as
// arrived — so the owner loops Feed over its buffer until consumed == 0 (need more bytes), then reads more.
//
// Body framing follows RFC 7230 §3.3.3 for what DIAL needs: a Content-Length body, a Transfer-Encoding:
// chunked body, no body, or — for a response — a close-delimited body (no Content-Length and no chunked
// encoding, the body running until the connection closes; rule 7, Phase::BodyUntilClose, ended by the owner
// on EOF). Direction matters, so the framer is told its MessageType and reads the response status: a request
// with neither framing header is bodyless (rule 6), and a 1xx/204/304 response is bodyless whatever headers
// it carries (rule 1).
// A HEAD request is refused outright: its response is bodyless even with a Content-Length, but the framer
// can't tell — that needs the paired request method, which lives in the opposite direction's framer. DIAL
// issues no HEAD, so refusing (drop-and-close) is cheaper than correlating methods across the two framers.
class HttpFraming {
public:
    // Called once per rewritable authority header — Host (requests), Application-URL / Location
    // (responses), matched case-insensitively. `found` is the authority parsed from the header. Return the
    // replacement, or nullopt to leave the header unchanged. Supplied per direction by DialProxy.
    using EndpointRewrite = Delegate<std::optional<IpEndpoint>(const IpEndpoint& found)>;

    // The forwardable result of one Feed. `header` is the rewritten header block (a view into HttpFraming's
    // own scratch), empty while a body is still streaming across feeds. `body` is a slice of the fed input
    // (zero-copy), possibly empty. The owner forwards header then body together. `consumed` is how many fed
    // bytes to drop; 0 means nothing was forwardable yet (an incomplete header) — read more and feed again.
    // Both views are valid until the next Feed (which reuses the scratch) or until the owner advances its
    // buffer past `consumed`.
    struct Output {
        std::string_view header;
        std::string_view body;
        size_t consumed = 0;
    };

    // A header block reaching this length without its terminating blank line is refused (Feed -> nullopt,
    // the owner closes), so a peer that never ends its headers can't grow the buffer unbounded. It also
    // FLOORS the DIAL proxy's per-connection receive buffer, which must EXCEED this so the over-cap refusal
    // fires before the buffer fills — otherwise the always-armed reader livelocks (static_assert in dial_proxy.h).
    static constexpr size_t MAX_HEADER_BYTES = 2 * 1024;

    // The same unterminated-line guard for a chunk-size line (a hex length + optional chunk extensions).
    static constexpr size_t MAX_CHUNK_LINE_BYTES = 256;

    // The same guard for one trailer field after the last chunk (RFC 7230 §4.1), relayed opaquely. Roomier
    // than a chunk-size line because a trailer value can be sizable (e.g. a base64 signature digest). Kept
    // <= MAX_HEADER_BYTES so the DIAL receive buffer, which already exceeds that, bounds it too.
    static constexpr size_t MAX_TRAILER_LINE_BYTES = 1024;

    // Which side this framer parses. Only a response can be close-delimited — a body that runs until the
    // connection closes (RFC 7230 §3.3.3 rule 7). A request with no Content-Length and no chunked encoding is
    // bodyless (rule 6), so the framer must know its direction. DialProxy builds one of each per connection.
    enum class MessageType : uint8_t { Request, Response };

    HttpFraming(EndpointRewrite rewrite, MessageType type);

    // Feed a contiguous view of the owner's buffered bytes. nullopt = a malformed or over-cap message (the
    // owner closes); otherwise the forwardable Output.
    [[nodiscard]] std::optional<Output> Feed(std::string_view input);

private:
    // Accumulating the start line + header block, or streaming a body of a known shape. BodyUntilClose is the
    // close-delimited response body (no Content-Length, no chunking): streamed opaquely until the close.
    enum class Phase : uint8_t { Header, BodyContentLength, BodyChunked, BodyChunkedDone, BodyUntilClose };

    // Rewrites the authority headers in header_ in place and sets the body phase from its framing; returns
    // false on a malformed header. header_ holds exactly the header block, so it scans [0, header_.size()).
    bool ScanAndRewriteHeader();

    EndpointRewrite rewrite_;

    Phase phase_ = Phase::Header;
    MessageType type_;              // request vs response: only a response can be close-delimited
    std::string header_;            // the current message's rewritten header (header views point in here)
    size_t body_remaining_ = 0;     // Content-Length bytes still to forward
    size_t chunk_remaining_ = 0;    // current chunk DATA(+CRLF) still to forward
};

} // namespace reflector
