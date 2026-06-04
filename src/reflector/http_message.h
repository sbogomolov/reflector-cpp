#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "reflector/ip_endpoint.h"
#include "reflector/util/delegate.h"

namespace reflector {

// Replaces the authority `from` (its formatted "addr:port", compared literally) with `to` wherever it
// appears in `text` — an SSDP LOCATION line or any header value. Returns the rewritten copy; `text`
// without `from`'s authority is returned unchanged. (Used by the SSDP LOCATION path; HttpFraming splices
// inline rather than calling this.)
[[nodiscard]] std::string RewriteAuthority(std::string_view text, const IpEndpoint& from, const IpEndpoint& to);

// Per-direction incremental HTTP/1.1 framing + authority-header rewrite. The owner reads into its own
// buffer and feeds a contiguous view; HttpFraming copies only the header (to rewrite Host / Application-URL
// / Location authorities), leaves the body in place, and reports back what to forward and how much of the
// input it consumed. The owner forwards `header` then `body` (e.g. one writev) and drops `consumed` bytes
// from its buffer. The header is copied because rewriting changes it; the body is a zero-copy slice of the
// fed input. Each Feed yields at most one message's worth — a complete header plus as much of its body as
// arrived — so the owner loops Feed over its buffer until consumed == 0 (need more bytes), then reads more.
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

    explicit HttpFraming(EndpointRewrite rewrite);

    // Feed a contiguous view of the owner's buffered bytes. nullopt = a malformed or over-cap message (the
    // owner closes); otherwise the forwardable Output.
    [[nodiscard]] std::optional<Output> Feed(std::string_view input);

private:
    // Accumulating the start line + header block, or streaming a body of a known shape.
    enum class Phase : uint8_t { Header, BodyContentLength, BodyChunked, BodyChunkedDone };

    // Rewrites the authority headers in header_ in place and sets the body phase from its framing; returns
    // false on a malformed header. header_ holds exactly the header block, so it scans [0, header_.size()).
    bool ScanAndRewriteHeader();

    EndpointRewrite rewrite_;

    Phase phase_ = Phase::Header;
    std::string header_;            // the current message's rewritten header (header views point in here)
    size_t body_remaining_ = 0;     // Content-Length bytes still to forward
    size_t chunk_remaining_ = 0;    // current chunk DATA(+CRLF), or the closing CRLF, still to forward
};

} // namespace reflector
