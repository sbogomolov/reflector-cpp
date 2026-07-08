#include "reflector/http_message.h"

#include "reflector/logger.h"
#include "reflector/util/ascii.h"

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cstdint>
#include <format>
#include <limits>
#include <utility>

namespace {

using namespace reflector;

constexpr std::string_view CRLF = "\r\n";
constexpr std::string_view HEADER_TERMINATOR = "\r\n\r\n";

Logger& GetLogger() noexcept {
    static Logger logger{"HttpFraming"};
    return logger;
}

// The numeric status code of a response start line ("HTTP/x.y SP code SP reason"), or 0 if it can't be read.
// Only used to spot the bodyless statuses, so a 0 just means "treat as an ordinary-bodied response".
int ParseStatusCode(std::string_view start_line) {
    const size_t sp = start_line.find(' ');
    if (sp == std::string_view::npos) {
        return 0;
    }
    const std::string_view code_field = TrimLeadingSpace(start_line.substr(sp + 1));
    int code = 0;
    const auto* const end = code_field.data() + code_field.size();
    return std::from_chars(code_field.data(), end, code).ec == std::errc{} ? code : 0;
}

// A 1xx, 204, or 304 response has no body whatever the framing headers say (RFC 7230 §3.3.3 rule 1), so it
// must not be taken for a close-delimited body.
bool StatusForbidsBody(int code) {
    return (code >= 100 && code < 200) || code == 204 || code == 304;
}

} // namespace

namespace reflector {

std::optional<Authority> ParseAuthority(std::string_view value, bool bare) {
    size_t auth_start = 0;
    if (!bare) {
        constexpr std::string_view SCHEME = "http://";
        if (!StartsWithNoCase(value, SCHEME)) {
            return std::nullopt;
        }
        auth_start = SCHEME.size();
    }
    size_t auth_end = value.find_first_of("/?# \t\r", auth_start);  // path, query, or fragment ends it (RFC 3986)
    if (auth_end == std::string_view::npos) {
        auth_end = value.size();
    }
    const size_t auth_len = auth_end - auth_start;
    const std::string_view authority = value.substr(auth_start, auth_len);
    const size_t colon = authority.rfind(':');
    const std::string_view host = colon == std::string_view::npos ? authority : authority.substr(0, colon);
    const auto addr = IpAddress::FromString(std::string{host});
    if (!addr) {
        return std::nullopt;
    }
    uint16_t port = 80;  // the http scheme default (RFC 3986) when the authority omits the port
    if (colon != std::string_view::npos) {
        const std::string_view port_text = authority.substr(colon + 1);
        const auto* const port_end = port_text.data() + port_text.size();
        const auto result = std::from_chars(port_text.data(), port_end, port);
        // Require the whole port_text to be consumed so trailing junk (e.g. "80x") is rejected, not truncated.
        if (result.ec != std::errc{} || result.ptr != port_end || port == 0) {
            return std::nullopt;  // a ':' was present but the port is empty, non-numeric, has trailing junk, or 0
        }
    }
    return Authority{IpEndpoint{*addr, port}, auth_start, auth_len};
}

HttpFraming::HttpFraming(EndpointRewrite rewrite, MessageType type)
    : rewrite_{std::move(rewrite)}, type_{type} {
    header_.reserve(MAX_HEADER_BYTES);
}

// Rewrites the target authority headers in header_ in place and sets the body phase from its framing.
// header_ holds exactly the header block, so the scan runs over [0, header_.size()) and the in-place
// std::string::replace splices keep that bound current. Returns false on an unparseable Content-Length.
bool HttpFraming::ScanAndRewriteHeader() {
    size_t content_length = 0;
    bool has_content_length = false;
    bool chunked = false;
    // A response's status line can make it bodyless whatever the framing headers say (rule 1); read the code
    // so a 1xx/204/304 is forced bodyless below, ahead of the Content-Length / chunked / close-delimited
    // branches. Requests carry no status code, so this stays false for them.
    const bool bodyless_status = type_ == MessageType::Response
        && StatusForbidsBody(ParseStatusCode(std::string_view{header_}.substr(0, header_.find(CRLF))));
    size_t pos = 0;
    while (pos < header_.size()) {
        const std::string_view header_view{header_};
        size_t eol = header_view.find(CRLF, pos);
        assert(eol != std::string_view::npos);  // header_ ends with \r\n\r\n, so every line's CRLF is present
        const std::string_view line = header_view.substr(pos, eol - pos);

        if (StartsWithNoCase(line, "Content-Length:")) {
            const std::string_view v = TrimLeadingSpace(line.substr(line.find(':') + 1));
            size_t parsed = 0;
            const auto result = std::from_chars(v.data(), v.data() + v.size(), parsed);
            // Require the whole value to be the number, like ParseAuthority's port parse: from_chars stops
            // at the first non-digit and reports success, so "12abc" would otherwise frame a body of 12 and
            // mis-parse the rest. Trailing OWS (RFC 7230 §3.2.4) is tolerated; any other trailing byte rejects.
            if (result.ec != std::errc{} || !TrimLeadingSpace({result.ptr, v.data() + v.size()}).empty()) {
                GetLogger().Error("malformed Content-Length value \"{}\"", v);
                return false;
            }
            // A second, differing Content-Length is a request-smuggling vector (RFC 9112 §6.3): refuse
            // the message rather than pick a winner. Identical repeats agree on the framing, so they pass.
            if (has_content_length && parsed != content_length) {
                GetLogger().Error("conflicting Content-Length values {} and {}", content_length, parsed);
                return false;
            }
            content_length = parsed;
            has_content_length = true;
        } else if (StartsWithNoCase(line, "Transfer-Encoding:")) {
            const std::string_view v = line.substr(line.find(':') + 1);
            // chunked is case-insensitive (RFC 7230) and may end a coding list, e.g. "gzip, chunked".
            // search passes (haystack, needle) chars in that order; the needle is lowercase, so fold only `a`.
            chunked = !std::ranges::search(v, std::string_view{"chunked"},
                [](char a, char b) { return AsciiToLower(a) == b; }).empty();
        }

        const bool is_host = StartsWithNoCase(line, "Host:");
        const bool is_url = StartsWithNoCase(line, "Application-URL:")
                         || StartsWithNoCase(line, "Location:");
        if (is_host || is_url) {
            const size_t colon = line.find(':');
            const std::string_view value = TrimLeadingSpace(line.substr(colon + 1));
            if (const auto found = ParseAuthority(value, /*bare=*/is_host)) {
                if (const auto repl = rewrite_(found->endpoint)) {
                    // Log before the splice: `line` views into header_, which the replace may reallocate.
                    GetLogger().Debug("rewrote {} authority {} -> {}", line.substr(0, colon),
                        found->endpoint, *repl);
                    const std::string repl_text = std::format("{}", *repl);
                    const size_t auth_off =
                        static_cast<size_t>(value.data() - header_view.data()) + found->offset;
                    header_.replace(auth_off, found->length, repl_text);  // shifts the rest of header_
                    eol = eol - found->length + repl_text.size();         // this line's CRLF moved with it
                }
            }
        }
        pos = eol + CRLF.size();
    }

    if (bodyless_status) {
        // 1xx/204/304: no body whatever the framing headers say (RFC 7230 §3.3.3 rule 1). This precedes — and
        // overrides — the Content-Length / chunked / close-delimited branches, so a stray Content-Length on
        // such a response can't frame a phantom body that swallows the next response.
        phase_ = Phase::Header;
    } else if (chunked) {
        phase_ = Phase::BodyChunked;
        chunk_remaining_ = 0;
    } else if (has_content_length && content_length > 0) {
        phase_ = Phase::BodyContentLength;
        body_remaining_ = content_length;
    } else if (type_ == MessageType::Response && !has_content_length) {
        // A response with neither Content-Length nor chunked encoding runs until the connection closes
        // (RFC 7230 §3.3.3 rule 7): stream the body opaquely until the owner sees EOF. A same-shape request
        // is bodyless instead (rule 6) — the branch below.
        phase_ = Phase::BodyUntilClose;
    } else {
        phase_ = Phase::Header;  // bodyless: the message ends at the header
    }
    return true;
}

std::optional<HttpFraming::Output> HttpFraming::Feed(std::string_view input) {
    std::string_view header_view;  // stays empty unless this call completes a header
    size_t pos = 0;

    if (phase_ == Phase::Header) {
        const size_t term = input.find(HEADER_TERMINATOR);
        if (term == std::string_view::npos) {
            if (input.size() > MAX_HEADER_BYTES) {
                GetLogger().Error("header block exceeds the {}-byte cap with no terminator", MAX_HEADER_BYTES);
                return std::nullopt;
            }
            return Output{};  // incomplete header: nothing forwardable yet, read more and feed again
        }
        const size_t header_len = term + HEADER_TERMINATOR.size();
        // The cap must not depend on TCP segmentation: a coalesced read could otherwise slip a
        // header past it that a segmented one could not (the unterminated check above never fires
        // when the terminator is already in the buffer).
        if (header_len > MAX_HEADER_BYTES) {
            GetLogger().Error("header block exceeds the {}-byte cap", MAX_HEADER_BYTES);
            return std::nullopt;
        }
        header_.assign(input.data(), header_len);  // copy only the header, to rewrite it
        if (!ScanAndRewriteHeader()) {             // rewrites header_ in place and sets the body phase
            return std::nullopt;
        }
        header_view = std::string_view{header_};
        pos = header_len;
    }

    // Forward as much of the body as arrived, as a zero-copy slice of `input`, stopping at the message
    // boundary, the end of the input, or an incomplete chunk-size line (left in the owner's buffer).
    const size_t body_start = pos;
    bool stop = false;
    while (pos < input.size() && !stop) {
        switch (phase_) {
        using enum Phase;
        case Header:
            stop = true;  // the next message starts here — one message per Feed
            break;
        case BodyContentLength: {
            const size_t take = std::min(body_remaining_, input.size() - pos);
            pos += take;
            body_remaining_ -= take;
            if (body_remaining_ == 0) {
                phase_ = Header;
            }
            stop = true;  // a Content-Length body is one contiguous run — nothing more to forward now
            break;
        }
        case BodyChunked: {
            if (chunk_remaining_ > 0) {  // forwarding the current chunk's DATA(+CRLF), opaque
                const size_t take = std::min(chunk_remaining_, input.size() - pos);
                pos += take;
                chunk_remaining_ -= take;
                if (chunk_remaining_ > 0) {
                    stop = true;  // ran out mid-chunk
                }
                break;
            }
            const size_t eol = input.find(CRLF, pos);
            if (eol == std::string_view::npos) {
                if (input.size() - pos > MAX_CHUNK_LINE_BYTES) {
                    GetLogger().Error("chunk-size line exceeds the {}-byte cap with no terminator",
                                      MAX_CHUNK_LINE_BYTES);
                    return std::nullopt;
                }
                stop = true;  // incomplete chunk-size line: leave it for the next feed
                break;
            }
            std::string_view size_field = input.substr(pos, eol - pos);
            if (const size_t semi = size_field.find(';'); semi != std::string_view::npos) {
                size_field = size_field.substr(0, semi);  // drop chunk extensions
            }
            size_t chunk_size = 0;
            if (std::from_chars(size_field.data(), size_field.data() + size_field.size(),
                                chunk_size, 16).ec != std::errc{}) {
                GetLogger().Error("malformed chunk size \"{}\"", size_field);
                return std::nullopt;
            }
            pos = eol + CRLF.size();
            if (chunk_size == 0) {
                phase_ = BodyChunkedDone;  // an optional trailer section + the closing CRLF remain
            } else if (chunk_size > std::numeric_limits<size_t>::max() - CRLF.size()) {
                // A near-SIZE_MAX size (hostile/buggy device) would wrap the addition below and misframe.
                GetLogger().Error("chunk size {:#x} too large to frame", chunk_size);
                return std::nullopt;
            } else {
                chunk_remaining_ = chunk_size + CRLF.size();  // chunk DATA + its terminating CRLF
            }
            break;
        }
        case BodyChunkedDone: {
            // After the last chunk (RFC 7230 §4.1) comes an optional trailer section then the closing CRLF:
            // *(trailer-field CRLF) CRLF. Relayed opaquely (no trailer parsing) -- forward each complete line
            // and end the body at the empty line. A line without its CRLF (including a split closing CRLF) is
            // left for the next feed, capped so a peer dribbling an endless line can't grow the buffer.
            const size_t eol = input.find(CRLF, pos);
            if (eol == std::string_view::npos) {
                if (input.size() - pos > MAX_TRAILER_LINE_BYTES) {
                    GetLogger().Error("chunked trailer line exceeds the {}-byte cap with no terminator",
                                      MAX_TRAILER_LINE_BYTES);
                    return std::nullopt;
                }
                stop = true;  // incomplete line: leave it for the next feed
                break;
            }
            const bool empty_line = eol == pos;
            pos = eol + CRLF.size();  // forward this line (a trailer field, or the closing empty line) opaquely
            if (empty_line) {
                phase_ = Header;  // the empty line ends the trailer section and the chunked body
                stop = true;
            }
            break;  // a trailer field: keep scanning the next line in this same feed
        }
        case BodyUntilClose:
            // Close-delimited (RFC 7230 §3.3.3 rule 7): no length, no chunk frame. Forward all input as body,
            // opaquely; the message has no in-band end, so the owner ends it when the connection closes. The
            // phase never returns to Header — there is no next message on a close-delimited connection.
            pos = input.size();
            stop = true;
            break;
        }
    }

    return Output{header_view, input.substr(body_start, pos - body_start), pos};
}

} // namespace reflector
