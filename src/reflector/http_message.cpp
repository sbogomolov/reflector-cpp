#include "reflector/http_message.h"

#include "reflector/logger.h"
#include "reflector/util/ascii.h"

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cstdint>
#include <format>
#include <utility>

namespace {

using namespace reflector;

constexpr std::string_view CRLF = "\r\n";
constexpr std::string_view HEADER_TERMINATOR = "\r\n\r\n";

Logger& GetLogger() noexcept {
    static Logger logger{"HttpFraming"};
    return logger;
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
    size_t auth_end = value.find_first_of("/ \t\r", auth_start);
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

HttpFraming::HttpFraming(EndpointRewrite rewrite)
    : rewrite_{std::move(rewrite)} {
    header_.reserve(MAX_HEADER_BYTES);
}

// Rewrites the target authority headers in header_ in place and sets the body phase from its framing.
// header_ holds exactly the header block, so the scan runs over [0, header_.size()) and the in-place
// std::string::replace splices keep that bound current. Returns false on an unparseable Content-Length.
bool HttpFraming::ScanAndRewriteHeader() {
    size_t content_length = 0;
    bool has_content_length = false;
    bool chunked = false;
    size_t pos = 0;
    while (pos < header_.size()) {
        const std::string_view header_view{header_};
        size_t eol = header_view.find(CRLF, pos);
        assert(eol != std::string_view::npos);  // header_ ends with \r\n\r\n, so every line's CRLF is present
        const std::string_view line = header_view.substr(pos, eol - pos);

        if (StartsWithNoCase(line, "Content-Length:")) {
            const std::string_view v = TrimLeadingSpace(line.substr(line.find(':') + 1));
            if (std::from_chars(v.data(), v.data() + v.size(), content_length).ec != std::errc{}) {
                GetLogger().Error("malformed Content-Length value \"{}\"", v);
                return false;
            }
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

    if (chunked) {
        phase_ = Phase::BodyChunked;
        chunk_remaining_ = 0;
    } else if (has_content_length && content_length > 0) {
        phase_ = Phase::BodyContentLength;
        body_remaining_ = content_length;
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
        case Phase::Header:
            stop = true;  // the next message starts here — one message per Feed
            break;
        case Phase::BodyContentLength: {
            const size_t take = std::min(body_remaining_, input.size() - pos);
            pos += take;
            body_remaining_ -= take;
            if (body_remaining_ == 0) {
                phase_ = Phase::Header;
            }
            stop = true;  // a Content-Length body is one contiguous run — nothing more to forward now
            break;
        }
        case Phase::BodyChunked: {
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
                phase_ = Phase::BodyChunkedDone;
                chunk_remaining_ = CRLF.size();  // the blank line closing the chunked body
            } else {
                chunk_remaining_ = chunk_size + CRLF.size();  // chunk DATA + its terminating CRLF
            }
            break;
        }
        case Phase::BodyChunkedDone: {
            // A chunked body closes with a bare CRLF. A trailer field (RFC 7230) would appear here instead;
            // this framer relays bodies opaquely and has no trailer scanner, so a non-CRLF close is refused
            // rather than silently mis-framed as the next message. The CRLF may itself be split across feeds.
            while (chunk_remaining_ > 0 && pos < input.size()) {
                if (input[pos] != CRLF[CRLF.size() - chunk_remaining_]) {
                    GetLogger().Error("chunked body not closed by CRLF (chunked trailers are unsupported)");
                    return std::nullopt;
                }
                ++pos;
                --chunk_remaining_;
            }
            if (chunk_remaining_ == 0) {
                phase_ = Phase::Header;
            }
            stop = true;
            break;
        }
        }
    }

    return Output{header_view, input.substr(body_start, pos - body_start), pos};
}

} // namespace reflector
