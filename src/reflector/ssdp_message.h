#pragma once

#include "http_message.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// An SSDP discovery message is either a multicast search (M-SEARCH) or an advertisement (NOTIFY).
// These are the two kinds a multicast reflector reflects — search source->target, advertisement
// target->source. The unicast search response (HTTP/1.1 200 OK) is neither and isn't classified here.
enum class SsdpMessageKind : uint8_t {
    Search,
    Advertisement,
};

// Classifies an SSDP datagram by its HTTPU start line. Per UPnP Device Architecture 2.0 the start
// line is exactly one of "M-SEARCH * HTTP/1.1", "NOTIFY * HTTP/1.1", or "HTTP/1.1 200 OK"; this
// matches only the leading method token, case-sensitive. Returns nullopt for a response status line,
// a payload too short to hold the token, or anything else.
[[nodiscard]] std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept;

// The fallback M-SEARCH response window (seconds) a caller applies when ParseMSearchMx reports no
// usable MX. Per UDA 2.0 a multicast M-SEARCH MUST carry MX, so an absent/unparseable one is a
// non-conformant searcher — the caller reflects it anyway with this fallback window and logs it.
inline constexpr uint8_t MSEARCH_MX_DEFAULT = 3;

// Parses the MX header of an M-SEARCH (the searcher's max response wait, in seconds), returning the
// value clamped to [1, 5] per UPnP Device Architecture 2.0. Returns nullopt when MX is absent or
// unparseable, leaving the fallback (MSEARCH_MX_DEFAULT) and the logging to the caller, which has the
// searcher's address for context. Walks the whole payload's CRLF-delimited lines for the first MX field
// (an M-SEARCH carries no body, so there is no header/body boundary to stop at); field name is
// case-insensitive.
[[nodiscard]] std::optional<uint8_t> ParseMSearchMx(std::span<const std::byte> payload) noexcept;

// True if `payload` advertises the DIAL service — its service-type URN (urn:dial-multiscreen-org:service:dial)
// appears anywhere in the message (ST/NT/USN). The SSDP path uses this to decide whether a response's LOCATION
// should be rewritten through the DialProxy; DialProxy itself never parses SSDP.
[[nodiscard]] bool IsDialServiceMessage(std::span<const std::byte> payload) noexcept;

// The DIAL device-description authority from the message's LOCATION header's http URL: the device endpoint
// to mint a reflector listener for, plus the byte span of its "host[:port]" text (here measured within
// `payload`, so the SSDP path can splice the reflector authority over exactly that span). nullopt when there
// is no LOCATION or it is unparseable. DIAL is IPv4-only; the URL's port may be omitted (defaults to 80) and
// the host must be an IPv4 literal.
[[nodiscard]] std::optional<Authority> ParseDialLocationAuthority(std::span<const std::byte> payload) noexcept;

} // namespace reflector
