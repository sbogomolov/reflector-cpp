#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// An SSDP discovery message is either a multicast search (M-SEARCH) or an advertisement (NOTIFY).
// These are the two kinds a multicast reflector relays — search source->target, advertisement
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

} // namespace reflector
