#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// An mDNS message is either a query or a response, per the QR bit of its DNS header. Unsolicited
// announcements are responses too (RFC 6762 §8.3), so this two-way split is exactly the reflector's
// directional gate: queries are relayed source->target, responses target->source.
enum class MdnsMessageKind : uint8_t {
    Query,
    Response,
};

// Classifies an mDNS/DNS message by the QR bit of its fixed 12-byte header (RFC 1035 §4.1.1).
// Returns nullopt when the payload is too short to contain that header. Looks only at the header
// — no question/record parsing.
[[nodiscard]] std::optional<MdnsMessageKind> ClassifyMdnsMessage(std::span<const std::byte> payload) noexcept;

} // namespace reflector
