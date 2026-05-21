#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace reflector {

// Big-endian (network-order) 16-bit read/write over raw byte spans, shared by the frame
// parser, the frame builder, and the checksum pseudo-headers. Host-order conversions
// (htons) and the DLT_NULL host-order address family are deliberately not here — they are
// not network-order and belong with their call sites.

// Reads a 16-bit value from the first two bytes of `bytes` (which must hold at least two).
[[nodiscard]] constexpr uint16_t ReadU16Be(std::span<const std::byte> bytes) noexcept {
    return static_cast<uint16_t>(
        (std::to_integer<uint16_t>(bytes[0]) << 8) | std::to_integer<uint16_t>(bytes[1]));
}

// Writes `value` into the first two bytes of `out` (which must hold at least two).
constexpr void WriteU16Be(uint16_t value, std::span<std::byte> out) noexcept {
    out[0] = static_cast<std::byte>(value >> 8);
    out[1] = static_cast<std::byte>(value & 0xff);
}

} // namespace reflector
