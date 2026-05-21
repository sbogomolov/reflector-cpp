#pragma once

#include "ip_address.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace reflector {

// RFC 1071 Internet checksum helpers for the frames we build on the egress (raw inject)
// path. The capture/RX path deliberately does NOT verify checksums (see raw_socket.h); these
// exist only for TX, where dropping the kernel UDP stack means we must compute them ourselves.

// Checksum over an IPv4 header. `header` is the full IHL-sized header with its checksum field
// (bytes 10-11) already zeroed. The result is stored network-byte-order into that field.
[[nodiscard]] uint16_t Ipv4HeaderChecksum(std::span<const std::byte> header) noexcept;

// UDP checksum including the IPv4/IPv6 pseudo-header. `udp` is the contiguous UDP header plus
// payload with the checksum field (bytes 6-7) zeroed; `src`/`dst` must share an address
// family. A computed 0x0000 is mapped to 0xffff (RFC 768) — required for IPv6, where a zero
// UDP checksum is illegal and receivers must drop it.
[[nodiscard]] uint16_t UdpChecksum(IpAddress src, IpAddress dst, std::span<const std::byte> udp) noexcept;

} // namespace reflector
