#pragma once

#include "ip_address.h"
#include "mac_address.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace reflector {

// L2 destination MAC for an IPv4/IPv6 multicast or limited-broadcast address: the IPv4 limited
// broadcast maps to ff:ff:ff:ff:ff:ff, an IPv4 multicast to 01:00:5e + the low 23 address bits
// (RFC 1112), and an IPv6 multicast to 33:33 + the low 32 address bits (RFC 2464).
[[nodiscard]] MacAddress MulticastMacFor(IpAddress address) noexcept;

// Builds an Ethernet frame carrying one UDP datagram (IPv4/IPv6 + UDP headers, with the IPv4
// header checksum and UDP checksum filled in) into `out`. Returns the frame length, or 0 if
// `out` is too small or the datagram would overflow the 16-bit length fields. `src_ip`/`dst_ip`
// must share an address family. Used on every interface on Linux and on Ethernet interfaces on
// macOS.
[[nodiscard]] size_t BuildUdpFrame(
    MacAddress dst_mac,
    MacAddress src_mac,
    IpAddress src_ip,
    IpAddress dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    std::span<const std::byte> payload,
    uint8_t ttl,
    std::span<std::byte> out) noexcept;

#if defined(__APPLE__)
// Like BuildUdpFrame but with BSD DLT_NULL framing (a 4-byte host-order address family in place
// of the Ethernet header, and no L2 MACs), as used on the macOS loopback interface (lo0). Linux
// frames loopback as Ethernet, so this exists only on macOS.
[[nodiscard]] size_t BuildLoopbackUdpFrame(
    IpAddress src_ip,
    IpAddress dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    std::span<const std::byte> payload,
    uint8_t ttl,
    std::span<std::byte> out) noexcept;
#endif

} // namespace reflector
