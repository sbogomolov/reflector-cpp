#pragma once

#include <cstddef>
#include <cstdint>

namespace reflector {

// L2/L3/L4 header sizes and format constants shared by the frame builder (egress) and the raw-socket
// parser (capture), so the wire layout is defined once rather than duplicated per file.
//
// The ethertypes are named IPV4_ETHERTYPE / IPV6_ETHERTYPE rather than ETHERTYPE_IPV4 / ETHERTYPE_IPV6:
// macOS <net/ethernet.h> defines the latter as macros, which would macro-expand a same-named identifier
// into garbage wherever that header is also included (e.g. the raw socket).
inline constexpr size_t ETHERNET_HEADER_SIZE = 14;  // dst MAC(6) + src MAC(6) + ethertype(2)
inline constexpr size_t ETHERTYPE_OFFSET = 12;      // the ethertype's offset within the Ethernet header
inline constexpr size_t IPV4_HEADER_SIZE = 20;      // no options (IHL 5); also the minimum valid header size
inline constexpr size_t IPV6_HEADER_SIZE = 40;      // fixed (no extension headers)
inline constexpr size_t UDP_HEADER_SIZE = 8;
inline constexpr uint16_t IPV4_ETHERTYPE = 0x0800;
inline constexpr uint16_t IPV6_ETHERTYPE = 0x86dd;
inline constexpr uint8_t IP_PROTO_UDP = 17;

// Ceiling for any frame the reflector handles, capture and egress alike: one datagram at a typical
// Ethernet MTU plus headers, with headroom. Reflected traffic fits well below it; larger datagrams
// would be IP-fragmented and the parser drops fragments anyway.
inline constexpr size_t MAX_FRAME_SIZE = 4 * 1024;

// The largest UDP payload that still fits MAX_FRAME_SIZE once framed, under the worst-case header
// stack (Ethernet over DLT_NULL's 4 bytes, IPv6 over IPv4, no extension headers since the builders
// emit none): anything built within it is sendable on either family.
inline constexpr size_t MAX_UDP_PAYLOAD_SIZE =
    MAX_FRAME_SIZE - (ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE + UDP_HEADER_SIZE);

} // namespace reflector
