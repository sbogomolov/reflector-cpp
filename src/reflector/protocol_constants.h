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

} // namespace reflector
