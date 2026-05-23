#pragma once

#include "ip_address.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace reflector {

// The send surface a reflector emits reflected datagrams through. RawSocket implements it over
// a raw L2 inject; tests substitute a recording fake so reflector logic is exercised without a
// real socket. Kept to just the two calls a reflector needs — capability probing and sending —
// so the seam stays narrow.
class UdpSender {
public:
    virtual ~UdpSender() noexcept = default;

    // True if this sender can originate a datagram of `family` (e.g. the bound interface has a
    // source address of that family). Gate SendUdpDatagram calls on it.
    [[nodiscard]] virtual bool CanSend(IpAddress::Family family) const noexcept = 0;

    // Sends a UDP datagram to `dst_ip`:`dst_port` from `src_port`, with the given TTL / hop
    // limit. Returns false (after logging) on failure. The result is unspecified when
    // !CanSend(dst_ip.AddressFamily()); gate with CanSend first.
    [[nodiscard]] virtual bool SendUdpDatagram(IpAddress dst_ip, uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;
};

} // namespace reflector
