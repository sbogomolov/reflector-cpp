#pragma once

#include "ip_address.h"
#include "mac_address.h"
#include "packet.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// The full duplex surface of a per-interface socket: capture (receive), inject (send), and the
// interface bookkeeping a long-running daemon needs to route address-change refreshes. RawSocket
// implements it over real L2 capture/inject; tests substitute one combined fake. The receive and
// send halves share a single interface rather than being split, because in this codebase one
// socket always does both directions.
class LinkSocket {
public:
    virtual ~LinkSocket() noexcept = default;

    // --- receive side: the packet dispatcher watches this fd and drains it ---

    [[nodiscard]] virtual bool IsValid() const noexcept = 0;
    [[nodiscard]] virtual int Fd() const noexcept = 0;

    // The next parsed datagram, or nullopt when none is currently available (EAGAIN) or the
    // next frame is unparseable. The payload may span the socket's buffer and stays valid only
    // until the next Receive() on the same socket.
    [[nodiscard]] virtual std::optional<Packet> Receive() noexcept = 0;

#if defined(__APPLE__)
    // macOS BPF batches several frames into one read(); these let the dispatcher drain the
    // userland buffer past the per-event cap and discard it when it abandons a drain. Not on
    // Linux, where AF_PACKET delivers one frame per recv with no userland buffering.
    [[nodiscard]] virtual bool HasBufferedData() const noexcept = 0;
    virtual void ClearBuffer() noexcept = 0;
#endif

    // --- send side: a reflector emits reflected datagrams through this ---

    // True if this socket can originate a datagram of `family` (e.g. the bound interface has a
    // source address of that family). Gate the Send* calls on it.
    [[nodiscard]] virtual bool CanSend(IpAddress::Family family) const noexcept = 0;

    // Sends a UDP datagram to an explicit unicast L2 destination `dst_mac` — the egress path does no
    // ARP/ND, so the caller supplies the peer's MAC (e.g. an SSDP searcher whose frame we captured).
    // Originates from this interface's own source address; `dst_ip` must be unicast. Returns false
    // (after logging) on failure; the result is unspecified when !CanSend(dst_ip.AddressFamily()),
    // so gate with CanSend first.
    [[nodiscard]] virtual bool SendUdpDatagram(MacAddress dst_mac, const IpAddress& dst_ip, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Sends a UDP datagram to multicast `group` (must be IpAddress::IsMulticast()), deriving the L2
    // destination from the group. Same source/failure contract as SendUdpDatagram.
    [[nodiscard]] virtual bool SendUdpMulticastDatagram(const IpAddress& group, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Sends a UDP datagram to the IPv4 limited broadcast (255.255.255.255), using the all-ones L2
    // destination. Same source/failure contract as SendUdpDatagram.
    [[nodiscard]] virtual bool SendUdpBroadcastDatagram(uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Joins multicast `group` so this socket's interface receives that group's traffic (programs
    // the kernel/NIC multicast filter — "gate 2"). Idempotent: re-joining a group already joined
    // on this socket succeeds without effect. `group` must be a multicast address. Returns false
    // (after logging) on failure.
    [[nodiscard]] virtual bool JoinMulticastGroup(const IpAddress& group) noexcept = 0;

    // --- interface bookkeeping: the daemon refreshes cached addresses on change ---

    // The interface's source address for `family` — the address the Send* calls originate from, and
    // the destination a unicast reply to a relayed datagram of that family is sent to. nullopt if the
    // interface has none (then CanSend(family) is also false). IPv6 returns the link-local address.
    [[nodiscard]] virtual std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept = 0;

    // The interface's kernel index (0 if unknown). The address monitor reports changes by index,
    // so the owner can map a changed index back to the socket whose addresses need refreshing.
    [[nodiscard]] virtual unsigned InterfaceIndex() const noexcept = 0;

    // Re-resolves the interface's source addresses, so a long-running daemon's cached source
    // addresses don't go stale (e.g. an IPv6 address finishing DAD, or DHCP renewal).
    virtual void RefreshAddresses() noexcept = 0;
};

} // namespace reflector
