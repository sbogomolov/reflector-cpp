#pragma once

#include "ip_address.h"
#include "ip_endpoint.h"
#include "mac_address.h"
#include "packet.h"
#include "platform.h"
#include "util/registration.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

class Interface;

// The full duplex surface of a per-interface socket: capture (receive), inject (send), and
// access to the Interface it runs on. RawSocket implements it over real L2 capture/inject;
// tests substitute one combined fake. The receive and send halves share a single interface
// rather than being split, because in this codebase one socket always does both directions.
class LinkSocket {
public:
    // RAII handle for one group membership (keyed by the group). Resetting/destroying it drops one
    // join of that group; the socket leaves the group only when its last membership goes.
    using MulticastMembership = reflector::Registration<LinkSocket, IpAddress>;

    virtual ~LinkSocket() noexcept = default;

    // --- receive side: the packet dispatcher watches this fd and drains it ---

    [[nodiscard]] virtual bool IsValid() const noexcept = 0;
    [[nodiscard]] virtual int Fd() const noexcept = 0;

    // The next parsed datagram, or nullopt when none is currently available (EAGAIN) or the
    // next frame is unparseable. The payload may span the socket's buffer and stays valid only
    // until the next Receive() on the same socket.
    [[nodiscard]] virtual std::optional<Packet> Receive() noexcept = 0;

#if !defined(__linux__)
    // macOS BPF batches several frames into one read(); this lets the dispatcher keep draining the
    // userland buffer past the per-event cap while frames remain. Not on Linux, where AF_PACKET
    // delivers one frame per recv with no userland buffering.
    [[nodiscard]] virtual bool HasBufferedData() const noexcept = 0;
#endif

    // --- send side: a reflector emits reflected datagrams through this ---

    // Sends a UDP datagram to an explicit unicast L2 destination `dst_mac` — the egress path does no
    // ARP/ND, so the caller supplies the peer's MAC (e.g. an SSDP searcher whose frame we captured).
    // Originates from this interface's own source address; `dst.addr` must be unicast. Returns false
    // (after logging) on failure; the result is unspecified when the interface has no source address
    // of the datagram's family, so gate with GetInterface().CanSend(family) first.
    [[nodiscard]] virtual bool SendUdpDatagram(MacAddress dst_mac, const IpEndpoint& dst,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Sends a UDP datagram to multicast destination `dst` (dst.addr must be IpAddress::IsMulticast()),
    // deriving the L2 destination from the group. Same source/failure contract as SendUdpDatagram.
    [[nodiscard]] virtual bool SendUdpMulticastDatagram(const IpEndpoint& dst,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Sends a UDP datagram to the IPv4 limited broadcast (255.255.255.255), using the all-ones L2
    // destination. Same source/failure contract as SendUdpDatagram.
    [[nodiscard]] virtual bool SendUdpBroadcastDatagram(uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // Joins multicast `group` so this socket's interface receives that group's traffic (programs
    // the kernel/NIC multicast filter — "gate 2"), returning an RAII membership; dropping it leaves
    // the group once no membership remains. Refcounted: joining a group already joined on this
    // socket just adds a membership without a second kernel join. `group` must be a multicast
    // address. An invalid membership (IsValid() == false, after logging) signals join failure.
    [[nodiscard]] virtual MulticastMembership JoinMulticastGroup(const IpAddress& group) noexcept = 0;

    // The Interface this socket captures on / injects through — its source addresses are what the
    // Send* calls originate from. The socket borrows it for its lifetime; the (Application-owned)
    // interface outlives the socket.
    [[nodiscard]] virtual const Interface& GetInterface() const noexcept = 0;

protected:
    // Mints a membership for `group` owned by this socket; the join must already have happened.
    [[nodiscard]] MulticastMembership MakeMembership(const IpAddress& group) noexcept {
        return MulticastMembership{this, group};
    }

private:
    friend MulticastMembership;

    // Drops one membership of `group` (MulticastMembership::Reset calls this): leaves the group in
    // the kernel only when the last membership goes. Returns false for a group with no membership.
    virtual bool Unregister(const IpAddress& group) noexcept = 0;
};

} // namespace reflector
