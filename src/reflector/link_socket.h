#pragma once

#include "ip_address.h"
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
    // source address of that family). Gate SendUdpDatagram calls on it.
    [[nodiscard]] virtual bool CanSend(IpAddress::Family family) const noexcept = 0;

    // Sends a UDP datagram to `dst_ip`:`dst_port` from `src_port`, with the given TTL / hop
    // limit. Returns false (after logging) on failure. The result is unspecified when
    // !CanSend(dst_ip.AddressFamily()); gate with CanSend first.
    [[nodiscard]] virtual bool SendUdpDatagram(IpAddress dst_ip, uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;

    // --- interface bookkeeping: the daemon refreshes cached addresses on change ---

    // The interface's kernel index (0 if unknown). The address monitor reports changes by index,
    // so the owner can map a changed index back to the socket whose addresses need refreshing.
    [[nodiscard]] virtual unsigned InterfaceIndex() const noexcept = 0;

    // Re-resolves the interface's source addresses, so a long-running daemon's cached source
    // addresses don't go stale (e.g. an IPv6 address finishing DAD, or DHCP renewal).
    virtual void RefreshAddresses() noexcept = 0;
};

} // namespace reflector
