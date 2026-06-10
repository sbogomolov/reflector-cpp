#pragma once

#include "interface.h"
#include "link_socket.h"
#include "logger.h"
#include "packet.h"
#include "util/no_move.h"
#include "util/unique_fd.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

// Per-interface L2 packet capture. Opens AF_PACKET (Linux) or /dev/bpf* (macOS), installs
// a static kernel BPF program that accepts only IPv4/IPv6 UDP, and parses Ethernet+IP+UDP
// frames into Packet. Fragmented IP datagrams and frames with VLAN tags or IPv6 extension
// headers are dropped — out of scope for the WoL/mDNS/SSDP traffic this serves.
//
// Unlike the kernel UDP stack, this path does NOT validate the UDP checksum: capture
// happens below the layer that would verify it, and captured frames legitimately carry a
// zero/unset checksum (loopback, TX/RX checksum offload). Checksum-invalid datagrams are
// therefore reflected as-is; downstream consumers (e.g. WoL magic-packet matching) are the
// integrity gate, and the re-emitted packet gets a fresh kernel-computed checksum anyway.
//
// Requires CAP_NET_RAW on Linux or BPF device permissions on macOS.
//
// Immovable so registered instances stay put: DefaultPacketDispatcher caches the socket address in
// its capture-source map and registration entries and dereferences it on every drain; a move
// would silently invalidate those pointers. Hold instances in storage that preserves
// element addresses (stack, std::optional, node-based map) — std::vector won't do.
class RawSocket : public LinkSocket, NoMove {
public:
    // Borrows `interface` (Application-owned, outlives the socket) for its identity and the
    // source addresses the inject path stamps into frames. An invalid interface yields an
    // invalid socket.
    explicit RawSocket(const Interface& interface);
    ~RawSocket() noexcept override;

    // Test-only: wrap an arbitrary fd without performing any OS-level capture setup.
    // Receive() consumes bytes from that fd the same way the production socket would,
    // so tests can either synthesize Packets via DefaultPacketDispatcher::DispatchPacket directly
    // (when nothing is written to the fd) or drive real frames end-to-end via
    // TestCaptureSocket::WriteFrame.
    [[nodiscard]] static RawSocket ForTesting(const Interface& interface, int owned_fd);

    // unique_ptr counterpart to ForTesting, for owners that hold the (immovable) socket
    // behind a pointer — e.g. Application's injectable capture-socket factory.
    [[nodiscard]] static std::unique_ptr<RawSocket> ForTestingPtr(const Interface& interface, int owned_fd);

    [[nodiscard]] bool IsValid() const noexcept override { return fd_.IsValid(); }
    [[nodiscard]] int Fd() const noexcept override { return fd_.Get(); }

    [[nodiscard]] const Interface& GetInterface() const noexcept override { return interface_; }

    // Injects a UDP datagram out this interface as a raw L2 frame, building the Ethernet/IP/UDP
    // headers and checksums from the interface's cached source MAC/IP and writing the frame to the
    // kernel. These three differ only in the L2 destination: SendUdpDatagram takes an explicit
    // unicast `dst_mac` (no ARP/ND), SendUdpMulticastDatagram derives it from a multicast group, and
    // SendUdpBroadcastDatagram uses the all-ones broadcast MAC (always IPv4). `ttl` sets the IPv4 TTL
    // / IPv6 hop limit. Each fails (after logging) if the interface has no source address for the
    // datagram's family; gate first with CanSend (CanSend(Family::V4) for the broadcast).
    [[nodiscard]] bool SendUdpDatagram(MacAddress dst_mac, const IpEndpoint& dst,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept override;
    [[nodiscard]] bool SendUdpMulticastDatagram(const IpEndpoint& dst, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override;
    [[nodiscard]] bool SendUdpBroadcastDatagram(uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override;

    // Joins `group` on a dedicated, unbound join-only fd (AF_INET / AF_INET6 per family) so the
    // kernel delivers that group to this interface's capture path. The fd is held for the socket's
    // lifetime to keep the membership alive; one is opened lazily per family. Idempotent — a
    // re-join of an already-joined group is swallowed (EADDRINUSE) and reported as success.
    [[nodiscard]] bool JoinMulticastGroup(const IpAddress& group) noexcept override;

    // Returns the next parsed UDP datagram. The returned Packet's payload spans into the
    // socket's internal buffer and is valid until the next Receive() call on this socket.
    // Returns nullopt when no datagram is currently available (EAGAIN), or when the next
    // frame is unparseable / fragmented — caller treats both the same way and tries again
    // on the next read event.
    [[nodiscard]] std::optional<Packet> Receive() noexcept override;

#if defined(__APPLE__)
    // True if there are unparsed bytes in the socket's userland buffer. macOS BPF batches
    // multiple frames per read() into our buffer; if the drain stops before the batch is
    // consumed, kqueue won't fire again (the kernel side is empty) and the remaining frames
    // would stall. DefaultPacketDispatcher uses this to keep draining past the packet-per-event cap
    // while the buffer still has data. Not defined on Linux because AF_PACKET delivers one
    // frame per recv with no userland buffering.
    [[nodiscard]] bool HasBufferedData() const noexcept override;

    // Discards any unparsed bytes in the userland buffer. DefaultPacketDispatcher calls this when it
    // abandons a drain mid-batch (last registration for this fd was unregistered by a
    // callback); the leftover frames would otherwise sit until either the socket is
    // destroyed or new kernel data arrives to trigger a fresh drain.
    void ClearBuffer() noexcept override;
#endif

private:
    friend class RawSocketTest;

    enum class TestingTag {};
    RawSocket(TestingTag, const Interface& interface, int owned_fd) noexcept;

    void Close() noexcept;

    [[nodiscard]] std::optional<Packet> ParseFrame(std::span<const std::byte> frame) noexcept;

    // Shared body of the three public sends: builds the frame to `dst_mac` from this interface's
    // cached source MAC/IP and writes it. The callers compute `dst_mac` (explicit unicast, derived
    // multicast, or broadcast) and enforce their address-type precondition first.
    [[nodiscard]] bool SendFrame(MacAddress dst_mac, const IpEndpoint& dst, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept;

    Logger logger_;
    const Interface& interface_;
    UniqueFd fd_;
    // Dedicated unbound fds that hold multicast group memberships alive, one per family, opened
    // lazily by JoinMulticastGroup. Separate from fd_ (the capture/inject socket).
    UniqueFd join_fd_v4_;
    UniqueFd join_fd_v6_;

    // Linux: holds one frame per recv() into receive_buffer_.
    // macOS: holds a batch of bpf_hdr-prefixed frames per read(); receive_buffer_filled_
    //   tracks how many bytes are valid and receive_buffer_offset_ tracks how far we've
    //   walked through the batch.
    std::vector<std::byte> receive_buffer_;

#if defined(__APPLE__)
    size_t receive_buffer_filled_ = 0;
    size_t receive_buffer_offset_ = 0;

    // BPF on macOS can return either Ethernet framing (most interfaces) or DLT_NULL
    // framing (lo0). Linux's AF_PACKET always delivers Ethernet-framed L2 frames — even
    // on lo — so this distinction is macOS-only.
    enum class LinkType {
        Ethernet,  // DLT_EN10MB: 14-byte Ethernet header.
        Loopback,  // DLT_NULL: 4-byte host-byte-order address family, then IP.
    };
    LinkType link_type_ = LinkType::Ethernet;
#endif
};

} // namespace reflector
