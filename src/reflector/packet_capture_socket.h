#pragma once

#include "logger.h"
#include "packet.h"
#include "util/no_move.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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
// Immovable so registered instances stay put: Dispatcher caches the socket address in its
// kernel event queue (epoll data.ptr / kqueue udata) and in registration entries; a move
// would silently invalidate those pointers. Hold instances in storage that preserves
// element addresses (stack, std::optional, node-based map) — std::vector won't do.
class PacketCaptureSocket : NoMove {
public:
    explicit PacketCaptureSocket(std::string_view interface);
    ~PacketCaptureSocket() noexcept;

    // Test-only: wrap an arbitrary fd without performing any OS-level capture setup.
    // Receive() consumes bytes from that fd the same way the production socket would,
    // so tests can either synthesize Packets via Dispatcher::DispatchPacket directly
    // (when nothing is written to the fd) or drive real frames end-to-end via
    // TestCaptureSocket::WriteFrame.
    [[nodiscard]] static PacketCaptureSocket ForTesting(std::string_view interface, int owned_fd);

    [[nodiscard]] bool IsValid() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int Fd() const noexcept { return fd_; }
    [[nodiscard]] std::string_view Interface() const noexcept { return interface_; }

    // Returns the next parsed UDP datagram. The returned Packet's payload spans into the
    // socket's internal buffer and is valid until the next Receive() call on this socket.
    // Returns nullopt when no datagram is currently available (EAGAIN), or when the next
    // frame is unparseable / fragmented — caller treats both the same way and tries again
    // on the next read event.
    [[nodiscard]] std::optional<Packet> Receive() noexcept;

#if defined(__APPLE__)
    // True if there are unparsed bytes in the socket's userland buffer. macOS BPF batches
    // multiple frames per read() into our buffer; if the dispatcher stops draining before
    // the batch is consumed, kqueue won't fire again (the kernel side is empty) and the
    // remaining frames would stall. Dispatcher uses this to keep draining past the
    // packet-per-event cap while the buffer still has data. Not defined on Linux because
    // AF_PACKET delivers one frame per recv with no userland buffering.
    [[nodiscard]] bool HasBufferedData() const noexcept;

    // Discards any unparsed bytes in the userland buffer. Dispatcher calls this when it
    // abandons a drain mid-batch (last registration for this fd was unregistered by a
    // callback); the leftover frames would otherwise sit until either the socket is
    // destroyed or new kernel data arrives to trigger a fresh drain.
    void ClearBuffer() noexcept;
#endif

private:
    friend class PacketCaptureSocketTest;

    enum class TestingTag {};
    PacketCaptureSocket(TestingTag, std::string_view interface, int owned_fd) noexcept;

    void Close() noexcept;

    [[nodiscard]] std::optional<Packet> ParseFrame(std::span<const std::byte> frame) noexcept;

    Logger logger_;
    std::string interface_;
    int fd_ = -1;

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
