#pragma once

#include "reflector/ip_endpoint.h"
#include "reflector/util/no_copy.h"
#include "reflector/util/stream_buffer.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// Outcome of a non-blocking read or write.
enum class IoStatus : uint8_t {
    Ok,         // bytes were moved (IoResult::bytes > 0)
    WouldBlock, // EAGAIN/EWOULDBLOCK — nothing ready; retry on the next readable/writable edge
    Closed,     // orderly EOF (recv returned 0) — the peer closed its write half (read only)
    Error,      // fatal error — the connection is dead
};

struct IoResult {
    IoStatus status = IoStatus::Error;
    size_t bytes = 0;
};

// Outcome of a write/flush.
enum class SendStatus : uint8_t {
    Ok,        // sent, or the unsent tail was buffered within the cap
    Overflow,  // the tail would exceed the send-buffer cap — the owner must abort the connection
    Error,     // fatal send error
};

// A move-only, non-blocking TCP socket. It is deliberately DISPATCHER-INERT: it holds no Registration
// and never toggles write interest — the owner registers the fd and forwards WantsWrite() to the
// dispatcher. That inertness is what makes it safe to move (Accept returns one by value; an owner
// stores it by value). SIGPIPE-safe.
class TcpSocket : NoCopy {
public:
    // Listening socket bound to `bind` (port 0 = ephemeral; read it back via LocalEndpoint). Bound to a
    // specific address (not 0.0.0.0/::) so only that subnet can reach it. nullopt on failure.
    [[nodiscard]] static std::optional<TcpSocket> Listen(const IpEndpoint& bind);

    // Begin a non-blocking connect from `bind` to `dst`, egress-pinned to interface `ifindex` (0 = no
    // pin, e.g. loopback). The socket starts CONNECTING; completion is observed on the writable edge via
    // FinishConnect (a failure also surfaces on the next Read as an error). `ifindex` also scopes a
    // link-local IPv6 destination. nullopt if the connect can't be initiated.
    [[nodiscard]] static std::optional<TcpSocket> Connect(const IpEndpoint& dst, const IpEndpoint& bind,
        unsigned ifindex = 0);

    // Accept the next pending client (non-blocking) as a new ESTABLISHED socket; nullopt on EAGAIN/error.
    [[nodiscard]] std::optional<TcpSocket> Accept() noexcept;

    ~TcpSocket() noexcept;
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int Fd() const noexcept { return fd_; }
    [[nodiscard]] bool IsConnecting() const noexcept { return connecting_; }

    // On the writable edge: if connecting, read SO_ERROR and on success clear the connecting flag and
    // return true (false on connect failure). Once established it is a no-op returning true, so it is safe
    // to call on any writable edge without first checking IsConnecting().
    [[nodiscard]] bool FinishConnect() noexcept;

    // Read up to `out.size()` bytes into `out`.
    [[nodiscard]] IoResult Read(std::span<std::byte> out) noexcept;

    // Send `data`: write what the kernel takes now, buffer the unsent tail. Overflow if the tail would
    // exceed MAX_SEND_BUFFER (owner aborts the connection).
    [[nodiscard]] SendStatus Send(std::span<const std::byte> data) noexcept;

    // Scatter-gather send: write `chunks` (e.g. header + body) in one sendmsg, buffering any unsent tail.
    // Same Overflow/Error contract as the single-span Send. Up to MAX_SEND_CHUNKS chunks ride the sendmsg; a
    // call with more warns and buffers the overflow (flushed on later writable edges).
    [[nodiscard]] SendStatus Send(std::span<const std::span<const std::byte>> chunks) noexcept;

    // Flush the buffered tail on a writable edge. true if it drained (or partially drained and would block —
    // resume on the next edge); false on a fatal write error (the owner aborts).
    [[nodiscard]] bool Flush() noexcept;

    // Whether the socket wants a writable event: connecting, or has a buffered tail. The owner forwards
    // this to Dispatcher::SetWriteInterest.
    [[nodiscard]] bool WantsWrite() const noexcept { return connecting_ || !send_buffer_.Empty(); }

    // The socket's endpoints, captured once at construction (Listen/Connect/Accept) — no syscall, returned by
    // reference (no copy). Local is always known; peer is empty for a listener (it has no connected peer).
    [[nodiscard]] const IpEndpoint& LocalEndpoint() const noexcept { return local_; }
    [[nodiscard]] const std::optional<IpEndpoint>& PeerEndpoint() const noexcept { return peer_; }

    // Half-close both directions (send a FIN to the peer now) without releasing the fd — the owner uses this
    // to make a deferred teardown's FIN reach the peer promptly while the socket lives on until Close(). The
    // fd stays valid (Close() still owns the descriptor). Best-effort: a never-connected or already-reset
    // socket (ENOTCONN/EINVAL) is a no-op, not an error.
    void Shutdown() noexcept;
    void Close() noexcept;

private:
    // The scatter-gather boundary-walk (AppendUnsent) is private; a partial sendmsg can't be steered onto an
    // exact chunk seam through a live socket (kernel slop), so the test drives it directly with a chosen count.
    friend class TcpSocketTest;

    // Wraps an owned fd with its endpoints, known at construction (`peer` empty for a listener); `connecting`
    // is true only for a Connect() socket awaiting completion.
    TcpSocket(int fd, const IpEndpoint& local, const std::optional<IpEndpoint>& peer,
        bool connecting = false) noexcept;

    // Write as much of `data` as the kernel takes now (SIGPIPE-safe): Ok with the bytes written,
    // WouldBlock (0 bytes) when the kernel buffer is full, or Error on a fatal failure.
    [[nodiscard]] IoResult WriteSome(std::span<const std::byte> data) noexcept;

    // Like WriteSome but scatter-gather: write as much of `chunks` as the kernel takes now in one sendmsg
    // (SIGPIPE-safe). Same Ok/WouldBlock/Error contract as WriteSome.
    [[nodiscard]] IoResult WriteSomeV(std::span<const std::span<const std::byte>> chunks) noexcept;

    // Append to `buf` the portion of `chunks` past the first `already_sent` bytes — the tail a partial sendmsg
    // didn't take, walked across the chunk boundary (a count landing inside a chunk splits it). Returns false
    // on overflow (a chunk didn't fit); a partial append may have landed, but the caller logs and aborts, so
    // the buffer is discarded.
    [[nodiscard]] static bool AppendUnsent(StreamBuffer& buf,
        std::span<const std::span<const std::byte>> chunks, size_t already_sent);

    // Outbound-buffer cap: a Send whose unsent tail would exceed this aborts the connection (drop-and-close).
    // DIAL carries only small control messages that the kernel accepts immediately, so in normal operation
    // this buffer stays empty — StreamBuffer is lazily allocated, so an undrained-tail of 0 costs no bytes —
    // and the cap only ever bites a genuinely stalled peer. Independent of the receive cap (a single message
    // never fills it), so it is not part of the receive-buffer cap hierarchy.
    static constexpr size_t MAX_SEND_BUFFER = 8 * 1024;

    // One scatter-gather Send packs up to this many chunks into a single sendmsg (DIAL passes 2: header +
    // body); a call with more warns and buffers the overflow. Sizes the stack iovec.
    static constexpr size_t MAX_SEND_CHUNKS = 8;

    // Members largest-first so the struct's only padding is at the end.
    StreamBuffer send_buffer_{MAX_SEND_BUFFER};
    IpEndpoint local_;                // bound addr (Listen) / connect source / accept local — always known
    std::optional<IpEndpoint> peer_;  // the connected peer; empty for a listener
    int fd_ = -1;
    bool connecting_ = false;
};

} // namespace reflector
