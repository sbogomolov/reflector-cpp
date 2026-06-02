#pragma once

#include "reflector/ip_endpoint.h"
#include "reflector/util/no_copy.h"
#include "reflector/util/send_buffer.h"

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
// dispatcher (design §4.2 / decision D12). That inertness is what makes it safe to move (Accept returns
// one by value; an owner stores it by value). SIGPIPE-safe.
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
    // return Ok (Error on failure). Once established it is a no-op Ok, so it is safe to call on any
    // writable edge without first checking IsConnecting().
    [[nodiscard]] IoStatus FinishConnect() noexcept;

    // Read up to `out.size()` bytes into `out`.
    [[nodiscard]] IoResult Read(std::span<std::byte> out) noexcept;

    // Send `data`: write what the kernel takes now, buffer the unsent tail. Overflow if the tail would
    // exceed MAX_SEND_BUFFER (owner aborts the connection).
    [[nodiscard]] SendStatus Send(std::span<const std::byte> data) noexcept;

    // Flush the buffered tail on a writable edge.
    [[nodiscard]] SendStatus Flush() noexcept;

    // Whether the socket wants a writable event: connecting, or has a buffered tail. The owner forwards
    // this to Dispatcher::SetWriteInterest.
    [[nodiscard]] bool WantsWrite() const noexcept { return connecting_ || !send_buffer_.Empty(); }

    [[nodiscard]] std::optional<IpEndpoint> LocalEndpoint() const noexcept;  // getsockname
    [[nodiscard]] std::optional<IpEndpoint> PeerEndpoint() const noexcept;   // getpeername

    void Close() noexcept;

private:
    // Wraps an owned fd; `connecting` is true only for a Connect() socket awaiting completion.
    explicit TcpSocket(int fd, bool connecting = false) noexcept;

    // Write as much of `data` as the kernel takes now (SIGPIPE-safe): Ok with the bytes written,
    // WouldBlock (0 bytes) when the kernel buffer is full, or Error on a fatal failure.
    [[nodiscard]] IoResult WriteSome(std::span<const std::byte> data) noexcept;

    // Outbound-buffer cap: a Send whose tail would exceed this aborts the connection (drop-and-close).
    // Sits well above any single DIAL message (a device-description XML is a few KB) — the proxy carries
    // only small HTTP control messages — while bounding per-connection memory; mostly a stall/DoS valve.
    static constexpr size_t MAX_SEND_BUFFER = 64 * 1024;

    // Members largest-first so the struct's only padding is at the end.
    SendBuffer send_buffer_;
    int fd_ = -1;
    bool connecting_ = false;
};

} // namespace reflector
