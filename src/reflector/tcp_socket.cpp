#include "tcp_socket.h"

#include "error.h"
#include "logger.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <format>
#include <utility>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace {

using namespace reflector;

Logger& GetLogger() noexcept {
    static Logger logger{"TcpSocket"};
    return logger;
}

// Make `fd` non-blocking and SIGPIPE-safe. On Linux SIGPIPE is suppressed per-send via MSG_NOSIGNAL, so
// only the non-blocking flag is set here; on macOS there is no MSG_NOSIGNAL, so SO_NOSIGPIPE is set once.
[[nodiscard]] bool ConfigureFd(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        GetLogger().Error("Cannot set socket non-blocking: {}", Error::FromErrno());
        return false;
    }
#if defined(__APPLE__)
    const int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
        GetLogger().Error("Cannot set SO_NOSIGPIPE: {}", Error::FromErrno());
        return false;
    }
#endif
    return true;
}

// Pin egress to interface `ifindex` so the connect leaves via that interface even if a host route would
// otherwise send it elsewhere (SO_BINDTODEVICE on Linux — needs CAP_NET_RAW; IP_BOUND_IF on macOS).
[[nodiscard]] bool PinEgress(int fd, [[maybe_unused]] int family, unsigned ifindex) noexcept {
#if defined(__linux__)
    char name[IF_NAMESIZE];
    if (if_indextoname(ifindex, name) == nullptr) {
        GetLogger().Error("Cannot resolve interface index {}: {}", ifindex, Error::FromErrno());
        return false;
    }
    if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, static_cast<socklen_t>(std::strlen(name))) != 0) {
        GetLogger().Error("Cannot pin egress to interface \"{}\": {}", name, Error::FromErrno());
        return false;
    }
#elif defined(__APPLE__)
    const int level = family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int optname = family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
    if (::setsockopt(fd, level, optname, &ifindex, sizeof(ifindex)) != 0) {
        GetLogger().Error("Cannot pin egress to interface index {}: {}", ifindex, Error::FromErrno());
        return false;
    }
#endif
    return true;
}

// getsockname as an IpEndpoint; nullopt on syscall/parse failure. The factories call this once to capture
// the local endpoint at construction, so LocalEndpoint() needs no syscall.
[[nodiscard]] std::optional<IpEndpoint> LocalNameOf(int fd) noexcept {
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        GetLogger().Error("Cannot read local endpoint for fd {}: {}", fd, Error::FromErrno());
        return std::nullopt;
    }
    return IpEndpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&addr));
}

} // namespace

namespace reflector {

TcpSocket::TcpSocket(int fd, const IpEndpoint& local, const std::optional<IpEndpoint>& peer,
    bool connecting) noexcept
        : logger_{std::format("TcpSocket:{}", fd)}
        , local_{local}, peer_{peer}, fd_{fd}, connecting_{connecting} {}

TcpSocket::~TcpSocket() noexcept {
    Close();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
        : send_buffer_{std::move(other.send_buffer_)},
          logger_{std::move(other.logger_)},
          local_{std::move(other.local_)},
          peer_{std::move(other.peer_)},
          fd_{std::move(other.fd_)},
          connecting_{std::exchange(other.connecting_, false)} {}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        send_buffer_ = std::move(other.send_buffer_);
        logger_ = std::move(other.logger_);
        local_ = std::move(other.local_);
        peer_ = std::move(other.peer_);
        fd_ = std::move(other.fd_);
        connecting_ = std::exchange(other.connecting_, false);
    }
    return *this;
}

void TcpSocket::Shutdown() noexcept {
    if (fd_) {
        // Best-effort FIN: ignore ENOTCONN (a refused/never-connected upstream) and the like — the point is
        // to wake a blocked peer, not to report. Keep fd_ valid; Close() still owns the descriptor.
        ::shutdown(fd_.Get(), SHUT_RDWR);
    }
}

void TcpSocket::Close() noexcept {
    if (fd_) {
        logger_.Debug("Closing socket");
        fd_.Reset();
    }
}

std::optional<TcpSocket> TcpSocket::Listen(const IpEndpoint& bind) {
    const int family = bind.addr.IsV6() ? AF_INET6 : AF_INET;
    const int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        GetLogger().Error("Cannot create listening socket: {}", Error::FromErrno());
        return std::nullopt;
    }
    const int on = 1;
    if (!ConfigureFd(fd)) {  // ConfigureFd logs its own failure
        ::close(fd);
        return std::nullopt;
    }
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        GetLogger().Error("Cannot set SO_REUSEADDR: {}", Error::FromErrno());
        ::close(fd);
        return std::nullopt;
    }
    sockaddr_storage addr{};
    const socklen_t len = bind.ToSockaddr(addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0
        || ::listen(fd, SOMAXCONN) != 0) {
        GetLogger().Error("Cannot bind/listen on {}: {}", bind, Error::FromErrno());
        ::close(fd);
        return std::nullopt;
    }
    auto local = LocalNameOf(fd);  // the now-bound addr:ephemeral-port (LocalNameOf logs on failure)
    if (!local) {
        ::close(fd);
        return std::nullopt;
    }
    return TcpSocket{fd, *local, std::nullopt};  // a listener has no peer
}

std::optional<TcpSocket> TcpSocket::Connect(const IpEndpoint& dst, const IpEndpoint& bind, unsigned ifindex) {
    const int family = dst.addr.IsV6() ? AF_INET6 : AF_INET;
    const int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        GetLogger().Error("Cannot create connect socket: {}", Error::FromErrno());
        return std::nullopt;
    }
    if (!ConfigureFd(fd) || (ifindex != 0 && !PinEgress(fd, family, ifindex))) {
        ::close(fd);
        return std::nullopt;
    }
    sockaddr_storage src{};
    const socklen_t src_len = bind.ToSockaddr(src, ifindex);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&src), src_len) != 0) {
        GetLogger().Error("Cannot bind connect source to {}: {}", bind, Error::FromErrno());
        ::close(fd);
        return std::nullopt;
    }
    sockaddr_storage dest{};
    const socklen_t dest_len = dst.ToSockaddr(dest, ifindex);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&dest), dest_len) != 0 && errno != EINPROGRESS) {
        GetLogger().Error("Cannot connect to {}: {}", dst, Error::FromErrno());
        ::close(fd);
        return std::nullopt;
    }
    // connect() has assigned the local endpoint; the peer is dst (getpeername would fail until connected).
    auto local = LocalNameOf(fd);
    if (!local) {
        ::close(fd);
        return std::nullopt;
    }
    // Start CONNECTING — even an immediate (loopback) completion resolves uniformly via the first
    // writable edge + FinishConnect.
    return TcpSocket{fd, *local, dst, /*connecting=*/true};
}

std::optional<TcpSocket> TcpSocket::Accept() noexcept {
    sockaddr_storage peer{};
    socklen_t peer_len = sizeof(peer);
#if defined(__linux__)
    const int client = ::accept4(fd_.Get(), reinterpret_cast<sockaddr*>(&peer), &peer_len, SOCK_NONBLOCK);
#else
    const int client = ::accept(fd_.Get(), reinterpret_cast<sockaddr*>(&peer), &peer_len);
#endif
    if (client < 0) {
        if (!IsWouldBlockErrno(errno)) {
            GetLogger().Error("Cannot accept connection: {}", Error::FromErrno());
        }
        return std::nullopt;
    }
#if defined(__APPLE__)
    // accept() does not inherit non-blocking; set it (+ SO_NOSIGPIPE). accept4 already did on Linux.
    if (!ConfigureFd(client)) {
        ::close(client);
        return std::nullopt;
    }
#endif
    // peer came from accept(); read the local endpoint once here (it matches the listener's bound address).
    auto local = LocalNameOf(client);
    if (!local) {
        ::close(client);
        return std::nullopt;
    }
    return TcpSocket{client, *local, IpEndpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&peer))};
}

bool TcpSocket::FinishConnect() noexcept {
    if (!connecting_) {
        return true;  // nothing in flight; reading SO_ERROR here would clear a pending Read() error
    }
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (::getsockopt(fd_.Get(), SOL_SOCKET, SO_ERROR, &so_error, &len) != 0) {
        logger_.Error("Cannot read SO_ERROR: {}", Error::FromErrno());
        return false;
    }
    if (so_error != 0) {
        logger_.Error("Connect failed: {}", Error::FromErrno(so_error));
        return false;
    }
    connecting_ = false;
    return true;
}

IoResult TcpSocket::Read(std::span<std::byte> out) noexcept {
    const ssize_t n = ::recv(fd_.Get(), out.data(), out.size(), 0);
    if (n > 0) {
        return {IoStatus::Ok, static_cast<size_t>(n)};
    }
    if (n == 0) {
        return {IoStatus::Closed, 0};
    }
    if (IsWouldBlockErrno(errno)) {
        return {IoStatus::WouldBlock, 0};
    }
    logger_.Error("Receive failed: {}", Error::FromErrno());
    return {IoStatus::Error, 0};
}

IoResult TcpSocket::WriteSome(std::span<const std::byte> data) noexcept {
    if (data.empty()) {
        return {IoStatus::Ok, 0};
    }
#if defined(__linux__)
    const ssize_t n = ::send(fd_.Get(), data.data(), data.size(), MSG_NOSIGNAL);
#else
    const ssize_t n = ::send(fd_.Get(), data.data(), data.size(), 0);  // SO_NOSIGPIPE set at creation
#endif
    if (n >= 0) {
        return {IoStatus::Ok, static_cast<size_t>(n)};
    }
    if (IsWouldBlockErrno(errno)) {
        return {IoStatus::WouldBlock, 0};
    }
#if defined(__APPLE__)
    // A write to a still-connecting socket returns ENOTCONN on macOS (Linux returns EWOULDBLOCK, handled
    // above). Only while connecting does it mean "not ready yet": treat it as WouldBlock so the tail buffers
    // and the connect-completion writable edge flushes it, matching Linux. Gated on connecting_ so an
    // ENOTCONN on an established socket stays a real Error; a failed connect is still caught by FinishConnect.
    if (connecting_ && errno == ENOTCONN) {
        return {IoStatus::WouldBlock, 0};
    }
#endif
    logger_.Error("Send failed: {}", Error::FromErrno());
    return {IoStatus::Error, 0};
}

IoResult TcpSocket::WriteSomeV(std::span<const std::span<const std::byte>> chunks) noexcept {
    // Pack the non-empty chunks into an iovec; sendmsg (not writev) so Linux can carry MSG_NOSIGNAL.
    std::array<iovec, MAX_SEND_CHUNKS> iov;
    size_t count = 0;
    for (const std::span<const std::byte> chunk : chunks) {
        if (chunk.empty()) {
            continue;
        }
        if (count == iov.size()) {
            break;  // iovec full; the rest buffers via AppendUnsent (Send already warned). A capped sendmsg
                    // is indistinguishable from a short one — already_sent = bytes written.
        }
        iov[count].iov_base = const_cast<std::byte*>(chunk.data());  // sendmsg only reads the buffers
        iov[count].iov_len = chunk.size();
        ++count;
    }
    if (count == 0) {
        return {IoStatus::Ok, 0};
    }
    msghdr message{};
    message.msg_iov = iov.data();
    message.msg_iovlen = static_cast<decltype(message.msg_iovlen)>(count);
#if defined(__linux__)
    const ssize_t n = ::sendmsg(fd_.Get(), &message, MSG_NOSIGNAL);
#else
    const ssize_t n = ::sendmsg(fd_.Get(), &message, 0);  // SO_NOSIGPIPE set at creation
#endif
    if (n >= 0) {
        return {IoStatus::Ok, static_cast<size_t>(n)};
    }
    if (IsWouldBlockErrno(errno)) {
        return {IoStatus::WouldBlock, 0};
    }
#if defined(__APPLE__)
    if (connecting_ && errno == ENOTCONN) {  // still-connecting socket — see WriteSome's note
        return {IoStatus::WouldBlock, 0};
    }
#endif
    logger_.Error("Send failed: {}", Error::FromErrno());
    return {IoStatus::Error, 0};
}

SendStatus TcpSocket::Send(std::span<const std::byte> data) noexcept {
    // Only write directly when nothing is already queued — otherwise the tail must follow the backlog in
    // order.
    const bool was_buffering = !send_buffer_.Empty();
    if (!was_buffering) {
        const IoResult wrote = WriteSome(data);
        if (wrote.status == IoStatus::Error) {
            return SendStatus::Error;
        }
        data = data.subspan(wrote.bytes);  // bytes == 0 on WouldBlock — buffer the whole tail
        if (data.empty()) {
            return SendStatus::Ok;
        }
    }
    if (!send_buffer_.Append(data)) {
        logger_.Error("Send buffer overflow: {} queued + {}-byte tail exceeds the {}-byte cap",
            send_buffer_.Size(), data.size(), MAX_SEND_BUFFER);
        return SendStatus::Overflow;  // tail would exceed the cap — owner aborts the connection (drop-and-close)
    }
    if (!was_buffering) {
        logger_.Debug("Started buffering, {} bytes queued", send_buffer_.Size());
    }
    return SendStatus::Ok;
}

SendStatus TcpSocket::Send(std::span<const std::span<const std::byte>> chunks) noexcept {
    // One sendmsg carries at most MAX_SEND_CHUNKS chunks; a larger scatter still sends correctly — the overflow
    // buffers and flushes on later writable edges — but a caller only ever passes a header + body (2 chunks),
    // so a scatter this large is unexpected: warn and carry on.
    if (chunks.size() > MAX_SEND_CHUNKS) {
        logger_.Warning("Scatter-send of {} chunks exceeds the {}-chunk sendmsg cap; the overflow "
            "buffers and flushes on later writable edges", chunks.size(), MAX_SEND_CHUNKS);
    }
    // Write through only when nothing is already queued; otherwise the chunks follow the backlog in order
    // (already_sent stays 0, so AppendUnsent queues them whole).
    const size_t backlog = send_buffer_.Size();
    const bool was_buffering = backlog > 0;
    size_t already_sent = 0;
    if (!was_buffering) {
        const IoResult wrote = WriteSomeV(chunks);
        if (wrote.status == IoStatus::Error) {
            return SendStatus::Error;
        }
        already_sent = wrote.bytes;  // 0 on WouldBlock — buffer the whole message
    }
    if (!AppendUnsent(send_buffer_, chunks, already_sent)) {
        size_t total = 0;
        for (const std::span<const std::byte> chunk : chunks) {
            total += chunk.size();
        }
        logger_.Error("Send buffer overflow: {} queued + {}-byte tail exceeds the {}-byte cap",
            backlog, total - already_sent, MAX_SEND_BUFFER);
        return SendStatus::Overflow;  // tail would exceed the cap — owner aborts the connection (drop-and-close)
    }
    if (!was_buffering && !send_buffer_.Empty()) {
        logger_.Debug("Started buffering, {} bytes queued", send_buffer_.Size());
    }
    return SendStatus::Ok;
}

bool TcpSocket::AppendUnsent(StreamBuffer& buf, std::span<const std::span<const std::byte>> chunks,
        size_t already_sent) {
    for (const std::span<const std::byte> chunk : chunks) {
        if (already_sent >= chunk.size()) {  // this whole chunk is already on the wire
            already_sent -= chunk.size();
            continue;
        }
        // Append the unsent part of this chunk, then every later chunk whole. On overflow a partial append may
        // have landed, but the caller logs and aborts the connection, so the buffer is discarded unflushed.
        if (!buf.Append(chunk.subspan(already_sent))) {
            return false;
        }
        already_sent = 0;
    }
    return true;
}

bool TcpSocket::Flush() noexcept {
    const bool was_buffering = !send_buffer_.Empty();
    while (!send_buffer_.Empty()) {
        const IoResult wrote = WriteSome(send_buffer_.View());
        if (wrote.status == IoStatus::Error) {
            return false;
        }
        if (wrote.bytes == 0) {
            break;  // WouldBlock (the only zero-byte result here) — resume on the next writable edge
        }
        send_buffer_.Consume(wrote.bytes);
    }
    if (was_buffering && send_buffer_.Empty()) {
        logger_.Debug("Send buffer drained, resumed direct writes");
    }
    return true;
}

} // namespace reflector
