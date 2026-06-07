#include "port_reservation.h"

#include "error.h"
#include "logger.h"

#include <cstdint>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#if defined(__linux__)
#include <linux/filter.h>
#endif

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"PortReservation"};
    return logger;
}

} // namespace

std::optional<PortReservation> PortReservation::Create(const IpAddress& source_ip, unsigned scope_id) noexcept {
    const bool v6 = source_ip.IsV6();
    const int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        GetLogger().Error("Cannot open port reservation socket: {}", Error::FromErrno());
        return std::nullopt;
    }

#if defined(__linux__)
    // Drop every packet at the socket filter: the bind below already suppresses the ICMP NAK, and
    // the real 200 OK is captured by the raw socket — this socket must enqueue nothing.
    sock_filter drop_all[] = {{0x06, 0, 0, 0x00000000}};  // BPF_RET | BPF_K, 0
    sock_fprog program{.len = 1, .filter = drop_all};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) != 0) {
        GetLogger().Error("Cannot attach drop-all filter to port reservation socket: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }
#endif

    sockaddr_storage storage{};
    const socklen_t length = source_ip.ToSockaddr(storage, /*port=*/0, scope_id);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
        GetLogger().Error("Cannot bind port reservation socket: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }

    sockaddr_storage bound{};
    socklen_t bound_length = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
        GetLogger().Error("Cannot query the reserved port: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }
    const uint16_t port = v6
        ? ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);

    return PortReservation{fd, port};
}

PortReservation::PortReservation(PortReservation&& other) noexcept
        : fd_{std::move(other.fd_)}, port_{std::exchange(other.port_, 0)} {}

PortReservation& PortReservation::operator=(PortReservation&& other) noexcept {
    if (this != &other) {
        fd_ = std::move(other.fd_);
        port_ = std::exchange(other.port_, 0);
    }
    return *this;
}

} // namespace reflector
