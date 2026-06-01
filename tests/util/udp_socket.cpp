#include "udp_socket.h"

#include "reflector/error.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace reflector {

UdpSocket::UdpSocket(IpAddress::Family family) : family_{family} {
    logger_.Debug("Creating socket");
    fd_ = socket(family == IpAddress::Family::V6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
        if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
            logger_.Warning("Cannot create socket: address family not supported: {}", Error::FromErrno());
        } else {
            logger_.Error("Cannot create socket: {}", Error::FromErrno());
        }
        return;
    }

    logger_.SetName(std::format("UdpSocket:{}", fd_));

    if (!SetNonBlocking()) {
        Close();
    }
}

UdpSocket::~UdpSocket() noexcept {
    Close();
}

void UdpSocket::Close() noexcept {
    if (fd_ >= 0) {
        logger_.Debug("Closing socket");
        close(fd_);
        fd_ = -1;
    }
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
        : logger_{std::move(other.logger_)}
        , fd_{std::exchange(other.fd_, -1)}
        , family_{other.family_}
        , interface_index_{std::exchange(other.interface_index_, 0)} {}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Close();

    logger_ = std::move(other.logger_);
    fd_ = std::exchange(other.fd_, -1);
    family_ = other.family_;
    interface_index_ = std::exchange(other.interface_index_, 0);

    return *this;
}

bool UdpSocket::SetNonBlocking() noexcept {
    const auto flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0) {
        logger_.Error("Cannot get socket flags: {}", Error::FromErrno());
        return false;
    }

    if ((flags & O_NONBLOCK) != 0) {
        return true;
    }

    if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        logger_.Error("Cannot make socket nonblocking: {}", Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::IsInterfaceConsistent(const std::string& interface, unsigned int index) noexcept {
    if (interface_index_ != 0 && interface_index_ != index) {
        logger_.Error("Cannot use interface \"{}\": socket is already bound to a different interface (index {})",
                      interface, interface_index_);
        return false;
    }
    return true;
}

bool UdpSocket::SetInterface(const std::string& interface) {
    if (!IsValid()) {
        logger_.Error("Cannot set interface to \"{}\": socket is invalid", interface);
        return false;
    }

    logger_.Info("Setting interface to \"{}\"", interface);

    const unsigned int idx = if_nametoindex(interface.c_str());
    if (idx == 0) {
        logger_.Error("Cannot resolve interface \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
    if (!IsInterfaceConsistent(interface, idx)) {
        return false;
    }

#if defined(__linux__)
    const auto interface_size = interface.size() + 1;
    if (interface_size > IF_NAMESIZE) {
        logger_.Error("Cannot set SO_BINDTODEVICE to \"{}\": interface name is too long", interface);
        return false;
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), static_cast<socklen_t>(interface_size)) != 0) {
        logger_.Error("Cannot set SO_BINDTODEVICE to \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
#elif defined(__APPLE__)
    const int level = family_ == IpAddress::Family::V6 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int option = family_ == IpAddress::Family::V6 ? IPV6_BOUND_IF : IP_BOUND_IF;
    if (setsockopt(fd_, level, option, &idx, sizeof(idx)) != 0) {
        logger_.Error("Cannot bind socket to interface \"{}\" (index {}): {}",
                      interface, idx, Error::FromErrno());
        return false;
    }
#endif

    interface_index_ = idx;
    return true;
}

bool UdpSocket::SetBroadcast(bool enabled) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot set SO_BROADCAST to {}: socket is invalid", enabled);
        return false;
    }

    int value = enabled ? 1 : 0;
    if (setsockopt(fd_, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value)) != 0) {
        logger_.Error("Cannot set SO_BROADCAST to {}: {}", enabled, Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::SetReuseAddr(bool enabled) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot set SO_REUSEADDR to {}: socket is invalid", enabled);
        return false;
    }

    int value = enabled ? 1 : 0;
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0) {
        logger_.Error("Cannot set SO_REUSEADDR to {}: {}", enabled, Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::SetV6Only(bool enabled) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot set IPV6_V6ONLY to {}: socket is invalid", enabled);
        return false;
    }
    if (family_ != IpAddress::Family::V6) {
        logger_.Error("Cannot set IPV6_V6ONLY to {}: socket is not IPv6", enabled);
        return false;
    }

    int value = enabled ? 1 : 0;
    if (setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)) != 0) {
        logger_.Error("Cannot set IPV6_V6ONLY to {}: {}", enabled, Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::SetMulticastInterface(const std::string& interface) {
    if (!IsValid()) {
        logger_.Error("Cannot set multicast interface to \"{}\": socket is invalid", interface);
        return false;
    }
    if (family_ != IpAddress::Family::V6) {
        logger_.Error("Cannot set multicast interface to \"{}\": socket is not IPv6", interface);
        return false;
    }

    const unsigned int idx = if_nametoindex(interface.c_str());
    if (idx == 0) {
        logger_.Error("Cannot resolve interface \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
    if (!IsInterfaceConsistent(interface, idx)) {
        return false;
    }

    if (setsockopt(fd_, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx)) != 0) {
        logger_.Error("Cannot set IPV6_MULTICAST_IF to \"{}\" (index {}): {}",
                      interface, idx, Error::FromErrno());
        return false;
    }

    interface_index_ = idx;
    return true;
}

bool UdpSocket::JoinMulticastGroup(const IpAddress& group, const std::string& interface) {
    if (!IsValid()) {
        logger_.Error("Cannot join multicast group {}: socket is invalid", group);
        return false;
    }
    if (group.AddressFamily() != family_) {
        logger_.Error("Cannot join multicast group {}: address family does not match the socket",
                      group);
        return false;
    }

    const unsigned int idx = if_nametoindex(interface.c_str());
    if (idx == 0) {
        logger_.Error("Cannot resolve interface \"{}\": {}", interface, Error::FromErrno());
        return false;
    }

    // Protocol-independent, interface-by-index join (RFC 3678) — one path for both families, no
    // IPv4 by-address fallback. ToSockaddr fills the group sockaddr and the BSD length field the
    // kernel requires for the embedded address. Mirrors RawSocket::JoinMulticastGroup.
    group_req request{};
    request.gr_interface = idx;
    group.ToSockaddr(reinterpret_cast<sockaddr_storage&>(request.gr_group), /*port=*/0);
    const int level = family_ == IpAddress::Family::V6 ? IPPROTO_IPV6 : IPPROTO_IP;
    if (setsockopt(fd_, level, MCAST_JOIN_GROUP, &request, sizeof(request)) != 0) {
        logger_.Error("Cannot join multicast group {} on \"{}\": {}", group, interface,
                      Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::Bind(uint16_t port) {
    return Bind(family_ == IpAddress::Family::V6 ? IpAddress::AnyV6() : IpAddress::AnyV4(), port);
}

bool UdpSocket::Bind(const IpAddress& address, uint16_t port) {
    if (!IsValid()) {
        logger_.Error("Cannot bind to port {}: socket is invalid", port);
        return false;
    }
    if (address.AddressFamily() != family_) {
        logger_.Error("Cannot bind to {}:{}: address family does not match the socket's", address, port);
        return false;
    }

    logger_.Info("Binding socket to {}:{}", address, port);

    sockaddr_storage storage{};
    const socklen_t length = address.ToSockaddr(storage, port);
    if (bind(fd_, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
        logger_.Error("Cannot bind UDP socket: {}", Error::FromErrno());
        return false;
    }

    logger_.Debug("Bound UDP socket to {}:{}", address, port);
    return true;
}

bool UdpSocket::SendTo(std::span<const std::byte> payload, const IpAddress& address, uint16_t port) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot send to {}:{}: socket is invalid", address, port);
        return false;
    }
    if (address.AddressFamily() != family_) {
        logger_.Error("Cannot send to {}:{}: address family does not match the socket's", address, port);
        return false;
    }

    sockaddr_storage storage{};
    const socklen_t length = address.ToSockaddr(storage, port, interface_index_);

    ssize_t bytes_sent;
    do {
        bytes_sent = sendto(fd_,
            payload.data(),
            payload.size(),
            0,
            reinterpret_cast<sockaddr*>(&storage),
            length);
    } while (bytes_sent < 0 && errno == EINTR);
    if (bytes_sent < 0) {
        logger_.Error("Cannot send UDP packet to {}:{}: {}", address, port, Error::FromErrno());
        return false;
    }

    logger_.Debug("Sent {} bytes to {}:{}", bytes_sent, address, port);
    return true;
}

} // namespace reflector
