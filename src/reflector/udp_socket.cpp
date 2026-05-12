#include "error.h"
#include "udp_socket.h"

#include <cerrno>
#include <fcntl.h>
#include <format>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace reflector {

UdpSocket::UdpSocket() {
    logger_.Debug("Creating socket");
    socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ < 0) {
        logger_.Error("Cannot create socket: {}", Error::FromErrno());
        return;
    }

    logger_.SetName(std::format("UdpSocket:{}", socket_));

    if (!SetNonBlocking()) {
        Close();
    }
}

UdpSocket::~UdpSocket() noexcept {
    Close();
}

void UdpSocket::Close() noexcept {
    if (socket_ >= 0) {
        logger_.Debug("Closing socket");
        close(socket_);
        socket_ = -1;
    }
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
        : logger_{std::move(other.logger_)}
        , interface_{std::move(other.interface_)}
        , address_{std::exchange(other.address_, IpAddress::Any())}
        , socket_{std::exchange(other.socket_, -1)}
        , port_{std::exchange(other.port_, 0)} {}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Close();

    logger_ = std::move(other.logger_);
    interface_ = std::move(other.interface_);
    address_ = std::exchange(other.address_, IpAddress::Any());
    socket_ = std::exchange(other.socket_, -1);
    port_ = std::exchange(other.port_, 0);

    return *this;
}

bool UdpSocket::SetNonBlocking() noexcept {
    const auto flags = fcntl(socket_, F_GETFL, 0);
    if (flags < 0) {
        logger_.Error("Cannot get socket flags: {}", Error::FromErrno());
        return false;
    }

    if ((flags & O_NONBLOCK) != 0) {
        return true;
    }

    if (fcntl(socket_, F_SETFL, flags | O_NONBLOCK) != 0) {
        logger_.Error("Cannot make socket nonblocking: {}", Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::SetInterface(std::string_view interface) {
    if (!IsValid()) {
        logger_.Error("Cannot set interface to \"{}\": socket is invalid", interface);
        return false;
    }

    logger_.Info("Setting interface to \"{}\"", interface);
    interface_ = interface;

#if defined(__linux__)
    const auto interface_size = interface_.size() + 1;
    if (interface_size > IF_NAMESIZE) {
        logger_.Error("Cannot set SO_BINDTODEVICE to \"{}\": interface name is too long", interface);
        return false;
    }
    if (setsockopt(socket_, SOL_SOCKET, SO_BINDTODEVICE, interface_.c_str(), static_cast<socklen_t>(interface_size)) != 0) {
        logger_.Error("Cannot set SO_BINDTODEVICE to \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
#elif defined(__APPLE__)
    unsigned int idx = if_nametoindex(interface_.c_str());
    if (idx == 0) {
        logger_.Error("Cannot resolve interface \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
    if (setsockopt(socket_, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) != 0) {
        logger_.Error("Cannot set IP_BOUND_IF to \"{}\" (index {}): {}",
                      interface, idx, Error::FromErrno());
        return false;
    }
#endif

    return true;
}

bool UdpSocket::SetBroadcast(bool enabled) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot set SO_BROADCAST to {}: socket is invalid", enabled);
        return false;
    }

    int value = enabled ? 1 : 0;
    if (setsockopt(socket_, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value)) != 0) {
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
    if (setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0) {
        logger_.Error("Cannot set SO_REUSEADDR to {}: {}", enabled, Error::FromErrno());
        return false;
    }

    return true;
}

bool UdpSocket::Bind(uint16_t port) {
    return Bind(IpAddress::Any(), port);
}

bool UdpSocket::Bind(IpAddress address, uint16_t port) {
    if (!IsValid()) {
        logger_.Error("Cannot bind to port {}: socket is invalid", port);
        return false;
    }

    logger_.Info("Binding socket to {}:{}", address, port);
    address_ = address;
    port_ = port;

    sockaddr_in socket_address{};
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port);
    socket_address.sin_addr.s_addr = address.InAddr();

    if (bind(socket_, reinterpret_cast<sockaddr*>(&socket_address), sizeof(socket_address)) != 0) {
        logger_.Error("Cannot bind UDP socket: {}", Error::FromErrno());
        return false;
    }

    logger_.Debug("Bound UDP socket to {}:{}", address, port);
    return true;
}

bool UdpSocket::SendTo(std::span<const std::byte> payload, IpAddress address, uint16_t port) noexcept {
    if (!IsValid()) {
        logger_.Error("Cannot send to {}:{}: socket is invalid", address, port);
        return false;
    }

    sockaddr_in destination_address{};
    destination_address.sin_family = AF_INET;
    destination_address.sin_port = htons(port);
    destination_address.sin_addr.s_addr = address.InAddr();

    ssize_t bytes_sent;
    do {
        bytes_sent = sendto(socket_,
            payload.data(),
            payload.size(),
            0,
            reinterpret_cast<sockaddr*>(&destination_address),
            sizeof(destination_address));
    } while (bytes_sent < 0 && errno == EINTR);
    if (bytes_sent < 0) {
        logger_.Error("Cannot send UDP packet to {}:{}: {}", address, port, Error::FromErrno());
        return false;
    }

    logger_.Debug("Sent {} bytes to {}:{}", bytes_sent, address, port);
    return true;
}

} // namespace reflector
