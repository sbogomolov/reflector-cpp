#pragma once

#include "ip_address.h"
#include "logger.h"
#include "util/no_copy.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace reflector {

class UdpSocket : NoCopy {
public:
    UdpSocket();
    ~UdpSocket();

    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return socket_ >= 0; }
    [[nodiscard]] int Fd() const noexcept { return socket_; }

    void Close() noexcept;

    [[nodiscard]] bool SetInterface(std::string_view interface);
    [[nodiscard]] bool SetBroadcast(bool enabled) noexcept;
    [[nodiscard]] bool SetReuseAddr(bool enabled) noexcept;
    [[nodiscard]] bool Bind(uint16_t port);
    [[nodiscard]] bool Bind(IpAddress address, uint16_t port);
    [[nodiscard]] bool SendTo(std::span<const std::byte> payload, IpAddress address, uint16_t port) noexcept;

private:
    [[nodiscard]] bool SetNonBlocking() noexcept;
    void UpdateName();

    std::string name_;
    Logger logger_;
    std::string interface_;
    IpAddress address_ = IpAddress::Any();
    int socket_ = -1;
    uint16_t port_ = 0;
};

} // namespace reflector
