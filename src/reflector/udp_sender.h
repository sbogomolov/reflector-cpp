#pragma once

#include "logger.h"
#include "udp_socket.h"
#include "util/no_copy.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace reflector {

class UdpSender : NoCopy {
public:
    explicit UdpSender(std::string_view interface);
    UdpSender(std::string_view interface, IpAddress broadcast_address);

    [[nodiscard]] bool IsValid() const noexcept { return valid_; }
    [[nodiscard]] IpAddress BroadcastAddress() const noexcept { return broadcast_address_; }
    [[nodiscard]] bool SendBroadcast(std::span<const std::byte> payload, uint16_t port) noexcept;

private:
    Logger logger_{"UdpSender"};
    UdpSocket socket_;
    std::string interface_;
    IpAddress broadcast_address_;
    bool valid_ = false;
};

} // namespace reflector
