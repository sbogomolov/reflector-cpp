#pragma once

#include "udp_socket.h"
#include "util/no_copy.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace reflector {

// Sends packets to a family-appropriate "everyone on the link" address: the IPv4 limited
// broadcast 255.255.255.255, or the IPv6 link-local all-nodes multicast ff02::1.
class UdpLinkFanoutSender : NoCopy {
public:
    UdpLinkFanoutSender(std::string_view interface, IpAddress::Family family);
    UdpLinkFanoutSender(std::string_view interface, IpAddress destination_address);

    [[nodiscard]] bool IsValid() const noexcept { return valid_; }
    [[nodiscard]] IpAddress::Family AddressFamily() const noexcept { return destination_address_.AddressFamily(); }
    [[nodiscard]] IpAddress DestinationAddress() const noexcept { return destination_address_; }
    [[nodiscard]] bool Send(std::span<const std::byte> payload, uint16_t port) noexcept;

private:
    [[nodiscard]] bool SetUp() noexcept;

    UdpSocket socket_;
    std::string interface_;
    IpAddress destination_address_;
    bool valid_ = false;
};

} // namespace reflector
