#pragma once

#include "udp_socket.h"
#include "util/no_copy.h"

#include <cstdint>
#include <string>

namespace reflector {

class UdpListener : NoCopy {
public:
    struct Options {
        std::string interface;
        IpAddress local_ip = IpAddress::Any();
        uint16_t local_port = 0;
    };

    explicit UdpListener(const Options& options);

    [[nodiscard]] bool IsValid() const noexcept { return socket_.IsValid(); }
    [[nodiscard]] const UdpSocket& Socket() const noexcept { return socket_; }

private:
    UdpSocket socket_;
};

} // namespace reflector
