#pragma once

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "reflector/logger.h"
#include "reflector/util/no_copy.h"
#include "reflector/util/unique_fd.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace reflector {

class UdpSocket : NoCopy {
public:
    explicit UdpSocket(IpAddress::Family family);
    ~UdpSocket() noexcept;

    UdpSocket(UdpSocket&&) noexcept = default;
    UdpSocket& operator=(UdpSocket&&) noexcept = default;

    [[nodiscard]] bool IsValid() const noexcept { return fd_.IsValid(); }
    [[nodiscard]] int Fd() const noexcept { return fd_.Get(); }
    [[nodiscard]] IpAddress::Family AddressFamily() const noexcept { return family_; }

    void Close() noexcept;

    [[nodiscard]] bool SetInterface(const std::string& interface);
    [[nodiscard]] bool SetBroadcast(bool enabled) noexcept;
    [[nodiscard]] bool SetReuseAddr(bool enabled) noexcept;
    [[nodiscard]] bool SetV6Only(bool enabled) noexcept;
    [[nodiscard]] bool SetMulticastInterface(const std::string& interface);

    // Subscribes to `group` on `interface` (IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP), so datagrams
    // sent to that group and arriving on the interface are delivered to this socket. `group`'s
    // family must match the socket's.
    [[nodiscard]] bool JoinMulticastGroup(const IpAddress& group, const std::string& interface);
    [[nodiscard]] bool Bind(uint16_t port);
    [[nodiscard]] bool Bind(const IpEndpoint& endpoint);
    [[nodiscard]] bool SendTo(std::span<const std::byte> payload, const IpEndpoint& endpoint) noexcept;

private:
    [[nodiscard]] bool IsInterfaceConsistent(const std::string& interface, unsigned int index) noexcept;

    Logger logger_{"UdpSocket"};
    UniqueFd fd_;
    IpAddress::Family family_;
    // Used as the IPv6 scope id for link-local sends; 0 means no interface selected.
    unsigned interface_index_ = 0;
};

} // namespace reflector
