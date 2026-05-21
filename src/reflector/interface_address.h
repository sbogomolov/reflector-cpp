#pragma once

#include "ip_address.h"
#include "mac_address.h"

#include <optional>
#include <string_view>

namespace reflector {

// The source addresses a network interface can originate packets from, as resolved from
// getifaddrs. Used by the raw egress path, which (unlike a kernel UDP socket) must supply the
// source IP and MAC itself when building frames.
struct InterfaceAddresses {
    MacAddress mac{};             // link-layer address; all-zero when the interface has none (e.g. loopback)
    std::optional<IpAddress> v4;  // the interface's IPv4 address, if any
    std::optional<IpAddress> v6;  // the interface's IPv6 link-local (fe80::) address, if any
};

// Resolves `interface`'s MAC and per-family source addresses; fields are left empty for
// anything the interface lacks (or if the interface is unknown). The IPv6 result is the
// link-local address, which is the correct source for the link-local multicast we send. Needs
// no special privilege.
[[nodiscard]] InterfaceAddresses ResolveInterfaceAddresses(std::string_view interface) noexcept;

} // namespace reflector
