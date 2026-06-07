#pragma once

#include "ip_address.h"
#include "mac_address.h"

#include <optional>
#include <span>
#include <string_view>

namespace reflector {

// The source addresses a network interface can originate packets from, as resolved from
// getifaddrs. Used by the raw egress path, which (unlike a kernel UDP socket) must supply the
// source IP and MAC itself when building frames.
struct InterfaceAddresses {
    MacAddress mac{};             // all-zero when the interface has none (e.g. loopback)
    std::optional<IpAddress> v4;
    std::optional<IpAddress> v6;  // the interface's IPv6 link-local (fe80::) address, if any
};

namespace detail {

// Folds an interface's usable candidate addresses into `result`: the first IPv4, and the
// best-ranked IPv6 (link-local > ULA > GUA > other). Leaves result.mac untouched — the resolver
// sets that separately. Split out from the platform resolvers so the preference policy is testable
// without a real interface that happens to carry the right address mix.
void SelectSourceAddresses(std::span<const IpAddress> candidates, InterfaceAddresses& result) noexcept;

} // namespace detail

// Resolves an interface's MAC and per-family source addresses; fields are left empty for
// anything it lacks (or if it's unknown). The IPv6 result prefers a link-local address (the
// correct source for the link-local multicast we send), falling back to ULA then GUA, and skips
// tentative/deprecated/duplicated addresses. Needs no special privilege.
//
// Keyed by the identifier each platform resolves natively — and that RawSocket already holds:
// the kernel interface index on Linux (netlink), the interface name on macOS (getifaddrs).
#if defined(__linux__)
[[nodiscard]] InterfaceAddresses ResolveInterfaceAddresses(unsigned interface_index) noexcept;
#elif defined(__APPLE__)
[[nodiscard]] InterfaceAddresses ResolveInterfaceAddresses(std::string_view interface) noexcept;
#endif

} // namespace reflector
