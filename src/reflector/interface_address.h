#pragma once

#include "ip_address.h"
#include "mac_address.h"
#include "platform.h"

#include <optional>
#include <span>
#include <string_view>
#include <sys/socket.h>

namespace reflector {

// The source addresses a network interface can originate packets from, as resolved from
// getifaddrs. Used by the raw egress path, which (unlike a kernel UDP socket) must supply the
// source IP and MAC itself when building frames.
struct InterfaceAddresses {
    MacAddress mac{};               // all-zero when the interface has none (e.g. loopback)
    std::optional<IpAddress> v4{};  // the {} keep partial designated inits warning-free under GCC
    std::optional<IpAddress> v6{};  // best-ranked IPv6 source (prefers link-local fe80::, else ULA/GUA), if any
    // Best-ranked non-link-local IPv6 source (ULA > GUA), if any: the source for site/global-scoped
    // destinations (e.g. the SSDP ff05::c group), which must not originate from fe80::.
    std::optional<IpAddress> v6_routable{};
};

namespace detail {

// Folds an interface's usable candidate addresses into `result`: the first IPv4, and the
// best-ranked IPv6 (link-local > ULA > GUA > other). Leaves result.mac untouched — the resolver
// sets that separately. Split out from the platform resolvers so the preference policy is testable
// without a real interface that happens to carry the right address mix.
void SelectSourceAddresses(std::span<const IpAddress> candidates, InterfaceAddresses& result) noexcept;

#if !defined(__linux__)
// The BSD getifaddrs resolver's pure helpers, split out for unit testing (the resolver itself needs
// a real interface). `link_addr` is an AF_LINK sockaddr (a sockaddr_dl).

// The interface's link-layer MAC read from an AF_LINK sockaddr_dl, or all-zero if it carries none
// (addr_len != 6) or the address would run past the sockaddr's sa_len. Reads by byte offset — the
// MAC sits at a name-length-dependent offset a long interface name could push past a fixed local.
[[nodiscard]] MacAddress MacFromLinkSockaddr(const sockaddr& link_addr) noexcept;

// Whether the IN6_IFF_* flags (from SIOCGIFAFLAG_IN6) mark the address a usable source — not
// tentative, duplicated, detached, deprecated, or anycast.
[[nodiscard]] bool Ipv6SourceFlagsUsable(int flags6) noexcept;

// A KAME link-local sin6_addr with the embedded scope id (interface index in bytes 2-3) cleared to
// the canonical fe80::<id> on-wire form. macOS/FreeBSD only — Linux netlink already yields canonical
// addresses, so the same clearing there could corrupt a non-conforming one.
[[nodiscard]] IpAddress CanonicalizeLinkLocalV6(const IpAddress& address) noexcept;
#endif

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
#else
[[nodiscard]] InterfaceAddresses ResolveInterfaceAddresses(std::string_view interface) noexcept;
#endif

} // namespace reflector
