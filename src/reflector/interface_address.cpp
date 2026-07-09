#include "interface_address.h"

#include "error.h"
#include "logger.h"
#include "platform.h"
#include "util/start_lifetime_as.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else
#include <net/if_dl.h>
#include <netinet6/in6_var.h>
#endif

namespace {

using namespace reflector;

Logger& GetLogger() noexcept {
    static Logger logger{"InterfaceAddresses"};
    return logger;
}

constexpr size_t MAC_SIZE = MacAddress::ByteArray{}.size();

// Preference rank of an IPv6 source address: lower is better. We prefer a link-local source
// because most of what we send is link-local-scoped multicast (ff02::), then ULA, then GUA (which
// serve the site/global-scoped SSDP ff05:: path), and finally anything else (loopback ::1, etc.)
// as a last resort — so an interface that has only an unusual address still resolves something
// rather than nothing.
int Ipv6Rank(const IpAddress& address) noexcept {
    if (address.IsLinkLocal()) {
        return 0;
    }
    if (address.IsUniqueLocal()) {
        return 1;
    }
    if (address.IsGlobalUnicast()) {
        return 2;
    }
    return 3;
}

// Folds a usable interface address into the result: the first IPv4 wins; the best-ranked IPv6
// (see Ipv6Rank) wins, with the current pick's rank read back from result.v6. Non-link-local
// candidates additionally compete for v6_routable (so ULA > GUA > other), the source for
// site/global-scoped destinations.
void Consider(InterfaceAddresses& result, const IpAddress& address) noexcept {
    if (address.IsV4()) {
        if (!result.v4) {
            result.v4 = address;
        }
        return;
    }

    if (!result.v6 || Ipv6Rank(address) < Ipv6Rank(*result.v6)) {
        result.v6 = address;
    }
    if (!address.IsLinkLocal()
            && (!result.v6_routable || Ipv6Rank(address) < Ipv6Rank(*result.v6_routable))) {
        result.v6_routable = address;
    }
}

#if defined(__linux__)

bool IsUsable(uint32_t ifa_flags) noexcept {
    return (ifa_flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED | IFA_F_DADFAILED)) == 0;
}

// The kernel netlink macros (NLMSG_*, RTA_*, IFLA_RTA, IFA_RTA) use C-style casts and
// byte-wise pointer arithmetic that the project's strict warning set rejects; the alignment is
// sound (the receive buffer is max-aligned and every message/attribute is NLMSG_ALIGN/RTA_ALIGN
// padded), so scope the suppression to the netlink code rather than hand-reimplementing the
// macros. Every struct the walks read is start_lifetime_as'd first: the macros only compute
// addresses and read fields of the already-blessed current struct, so blessing each derived
// pointer before its first dereference keeps all accesses on live objects.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

// Sends a dump request (RTM_GETLINK or RTM_GETADDR) over `fd` and feeds each reply header to
// `handle` until NLMSG_DONE. Dumps everything and lets the handler filter by interface index —
// simpler and uniformly terminated than a single-interface request, and the set is tiny.
template <typename Handler>
bool NetlinkDump(int fd, uint16_t request_type, uint32_t seq, Handler&& handle) noexcept {
    struct {
        nlmsghdr header;
        union {
            ifinfomsg link;
            ifaddrmsg addr;
        } body;
    } request{};
    const size_t body_size =
        request_type == RTM_GETLINK ? sizeof(request.body.link) : sizeof(request.body.addr);
    request.header.nlmsg_len = NLMSG_LENGTH(body_size);
    request.header.nlmsg_type = request_type;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = seq;
    // body left zero: ifi_family / ifa_family = AF_UNSPEC dumps every family.

    if (send(fd, &request, request.header.nlmsg_len, 0) < 0) {
        GetLogger().Error("Cannot send netlink dump request: {}", Error::FromErrno());
        return false;
    }

    // A single netlink message can exceed any fixed size — RTM_GETLINK replies carry large
    // stats / SR-IOV VF attribute blocks on some NICs, and the kernel can't split one message
    // across datagrams — so a plain recv() into a fixed buffer would silently truncate it.
    // Peek each datagram's true length with MSG_TRUNC and grow before the real read. Starting
    // at one page covers the common case in a single pass. operator new over-aligns the
    // storage, so the nlmsghdr cast below is sound.
    std::vector<std::byte> buffer(8192);
    while (true) {
        const auto needed = recv(fd, buffer.data(), buffer.size(), MSG_PEEK | MSG_TRUNC);
        if (needed < 0) {
            GetLogger().Error("Cannot read netlink dump reply: {}", Error::FromErrno());
            return false;
        }
        if (static_cast<size_t>(needed) > buffer.size()) {
            buffer.resize(static_cast<size_t>(needed));
        }

        sockaddr_nl src{};
        socklen_t addrlen = sizeof(src);
        const auto received = recvfrom(fd, buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&src), &addrlen);
        if (received < 0) {
            GetLogger().Error("Cannot read netlink dump reply: {}", Error::FromErrno());
            return false;
        }
        // Only the kernel (nl_pid 0) may answer the dump; a local process could unicast a spoofed
        // reply to inject a bogus address. Discard anything else and read the next datagram.
        if (addrlen < sizeof(src) || src.nl_pid != 0) {
            GetLogger().Debug("Ignoring a netlink dump reply from a non-kernel sender (pid {})", src.nl_pid);
            continue;
        }

        auto* header = start_lifetime_as<nlmsghdr>(buffer.data());
        for (int length = static_cast<int>(received); NLMSG_OK(header, length);
                header = start_lifetime_as<nlmsghdr>(NLMSG_NEXT(header, length))) {
            if (header->nlmsg_seq != seq) {
                continue;
            }
            if (header->nlmsg_type == NLMSG_DONE) {
                return true;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                // nlmsgerr.error is a negative errno (0 is an ACK, not a failure).
                const auto* error = start_lifetime_as<nlmsgerr>(NLMSG_DATA(header));
                if (error->error != 0) {
                    GetLogger().Error("Netlink dump returned an error: {}", Error::FromErrno(-error->error));
                    return false;
                }
                return true;
            }
            handle(header);
        }
    }
}

void ResolveViaNetlink(unsigned index, InterfaceAddresses& result) noexcept {
    const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        GetLogger().Error("Cannot open netlink socket: {}", Error::FromErrno());
        return;
    }

    NetlinkDump(fd, RTM_GETLINK, 1, [&](nlmsghdr* header) {
        const auto* link = start_lifetime_as<ifinfomsg>(NLMSG_DATA(header));
        if (static_cast<unsigned>(link->ifi_index) != index) {
            return;
        }
        int length = IFLA_PAYLOAD(header);
        for (auto* attr = start_lifetime_as<rtattr>(IFLA_RTA(link)); RTA_OK(attr, length);
                attr = start_lifetime_as<rtattr>(RTA_NEXT(attr, length))) {
            if (attr->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(attr) == MAC_SIZE) {
                const auto* mac = static_cast<const std::byte*>(RTA_DATA(attr));
                result.mac = MacAddress::FromBytes(std::span<const std::byte, MAC_SIZE>{mac, MAC_SIZE});
                break;  // exactly one IFLA_ADDRESS per link message
            }
        }
    });

    std::vector<IpAddress> candidates;
    NetlinkDump(fd, RTM_GETADDR, 2, [&](nlmsghdr* header) {
        const auto* addr = start_lifetime_as<ifaddrmsg>(NLMSG_DATA(header));
        if (addr->ifa_index != index) {
            return;
        }
        if (addr->ifa_family != AF_INET && addr->ifa_family != AF_INET6) {
            return;
        }

        uint32_t flags = addr->ifa_flags;
        const std::byte* address_attr = nullptr;
        const std::byte* local_attr = nullptr;
        int length = IFA_PAYLOAD(header);
        for (auto* attr = start_lifetime_as<rtattr>(IFA_RTA(addr)); RTA_OK(attr, length);
                attr = start_lifetime_as<rtattr>(RTA_NEXT(attr, length))) {
            switch (attr->rta_type) {
            case IFA_ADDRESS:
                address_attr = static_cast<const std::byte*>(RTA_DATA(attr));
                break;
            case IFA_LOCAL:
                local_attr = static_cast<const std::byte*>(RTA_DATA(attr));
                break;
            case IFA_FLAGS:
                flags = *start_lifetime_as<uint32_t>(RTA_DATA(attr));
                break;
            default:
                break;
            }
        }
        if (!IsUsable(flags)) {
            return;
        }

        // IFA_LOCAL is the interface's own address; IFA_ADDRESS is the peer on point-to-point
        // links and the address itself elsewhere. Prefer IFA_LOCAL when present.
        const std::byte* chosen = local_attr != nullptr ? local_attr : address_attr;
        if (chosen == nullptr) {
            return;
        }
        if (addr->ifa_family == AF_INET) {
            candidates.push_back(IpAddress::FromV4Bytes(std::span<const std::byte, 4>{chosen, 4}));
        } else {
            candidates.push_back(IpAddress::FromV6Bytes(std::span<const std::byte, 16>{chosen, 16}));
        }
    });

    close(fd);

    detail::SelectSourceAddresses(candidates, result);
}

#pragma GCC diagnostic pop

#else

// True only if the kernel confirms the IPv6 address is a valid source. Queried via SIOCGIFAFLAG_IN6
// since getifaddrs doesn't surface per-address flags; the usable/unusable decision itself is
// detail::Ipv6SourceFlagsUsable. If the ioctl fails — most likely because the address was removed
// between enumeration and now — we can't confirm it's usable, so we skip it rather than risk a
// tentative or stale source.
bool IsUsableIpv6(int inet6_fd, const char* interface, const sockaddr_in6& sin6) noexcept {
    in6_ifreq request{};
    std::strncpy(request.ifr_name, interface, sizeof(request.ifr_name) - 1);
    request.ifr_ifru.ifru_addr = sin6;
    if (ioctl(inet6_fd, SIOCGIFAFLAG_IN6, &request) != 0) {
        GetLogger().Warning("Cannot query IPv6 address flags on interface \"{}\": {}", interface, Error::FromErrno());
        return false;
    }
    return detail::Ipv6SourceFlagsUsable(request.ifr_ifru.ifru_flags6);
}

void ResolveViaGetifaddrs(std::string_view interface, InterfaceAddresses& result) noexcept {
    // Unbound datagram socket for the per-address SIOCGIFAFLAG_IN6 flag queries. On a host with
    // IPv6 addresses to enumerate this effectively always succeeds; if it can't be opened we
    // can't verify any IPv6 source, so fail early rather than guess.
    const int inet6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (inet6_fd < 0) {
        GetLogger().Error("Cannot open IPv6 socket to query address flags: {}", Error::FromErrno());
        return;
    }

    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0) {
        GetLogger().Error("Cannot enumerate interface addresses: {}", Error::FromErrno());
        close(inet6_fd);
        return;
    }

    std::vector<IpAddress> candidates;
    for (const ifaddrs* ifa = head; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || interface != ifa->ifa_name) {
            continue;
        }
        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            if (const auto address = IpAddress::FromSockaddr(ifa->ifa_addr); address) {
                candidates.push_back(*address);
            }
            break;
        case AF_INET6: {
            // Copy rather than cast-and-read: getifaddrs owns the storage and FromSockaddr below
            // still reads it as a sockaddr, so beginning a sockaddr_in6's lifetime over it would
            // just move the aliasing problem there. The copy is defined either way.
            sockaddr_in6 sin6{};
            std::memcpy(&sin6, ifa->ifa_addr, sizeof(sin6));
            if (!IsUsableIpv6(inet6_fd, ifa->ifa_name, sin6)) {
                break;
            }
            if (auto address = IpAddress::FromSockaddr(ifa->ifa_addr); address) {
                if (address->IsLinkLocal()) {
                    address = detail::CanonicalizeLinkLocalV6(*address);
                }
                candidates.push_back(*address);
            }
            break;
        }
        case AF_LINK:
            result.mac = detail::MacFromLinkSockaddr(*ifa->ifa_addr);
            break;
        default:
            break;
        }
    }

    close(inet6_fd);
    freeifaddrs(head);

    detail::SelectSourceAddresses(candidates, result);
}

#endif

} // namespace

namespace reflector {

namespace detail {

void SelectSourceAddresses(std::span<const IpAddress> candidates, InterfaceAddresses& result) noexcept {
    for (const auto& address : candidates) {
        Consider(result, address);
    }
}

#if !defined(__linux__)

// Reads straight out of the kernel-provided sockaddr rather than copying the whole (variable-length)
// sockaddr into a fixed local: the MAC sits at a name-length-dependent offset in sdl_data that a long
// interface name could push past any local sockaddr_dl. Byte access through std::byte* is alignment-
// and aliasing-safe.
MacAddress MacFromLinkSockaddr(const sockaddr& link_addr) noexcept {
    const auto* bytes = reinterpret_cast<const std::byte*>(&link_addr);
    const auto sa_len = static_cast<size_t>(link_addr.sa_len);
    const auto name_len = std::to_integer<size_t>(bytes[offsetof(sockaddr_dl, sdl_nlen)]);
    const auto addr_len = std::to_integer<size_t>(bytes[offsetof(sockaddr_dl, sdl_alen)]);
    const auto mac_offset = offsetof(sockaddr_dl, sdl_data) + name_len;
    if (addr_len != MAC_SIZE || mac_offset + MAC_SIZE > sa_len) {
        return {};
    }
    return MacAddress::FromBytes(std::span<const std::byte, MAC_SIZE>{bytes + mac_offset, MAC_SIZE});
}

bool Ipv6SourceFlagsUsable(int flags6) noexcept {
    constexpr int unusable = IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED | IN6_IFF_DETACHED
        | IN6_IFF_DEPRECATED | IN6_IFF_ANYCAST;
    return (flags6 & unusable) == 0;
}

IpAddress CanonicalizeLinkLocalV6(const IpAddress& address) noexcept {
    auto bytes = address.Bytes();
    bytes[2] = std::byte{0};
    bytes[3] = std::byte{0};
    return IpAddress::FromV6Bytes(bytes);
}

#endif

} // namespace detail

#if defined(__linux__)

InterfaceAddresses ResolveInterfaceAddresses(unsigned interface_index) noexcept {
    InterfaceAddresses result;
    ResolveViaNetlink(interface_index, result);
    return result;
}

#else

InterfaceAddresses ResolveInterfaceAddresses(std::string_view interface) noexcept {
    InterfaceAddresses result;
    ResolveViaGetifaddrs(interface, result);
    return result;
}

#endif

} // namespace reflector
