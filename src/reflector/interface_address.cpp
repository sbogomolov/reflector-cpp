#include "interface_address.h"

#include "error.h"
#include "logger.h"

#include <cstddef>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <span>
#include <sys/socket.h>

#if defined(__linux__)
#include <netpacket/packet.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"InterfaceAddresses"};
    return logger;
}

constexpr size_t MAC_SIZE = MacAddress::ByteArray{}.size();

// True for an IPv6 fe80::/10 link-local address.
bool IsIpv6LinkLocal(const IpAddress& address) noexcept {
    if (!address.IsV6()) {
        return false;
    }
    const auto& bytes = address.Bytes();
    return std::to_integer<uint8_t>(bytes[0]) == 0xfe
        && (std::to_integer<uint8_t>(bytes[1]) & 0xc0) == 0x80;
}

// BSD embeds the scope id in bytes 2-3 of a link-local sin6_addr; clear it so the on-wire
// source is the canonical fe80::<interface-id> rather than fe80:<scope>::<interface-id>.
IpAddress CanonicalizeLinkLocal(const IpAddress& address) noexcept {
    auto bytes = address.Bytes();
    bytes[2] = std::byte{0};
    bytes[3] = std::byte{0};
    return IpAddress::FromV6Bytes(bytes);
}

// The interface's link-layer MAC, or a default (all-zero) MacAddress if it has none.
MacAddress ReadMac(const ifaddrs& ifa) noexcept {
    // Read the MAC straight out of the kernel-provided sockaddr rather than copying the whole
    // (variable-length) sockaddr into a fixed local: on macOS the MAC sits at a name-dependent
    // offset in sdl_data that a long interface name could push past any local sockaddr_dl. Byte
    // access through std::byte* is alignment- and aliasing-safe.
    const auto* bytes = reinterpret_cast<const std::byte*>(ifa.ifa_addr);
#if defined(__linux__)
    // sockaddr_ll is fixed-size: the MAC is in the dedicated sll_addr field, length in sll_halen.
    if (std::to_integer<size_t>(bytes[offsetof(sockaddr_ll, sll_halen)]) != MAC_SIZE) {
        return {};
    }
    return MacAddress::FromBytes(
        std::span<const std::byte, MAC_SIZE>{bytes + offsetof(sockaddr_ll, sll_addr), MAC_SIZE});
#elif defined(__APPLE__)
    // sockaddr_dl packs the interface name then the MAC into sdl_data (LLADDR = sdl_data +
    // sdl_nlen); sa_len is the kernel's true total length, which bounds where the MAC can sit.
    const auto sa_len = static_cast<size_t>(ifa.ifa_addr->sa_len);
    const auto name_len = std::to_integer<size_t>(bytes[offsetof(sockaddr_dl, sdl_nlen)]);
    const auto addr_len = std::to_integer<size_t>(bytes[offsetof(sockaddr_dl, sdl_alen)]);
    const auto mac_offset = offsetof(sockaddr_dl, sdl_data) + name_len;
    if (addr_len != MAC_SIZE || mac_offset + MAC_SIZE > sa_len) {
        return {};
    }
    return MacAddress::FromBytes(std::span<const std::byte, MAC_SIZE>{bytes + mac_offset, MAC_SIZE});
#endif
}

} // namespace

InterfaceAddresses ResolveInterfaceAddresses(std::string_view interface) noexcept {
    InterfaceAddresses result;

    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0) {
        GetLogger().Error("Cannot enumerate interface addresses: {}", Error::FromErrno());
        return result;
    }

    for (const ifaddrs* ifa = head; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || interface != ifa->ifa_name) {
            continue;
        }
        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            if (!result.v4) {
                result.v4 = IpAddress::FromSockaddr(ifa->ifa_addr);
            }
            break;
        case AF_INET6:
            if (!result.v6) {
                if (const auto address = IpAddress::FromSockaddr(ifa->ifa_addr);
                        address && IsIpv6LinkLocal(*address)) {
                    result.v6 = CanonicalizeLinkLocal(*address);
                }
            }
            break;
#if defined(__linux__)
        case AF_PACKET:
            result.mac = ReadMac(*ifa);
            break;
#elif defined(__APPLE__)
        case AF_LINK:
            result.mac = ReadMac(*ifa);
            break;
#endif
        default:
            break;
        }
    }

    freeifaddrs(head);

    GetLogger().Debug("Resolved interface \"{}\": MAC {}, IPv4 {}, IPv6 {}", interface, result.mac,
        result.v4 ? result.v4->ToString() : "none", result.v6 ? result.v6->ToString() : "none");
    return result;
}

} // namespace reflector
