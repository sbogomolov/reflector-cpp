#include "ip_address.h"

#include "reflector/error.h"
#include "reflector/logger.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <ostream>
#include <utility>

namespace reflector {

// IpAddress stores 16 network-order bytes; the platform address structs that ToSockaddr and
// FromSockaddr memcpy to/from must fit within that (in_addr is 4 bytes, in6_addr 16).
static_assert(sizeof(in_addr) <= sizeof(IpAddress::ByteArray));
static_assert(sizeof(in6_addr) <= sizeof(IpAddress::ByteArray));

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"IpAddress"};
    return logger;
}

} // namespace

std::ostream& operator<<(std::ostream& os, IpAddress::Family family) {
    return os << std::format("{}", family);
}

IpAddress IpAddress::BroadcastV4() noexcept {
    return FromV4Bytes(255, 255, 255, 255);
}

IpAddress IpAddress::AllNodesLinkLocalV6() noexcept {
    ByteArray bytes{};
    bytes[0] = std::byte{0xff};
    bytes[1] = std::byte{0x02};
    bytes[15] = std::byte{0x01};
    return IpAddress{Family::V6, bytes};
}

IpAddress IpAddress::MdnsGroupV4() noexcept {
    return FromV4Bytes(224, 0, 0, 251);
}

IpAddress IpAddress::MdnsGroupV6() noexcept {
    ByteArray bytes{};
    bytes[0] = std::byte{0xff};
    bytes[1] = std::byte{0x02};
    bytes[15] = std::byte{0xfb};
    return IpAddress{Family::V6, bytes};
}

IpAddress IpAddress::MdnsGroupFor(Family family) noexcept {
    return family == Family::V4 ? MdnsGroupV4() : MdnsGroupV6();
}

IpAddress IpAddress::SsdpGroupV4() noexcept {
    return FromV4Bytes(239, 255, 255, 250);
}

IpAddress IpAddress::SsdpGroupV6LinkLocal() noexcept {
    ByteArray bytes{};
    bytes[0] = std::byte{0xff};
    bytes[1] = std::byte{0x02};
    bytes[15] = std::byte{0x0c};
    return IpAddress{Family::V6, bytes};
}

IpAddress IpAddress::SsdpGroupV6SiteLocal() noexcept {
    ByteArray bytes{};
    bytes[0] = std::byte{0xff};
    bytes[1] = std::byte{0x05};
    bytes[15] = std::byte{0x0c};
    return IpAddress{Family::V6, bytes};
}

std::vector<IpAddress> IpAddress::SsdpGroupsFor(Family family) {
    if (family == Family::V4) {
        return {SsdpGroupV4()};
    }
    return {SsdpGroupV6LinkLocal(), SsdpGroupV6SiteLocal()};
}

IpAddress IpAddress::LoopbackV4() noexcept {
    return FromV4Bytes(127, 0, 0, 1);
}

IpAddress IpAddress::LoopbackV6() noexcept {
    ByteArray bytes{};
    bytes[15] = std::byte{0x01};
    return IpAddress{Family::V6, bytes};
}

IpAddress IpAddress::FromV4Bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept {
    ByteArray bytes{};
    bytes[0] = std::byte{a};
    bytes[1] = std::byte{b};
    bytes[2] = std::byte{c};
    bytes[3] = std::byte{d};
    return IpAddress{Family::V4, bytes};
}

IpAddress IpAddress::FromV4Bytes(std::span<const std::byte, 4> bytes) noexcept {
    ByteArray padded{};
    std::memcpy(padded.data(), bytes.data(), bytes.size());
    return IpAddress{Family::V4, padded};
}

IpAddress IpAddress::FromV6Bytes(std::span<const std::byte, 16> bytes) noexcept {
    ByteArray copy{};
    std::memcpy(copy.data(), bytes.data(), bytes.size());
    return IpAddress{Family::V6, copy};
}

std::optional<IpAddress> IpAddress::FromString(const std::string& address) {
    in_addr v4{};
    if (inet_pton(AF_INET, address.c_str(), &v4) == 1) {
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v4, sizeof(v4));
        return IpAddress{Family::V4, bytes};
    }

    in6_addr v6{};
    if (inet_pton(AF_INET6, address.c_str(), &v6) == 1) {
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v6, sizeof(v6));
        return IpAddress{Family::V6, bytes};
    }

    GetLogger().Error("Cannot parse IP address \"{}\"", address);
    return std::nullopt;
}

std::optional<IpAddress> IpAddress::FromSockaddr(const sockaddr* address) noexcept {
    if (address == nullptr) {
        return std::nullopt;
    }

    // Copy into a correctly-aligned local rather than reinterpret_cast the sockaddr*: the
    // pointee is always a sockaddr_storage in callers, so the read is in bounds, and the
    // copy sidesteps the alignment-increasing cast that -Wcast-align rejects.
    if (address->sa_family == AF_INET) {
        sockaddr_in v4{};
        std::memcpy(&v4, address, sizeof(v4));
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v4.sin_addr, sizeof(v4.sin_addr));
        return IpAddress{Family::V4, bytes};
    }

    if (address->sa_family == AF_INET6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, address, sizeof(v6));
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v6.sin6_addr, sizeof(v6.sin6_addr));
        return IpAddress{Family::V6, bytes};
    }

    GetLogger().Error("Cannot convert sockaddr with address family {} to IpAddress",
        static_cast<int>(address->sa_family));
    return std::nullopt;
}

socklen_t IpAddress::ToSockaddr(sockaddr_storage& storage, uint16_t port, unsigned scope_id) const noexcept {
    std::memset(&storage, 0, sizeof(storage));

    switch (family_) {
    using enum Family;
    case V4: {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        std::memcpy(&v4->sin_addr, bytes_.data(), sizeof(v4->sin_addr));
#if defined(__APPLE__)
        // BSD carries the length in the sockaddr. bind/sendto ignore it (they take an explicit
        // addrlen), but APIs that parse an embedded sockaddr — e.g. MCAST_JOIN_GROUP's gr_group —
        // require it, so fill it here rather than at each such call site.
        v4->sin_len = sizeof(sockaddr_in);
#endif
        return sizeof(sockaddr_in);
    }
    case V6: {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_scope_id = scope_id;
        std::memcpy(&v6->sin6_addr, bytes_.data(), sizeof(v6->sin6_addr));
#if defined(__APPLE__)
        v6->sin6_len = sizeof(sockaddr_in6);
#endif
        return sizeof(sockaddr_in6);
    }
    }

    std::unreachable();
}

std::string IpAddress::ToString() const {
    int address_family = 0;
    size_t buffer_size = 0;
    switch (family_) {
    using enum Family;
    case V4:
        address_family = AF_INET;
        buffer_size = INET_ADDRSTRLEN;
        break;
    case V6:
        address_family = AF_INET6;
        buffer_size = INET6_ADDRSTRLEN;
        break;
    }

    std::string result;
    result.resize(buffer_size);
    if (inet_ntop(address_family, bytes_.data(), result.data(),
            static_cast<socklen_t>(result.size())) == nullptr) {
        GetLogger().Error("Cannot convert IP address to string: {}", Error::FromErrno());
        return "<invalid_ip>";
    }

    result.resize(std::char_traits<char>::length(result.c_str()));
    return result;
}

} // namespace reflector
