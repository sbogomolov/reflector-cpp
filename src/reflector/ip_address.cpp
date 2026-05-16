#include "ip_address.h"

#include "reflector/error.h"
#include "reflector/logger.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <ostream>
#include <utility>

namespace reflector {

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

    if (address->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v4->sin_addr, sizeof(v4->sin_addr));
        return IpAddress{Family::V4, bytes};
    }

    if (address->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        ByteArray bytes{};
        std::memcpy(bytes.data(), &v6->sin6_addr, sizeof(v6->sin6_addr));
        return IpAddress{Family::V6, bytes};
    }

    GetLogger().Error("Cannot convert sockaddr with address family {} to IpAddress",
        static_cast<int>(address->sa_family));
    return std::nullopt;
}

socklen_t IpAddress::ToSockaddr(sockaddr_storage& storage, uint16_t port, unsigned scope_id) const noexcept {
    std::memset(&storage, 0, sizeof(storage));

    switch (family_) {
    case Family::V4: {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        std::memcpy(&v4->sin_addr, bytes_.data(), sizeof(v4->sin_addr));
        return sizeof(sockaddr_in);
    }
    case Family::V6: {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_scope_id = scope_id;
        std::memcpy(&v6->sin6_addr, bytes_.data(), sizeof(v6->sin6_addr));
        return sizeof(sockaddr_in6);
    }
    }

    std::unreachable();
}

std::string IpAddress::ToString() const {
    int address_family = 0;
    size_t buffer_size = 0;
    switch (family_) {
    case Family::V4:
        address_family = AF_INET;
        buffer_size = INET_ADDRSTRLEN;
        break;
    case Family::V6:
        address_family = AF_INET6;
        buffer_size = INET6_ADDRSTRLEN;
        break;
    }

    std::string result;
    result.resize(buffer_size);
    if (inet_ntop(address_family, bytes_.data(), result.data(), result.size()) == nullptr) {
        GetLogger().Error("Cannot convert IP address to string: {}", Error::FromErrno());
        return "<invalid_ip>";
    }

    result.resize(std::char_traits<char>::length(result.c_str()));
    return result;
}

} // namespace reflector
