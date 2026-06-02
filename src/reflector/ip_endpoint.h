#pragma once

#include "reflector/ip_address.h"

#include <cstdint>
#include <cstring>
#include <format>
#include <functional>
#include <optional>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace reflector {

// An IP address + port — the endpoint a TCP socket binds, connects, or accepts on. Owns the
// family-aware sockaddr conversion (delegating to IpAddress) so callers never branch on address family.
struct IpEndpoint {
    IpAddress addr;
    uint16_t port = 0;

    [[nodiscard]] bool operator==(const IpEndpoint&) const noexcept = default;
    [[nodiscard]] auto operator<=>(const IpEndpoint&) const noexcept = default;

    // Fills `storage` (sockaddr_in / sockaddr_in6) and returns the used length, for bind/connect.
    // `scope_id` populates sin6_scope_id for a link-scoped IPv6 endpoint; ignored for IPv4.
    socklen_t ToSockaddr(sockaddr_storage& storage, unsigned scope_id = 0) const noexcept {
        return addr.ToSockaddr(storage, port, scope_id);
    }

    // Reads the address + port back from a sockaddr (accept()/getsockname()); nullopt on an
    // unsupported family.
    [[nodiscard]] static std::optional<IpEndpoint> FromSockaddr(const sockaddr* address) noexcept {
        const auto address_ip = IpAddress::FromSockaddr(address);
        if (!address_ip) {
            return std::nullopt;
        }
        uint16_t port;
        if (address->sa_family == AF_INET) {
            sockaddr_in v4{};  // memcpy (not an aligned cast) — `address` may be under-aligned for sockaddr_in
            std::memcpy(&v4, address, sizeof(v4));
            port = ntohs(v4.sin_port);
        } else if (address->sa_family == AF_INET6) {
            sockaddr_in6 v6{};
            std::memcpy(&v6, address, sizeof(v6));
            port = ntohs(v6.sin6_port);
        } else {
            return std::nullopt;
        }
        return IpEndpoint{*address_ip, port};
    }
};

} // namespace reflector

template <>
struct std::hash<reflector::IpEndpoint> {
    size_t operator()(const reflector::IpEndpoint& endpoint) const noexcept {
        return std::hash<reflector::IpAddress>{}(endpoint.addr) * 31 + endpoint.port;
    }
};

template <>
struct std::formatter<reflector::IpEndpoint, char> {
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for IpEndpoint");
        }
        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::IpEndpoint& endpoint, FmtContext& ctx) const {
        // IpAddress already brackets IPv6, so this yields "127.0.0.1:80" / "[::1]:80" — a URL authority.
        return std::format_to(ctx.out(), "{}:{}", endpoint.addr, endpoint.port);
    }
};
