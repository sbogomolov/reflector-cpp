#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <sys/socket.h>

namespace reflector {

class IpAddress {
public:
    enum class Family : uint8_t { V4, V6 };

    // Network-byte-order octets: the first 4 are significant for IPv4, all 16 for IPv6.
    using ByteArray = std::array<std::byte, 16>;

    [[nodiscard]] static constexpr IpAddress AnyV4() noexcept { return IpAddress{Family::V4, {}}; }
    [[nodiscard]] static constexpr IpAddress AnyV6() noexcept { return IpAddress{Family::V6, {}}; }
    [[nodiscard]] static IpAddress BroadcastV4() noexcept;          // 255.255.255.255
    [[nodiscard]] static IpAddress AllNodesLinkLocalV6() noexcept;  // ff02::1
    [[nodiscard]] static IpAddress LoopbackV4() noexcept;           // 127.0.0.1
    [[nodiscard]] static IpAddress LoopbackV6() noexcept;           // ::1
    [[nodiscard]] static IpAddress FromV4Bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept;
    [[nodiscard]] static std::optional<IpAddress> FromString(const std::string& address);
    [[nodiscard]] static std::optional<IpAddress> FromSockaddr(const sockaddr* address) noexcept;

    [[nodiscard]] constexpr Family AddressFamily() const noexcept { return family_; }
    [[nodiscard]] constexpr bool IsV4() const noexcept { return family_ == Family::V4; }
    [[nodiscard]] constexpr bool IsV6() const noexcept { return family_ == Family::V6; }

    // `scope_id` populates sin6_scope_id for IPv6; ignored for IPv4.
    [[nodiscard]] socklen_t ToSockaddr(sockaddr_storage& storage, uint16_t port, unsigned scope_id = 0) const noexcept;

    [[nodiscard]] std::string ToString() const;

    [[nodiscard]] bool operator==(const IpAddress&) const noexcept = default;
    [[nodiscard]] auto operator<=>(const IpAddress&) const noexcept = default;

    [[nodiscard]] constexpr const ByteArray& Bytes() const noexcept { return bytes_; }

private:
    constexpr IpAddress(Family family, const ByteArray& bytes) noexcept
            : family_{family}, bytes_{bytes} {}

    Family family_;
    // Unused octets are zero (the trailing 12 for an IPv4 address).
    ByteArray bytes_;
};

// Visible declaration keeps GoogleTest's ADL printer consistent across translation units.
std::ostream& operator<<(std::ostream& os, IpAddress::Family family);

} // namespace reflector

template <>
struct std::hash<reflector::IpAddress>
{
    size_t operator()(const reflector::IpAddress& address) const noexcept {
        size_t result = std::hash<uint8_t>{}(static_cast<uint8_t>(address.AddressFamily()));
        for (const auto byte : address.Bytes()) {
            result = result * 31 + std::to_integer<size_t>(byte);
        }
        return result;
    }
};

template <>
struct std::formatter<reflector::IpAddress, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for IpAddress");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::IpAddress& address, FmtContext& ctx) const {
        if (address.IsV6()) {
            return std::format_to(ctx.out(), "[{}]", address.ToString());
        }
        return std::format_to(ctx.out(), "{}", address.ToString());
    }
};

template <>
struct std::formatter<reflector::IpAddress::Family, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for IpAddress::Family");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(reflector::IpAddress::Family family, FmtContext& ctx) const {
        return std::format_to(ctx.out(), "{}", family == reflector::IpAddress::Family::V6 ? "IPv6" : "IPv4");
    }
};
