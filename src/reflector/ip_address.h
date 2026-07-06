#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>
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
    [[nodiscard]] static IpAddress MdnsGroupV4() noexcept;          // 224.0.0.251
    [[nodiscard]] static IpAddress MdnsGroupV6() noexcept;          // ff02::fb
    // The mDNS multicast group for the family (224.0.0.251 / ff02::fb): the destination for
    // both queries and responses on UDP 5353.
    [[nodiscard]] static IpAddress MdnsGroupFor(Family family) noexcept;
    [[nodiscard]] static IpAddress SsdpGroupV4() noexcept;          // 239.255.255.250
    [[nodiscard]] static IpAddress SsdpGroupV6LinkLocal() noexcept; // ff02::c
    [[nodiscard]] static IpAddress SsdpGroupV6SiteLocal() noexcept; // ff05::c
    // The SSDP multicast groups for the family, in join order: the single IPv4 group, or the
    // IPv6 link-local then site-local groups, all served on UDP 1900.
    [[nodiscard]] static std::vector<IpAddress> SsdpGroupsFor(Family family);
    [[nodiscard]] static IpAddress LoopbackV4() noexcept;           // 127.0.0.1
    [[nodiscard]] static IpAddress LoopbackV6() noexcept;           // ::1
    [[nodiscard]] static IpAddress FromV4Bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept;
    [[nodiscard]] static IpAddress FromV4Bytes(std::span<const std::byte, 4> bytes) noexcept;
    [[nodiscard]] static IpAddress FromV6Bytes(std::span<const std::byte, 16> bytes) noexcept;
    [[nodiscard]] static std::optional<IpAddress> FromString(const std::string& address);
    [[nodiscard]] static std::optional<IpAddress> FromSockaddr(const sockaddr* address) noexcept;

    [[nodiscard]] constexpr Family AddressFamily() const noexcept { return family_; }
    [[nodiscard]] constexpr bool IsV4() const noexcept { return family_ == Family::V4; }
    [[nodiscard]] constexpr bool IsV6() const noexcept { return family_ == Family::V6; }

    // Multicast: IPv4 224.0.0.0/4 or IPv6 ff00::/8. (The L2 destination is MulticastMacFor.)
    [[nodiscard]] constexpr bool IsMulticast() const noexcept {
        return IsV4() ? (std::to_integer<uint8_t>(bytes_[0]) & 0xf0) == 0xe0
                      : std::to_integer<uint8_t>(bytes_[0]) == 0xff;
    }
    // The IPv4 limited broadcast 255.255.255.255 (IPv6 has no broadcast, so always false there).
    [[nodiscard]] constexpr bool IsBroadcast() const noexcept {
        return IsV4()
            && std::to_integer<uint8_t>(bytes_[0]) == 0xff && std::to_integer<uint8_t>(bytes_[1]) == 0xff
            && std::to_integer<uint8_t>(bytes_[2]) == 0xff && std::to_integer<uint8_t>(bytes_[3]) == 0xff;
    }

    // IPv6 scope classification (all false for IPv4): link-local fe80::/10, unique-local fc00::/7,
    // global unicast 2000::/3.
    [[nodiscard]] constexpr bool IsLinkLocal() const noexcept {
        return IsV6() && std::to_integer<uint8_t>(bytes_[0]) == 0xfe
            && (std::to_integer<uint8_t>(bytes_[1]) & 0xc0) == 0x80;
    }
    [[nodiscard]] constexpr bool IsUniqueLocal() const noexcept {
        return IsV6() && (std::to_integer<uint8_t>(bytes_[0]) & 0xfe) == 0xfc;
    }
    [[nodiscard]] constexpr bool IsGlobalUnicast() const noexcept {
        return IsV6() && (std::to_integer<uint8_t>(bytes_[0]) & 0xe0) == 0x20;
    }
    // Whether a v6 destination is link-local-scoped — link-local unicast, or a multicast group
    // with scope nibble 2 (ff?2::) — and so wants a link-local source; anything wider wants a
    // routable one. The IsMulticast() check isn't redundant: the scope nibble alone would also
    // match unicasts like fd02:: or 2012::.
    [[nodiscard]] constexpr bool IsLinkLocalScoped() const noexcept {
        return IsLinkLocal()
            || (IsV6() && IsMulticast() && (std::to_integer<uint8_t>(bytes_[1]) & 0x0f) == 0x02);
    }

    // Fills `storage` and returns its used length (for bind/sendto's addrlen). The length may be
    // ignored when it's implied by context — e.g. a fixed-size group_req — so this is not
    // [[nodiscard]]. `scope_id` populates sin6_scope_id for IPv6; ignored for IPv4.
    socklen_t ToSockaddr(sockaddr_storage& storage, uint16_t port, unsigned scope_id = 0) const noexcept;

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
        size_t result = std::hash<uint8_t>{}(std::to_underlying(address.AddressFamily()));
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
