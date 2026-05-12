#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace reflector {

class IpAddress {
public:
    constexpr IpAddress() noexcept = default;

    [[nodiscard]] static constexpr IpAddress Any() noexcept { return IpAddress{0}; }
    [[nodiscard]] static constexpr IpAddress Broadcast() noexcept { return IpAddress{0xffffffff}; }
    [[nodiscard]] static IpAddress Loopback() noexcept;
    [[nodiscard]] static IpAddress FromBytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept;
    // `address` must be in network byte order (e.g. struct in_addr::s_addr).
    [[nodiscard]] static constexpr IpAddress FromInAddr(uint32_t address) noexcept { return IpAddress{address}; }
    [[nodiscard]] static std::optional<IpAddress> FromString(std::string_view address);

    // Returns the address in network byte order, suitable for struct in_addr::s_addr.
    [[nodiscard]] constexpr uint32_t InAddr() const noexcept { return address_; }
    [[nodiscard]] constexpr bool IsAny() const noexcept { return address_ == Any().address_; }
    [[nodiscard]] std::string ToString() const;

    auto operator<=>(const IpAddress&) const = default;

private:
    explicit constexpr IpAddress(uint32_t address) noexcept : address_{address} {}

    // Stored in network byte order.
    uint32_t address_ = 0;
};

} // namespace reflector

template <>
struct std::hash<reflector::IpAddress>
{
    size_t operator()(const reflector::IpAddress& address) const noexcept {
        return std::hash<uint32_t>{}(address.InAddr());
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
        return std::format_to(ctx.out(), "{}", address.ToString());
    }
};
