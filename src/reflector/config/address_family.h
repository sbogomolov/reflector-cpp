#pragma once

#include <cstdint>
#include <format>
#include <utility>

namespace reflector {

enum class AddressFamily : uint8_t {
    Default,
    Dual,
    IPv4,
    IPv6,
};

// Which IP versions a reflector handles. "Uses" = will attempt the family; "Requires" = startup
// fails if it can't be initialized. Default attempts both but only requires IPv4 (IPv6 is
// best-effort); Dual requires both; IPv4 / IPv6 use only that one.
[[nodiscard]] constexpr bool UsesIPv4(AddressFamily family) noexcept {
    return family != AddressFamily::IPv6;
}
[[nodiscard]] constexpr bool UsesIPv6(AddressFamily family) noexcept {
    return family != AddressFamily::IPv4;
}
[[nodiscard]] constexpr bool RequiresIPv4(AddressFamily family) noexcept {
    return family == AddressFamily::Default || family == AddressFamily::Dual
        || family == AddressFamily::IPv4;
}
[[nodiscard]] constexpr bool RequiresIPv6(AddressFamily family) noexcept {
    return family == AddressFamily::Dual || family == AddressFamily::IPv6;
}

} // namespace reflector

template <>
struct std::formatter<reflector::AddressFamily, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for AddressFamily");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(reflector::AddressFamily address_family, FmtContext& ctx) const {
        switch (address_family) {
        using enum reflector::AddressFamily;
        case Default: return std::format_to(ctx.out(), "default");
        case Dual: return std::format_to(ctx.out(), "dual");
        case IPv4: return std::format_to(ctx.out(), "ipv4");
        case IPv6: return std::format_to(ctx.out(), "ipv6");
        }

        std::unreachable();
    }
};
