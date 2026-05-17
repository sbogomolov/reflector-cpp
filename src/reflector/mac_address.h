#pragma once

#include "reflector/error.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <string_view>

namespace reflector {

class MacAddress {
public:
    using ByteArray = std::array<std::byte, 6>;

    constexpr MacAddress() noexcept = default;
    explicit constexpr MacAddress(ByteArray bytes) noexcept : bytes_{bytes} {}

    [[nodiscard]] static std::expected<MacAddress, Error> FromString(std::string_view mac);

    [[nodiscard]] constexpr const ByteArray& Bytes() const noexcept { return bytes_; }

    bool operator==(const MacAddress&) const = default;

private:
    ByteArray bytes_{};
};

} // namespace reflector

template <>
struct std::formatter<reflector::MacAddress, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for MacAddress");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::MacAddress& mac, FmtContext& ctx) const {
        const auto& bytes = mac.Bytes();
        return std::format_to(ctx.out(), "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            static_cast<uint8_t>(bytes[0]), static_cast<uint8_t>(bytes[1]),
            static_cast<uint8_t>(bytes[2]), static_cast<uint8_t>(bytes[3]),
            static_cast<uint8_t>(bytes[4]), static_cast<uint8_t>(bytes[5]));
    }
};
