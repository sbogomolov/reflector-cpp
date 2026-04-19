#pragma once

#include "reflector/error.h"

#include <array>
#include <cstddef>
#include <expected>
#include <string_view>

namespace reflector {

class MacAddress {
public:
    using ByteArray = std::array<std::byte, 6>;

    constexpr MacAddress() noexcept = default;
    explicit constexpr MacAddress(ByteArray bytes) noexcept : bytes_{bytes} {}

    [[nodiscard]] static std::expected<MacAddress, Error> FromString(std::string_view mac);

    [[nodiscard]] constexpr bool IsValid() const noexcept {
        for (const auto byte : bytes_) {
            if (byte != std::byte{0}) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] constexpr const ByteArray& Bytes() const noexcept { return bytes_; }

    bool operator==(const MacAddress&) const = default;

private:
    ByteArray bytes_{};
};

} // namespace reflector
