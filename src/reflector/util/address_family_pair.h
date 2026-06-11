#pragma once

#include "reflector/ip_address.h"

#include <utility>

namespace reflector {

// A per-address-family pair of values with compile-time (Get<family>), runtime (Get(family)),
// and named (V4()/V6()) accessors, so per-family state and policy don't need parallel _v4/_v6
// members with hand-rolled dispatch.
template <typename T>
class AddressFamilyPair {
public:
    constexpr AddressFamilyPair() = default;

    template <typename U4, typename U6>
    constexpr AddressFamilyPair(U4&& v4, U6&& v6)
            : v4_{std::forward<U4>(v4)}, v6_{std::forward<U6>(v6)} {}

    template <IpAddress::Family family, typename Self>
    [[nodiscard]] constexpr auto& Get(this Self&& self) noexcept {
        if constexpr (family == IpAddress::Family::V4) {
            return std::forward<Self>(self).v4_;
        } else {
            return std::forward<Self>(self).v6_;
        }
    }

    template <typename Self>
    [[nodiscard]] constexpr auto& Get(this Self&& self, IpAddress::Family family) noexcept {
        return family == IpAddress::Family::V4 ? std::forward<Self>(self).v4_ : std::forward<Self>(self).v6_;
    }

    template <typename Self>
    [[nodiscard]] constexpr auto& V4(this Self&& self) noexcept { return std::forward<Self>(self).v4_; }
    template <typename Self>
    [[nodiscard]] constexpr auto& V6(this Self&& self) noexcept { return std::forward<Self>(self).v6_; }

private:
    T v4_{};
    T v6_{};
};

} // namespace reflector
