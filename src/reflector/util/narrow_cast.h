#pragma once

namespace reflector {

// Explicit narrowing conversion that is warning-clean on every target. Taking `from` by value makes
// the cast an lvalue-to-prvalue conversion, which GCC's -Wuseless-cast accepts even when `To` and
// `From` share a canonical type (on ILP32/armhf size_t, socklen_t and uint32_t are all unsigned int),
// while it stays a real explicit narrowing on LP64 (where size_t is 64-bit) that silences -Wconversion.
// The caller guarantees the value fits in `To`.
template <typename To, typename From>
[[nodiscard]] constexpr To narrow_cast(From from) noexcept {
    return static_cast<To>(from);
}

} // namespace reflector
