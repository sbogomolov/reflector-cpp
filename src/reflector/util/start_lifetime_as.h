#pragma once

#include <cstring>
#include <memory>
#include <new>
#include <type_traits>
#include <version>

namespace reflector {

// Begins the lifetime of a T in the storage at `p`, preserving the bytes already there (e.g. a struct
// the kernel filled via recvfrom) and returning a pointer to it — so reading through that pointer is
// well-defined, unlike a reinterpret_cast, which reads an object that was never created there.
//
// Delegates to C++23 std::start_lifetime_as where the standard library ships it; until then
// (libstdc++ < 15, the project's AppleClang) it falls back to the canonical memmove + launder form:
// memmove implicitly creates the implicit-lifetime object (P0593) and the self-copy keeps the bytes.
// is_trivially_copyable_v is the exact precondition — it implies implicit-lifetime (so std accepts it
// too) and is precisely what memmove can reconstitute.
template <typename T>
    requires std::is_trivially_copyable_v<T>
[[nodiscard]] T* start_lifetime_as(void* p) noexcept {
#ifdef __cpp_lib_start_lifetime_as
    return std::start_lifetime_as<T>(p);
#else
    return std::launder(static_cast<T*>(std::memmove(p, p, sizeof(T))));
#endif
}

} // namespace reflector
