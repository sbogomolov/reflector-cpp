#pragma once

#include <cstddef>

// Counting rides the sanitizer's malloc hooks, so it exists only in sanitized builds. Guard tests
// with REFLECTOR_HAS_ALLOCATION_COUNTER; the Debug gate always defines it.
#if defined(__SANITIZE_ADDRESS__)
#define REFLECTOR_HAS_ALLOCATION_COUNTER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define REFLECTOR_HAS_ALLOCATION_COUNTER 1
#endif
#endif

#if defined(REFLECTOR_HAS_ALLOCATION_COUNTER)

namespace reflector {

// Counts every allocation made while it is alive, so a test can assert that a path stays off the
// heap. Counting each malloc rather than watching allocated bytes is what catches a transient
// allocation — a std::string built and destroyed inside the window nets to zero bytes but is
// exactly the thing worth failing on.
//
// Replacing operator new would have to cover every nothrow and aligned overload to avoid
// mismatching the sanitizer's own, so this hooks the sanitizer's allocator instead. Single
// threaded, one live counter at a time.
class ScopedAllocationCounter {
public:
    ScopedAllocationCounter() noexcept;
    ~ScopedAllocationCounter() noexcept;

    ScopedAllocationCounter(const ScopedAllocationCounter&) = delete;
    ScopedAllocationCounter& operator=(const ScopedAllocationCounter&) = delete;

    [[nodiscard]] size_t Count() const noexcept;
};

} // namespace reflector

#endif  // REFLECTOR_HAS_ALLOCATION_COUNTER
