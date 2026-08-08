#include "allocation_counter.h"

#if defined(REFLECTOR_HAS_ALLOCATION_COUNTER)

#include <cassert>

// Declared here rather than included: the symbol is in the common sanitizer runtime that both
// clang and gcc ship, but only clang installs <sanitizer/allocator_interface.h>.
extern "C" int __sanitizer_install_malloc_and_free_hooks(
    void (*malloc_hook)(const volatile void*, size_t), void (*free_hook)(const volatile void*));

namespace {

// Read and written from the allocator hooks, which run outside normal control flow; plain
// zero-initialized globals are ready before any of it.
bool g_counting = false;
size_t g_allocations = 0;

void OnMalloc(const volatile void*, size_t) {
    if (g_counting) {
        ++g_allocations;
    }
}

void OnFree(const volatile void*) {}

} // namespace

namespace reflector {

ScopedAllocationCounter::ScopedAllocationCounter() noexcept {
    // The sanitizer offers no uninstall and only five hook slots, so install once per process and
    // let g_counting bound the window instead.
    static const bool installed = __sanitizer_install_malloc_and_free_hooks(&OnMalloc, &OnFree) != 0;
    assert(installed && "sanitizer malloc hooks unavailable; the count would always read zero");

    g_allocations = 0;
    g_counting = true;
}

ScopedAllocationCounter::~ScopedAllocationCounter() noexcept {
    g_counting = false;
}

size_t ScopedAllocationCounter::Count() const noexcept {
    return g_allocations;
}

} // namespace reflector

#endif  // REFLECTOR_HAS_ALLOCATION_COUNTER
