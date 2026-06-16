#include "memory_report.h"

#include "logger.h"
#include "platform.h"

#include <cstddef>
#include <cstdio>

#include <sys/resource.h>
#include <unistd.h>

#if defined(__GLIBC__)
#include <malloc.h>  // mallinfo2
#if __GLIBC_PREREQ(2, 33)
#define REFLECTOR_HAVE_MALLINFO2 1
#endif
#endif

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"MemoryReport"};
    return logger;
}

// Peak resident set size in KiB via getrusage (portable). ru_maxrss is KiB on Linux/FreeBSD but
// bytes on macOS; normalize to KiB. 0 if the call fails.
size_t PeakRssKib() noexcept {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0;
    }
#if defined(__APPLE__)
    return static_cast<size_t>(usage.ru_maxrss) / 1024;  // bytes -> KiB
#else
    return static_cast<size_t>(usage.ru_maxrss);         // already KiB
#endif
}

#if defined(__linux__)
// Current RSS in KiB from /proc/self/statm (field 2 = resident pages). 0 if unavailable.
size_t CurrentRssKib() noexcept {
    std::FILE* file = std::fopen("/proc/self/statm", "re");
    if (file == nullptr) {
        return 0;
    }
    unsigned long total_pages = 0;
    unsigned long resident_pages = 0;
    const int matched = std::fscanf(file, "%lu %lu", &total_pages, &resident_pages);
    std::fclose(file);
    if (matched != 2) {
        return 0;
    }
    const long page_size = sysconf(_SC_PAGESIZE);
    return static_cast<size_t>(resident_pages) * static_cast<size_t>(page_size) / 1024;
}
#endif

} // namespace

void LogMemoryReport() {
#if defined(REFLECTOR_HAVE_MALLINFO2)
    const auto info = mallinfo2();
    GetLogger().Info(
        "rss={} KiB, peak={} KiB; heap in_use={} KiB, free_retained={} KiB, arena={} KiB, mmap={} KiB",
        CurrentRssKib(), PeakRssKib(),
        info.uordblks / 1024, info.fordblks / 1024, info.arena / 1024, info.hblkhd / 1024);
#elif defined(__linux__)
    GetLogger().Info("rss={} KiB, peak={} KiB (heap arena stats need glibc >= 2.33)",
        CurrentRssKib(), PeakRssKib());
#else
    GetLogger().Info("peak={} KiB (detailed heap stats are glibc/Linux-only)", PeakRssKib());
#endif
}

} // namespace reflector
