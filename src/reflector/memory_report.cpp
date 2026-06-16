#include "memory_report.h"

#include "logger.h"
#include "platform.h"
#include "util/narrow_cast.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <sys/resource.h>

#if defined(__GLIBC__)
#include <malloc.h>  // mallinfo2 (glibc-only header)
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

// Peak resident set size in KiB via getrusage -- cross-platform (no /proc needed): Linux and FreeBSD
// report ru_maxrss in KiB, macOS in bytes. Same high-water value as /proc VmHWM on Linux, with one path.
size_t PeakRssKib() noexcept {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0;
    }
#if defined(__APPLE__)
    return narrow_cast<size_t>(usage.ru_maxrss) / 1024;  // bytes -> KiB
#else
    return narrow_cast<size_t>(usage.ru_maxrss);         // already KiB
#endif
}

#if defined(__linux__)

// A "<key>: <N> kB" value from /proc/self/status, in KiB; nullopt if absent/unreadable. Used for VmRSS
// (current resident set); the peak comes from getrusage instead, which is cross-platform.
std::optional<size_t> StatusValueKib(const char* key) noexcept {
    std::FILE* file = std::fopen("/proc/self/status", "r");
    if (file == nullptr) {
        return std::nullopt;
    }
    const size_t key_len = std::strlen(key);
    char line[256];
    std::optional<size_t> value;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        if (std::strncmp(line, key, key_len) == 0 && line[key_len] == ':') {
            unsigned long kib = 0;
            if (std::sscanf(line + key_len + 1, " %lu kB", &kib) == 1) {
                value = narrow_cast<size_t>(kib);
            }
            break;
        }
    }
    std::fclose(file);
    return value;
}

// A single unsigned integer (bytes) from a one-value cgroup file (memory.current / memory.peak).
std::optional<size_t> ReadByteCount(const char* path) noexcept {
    std::FILE* file = std::fopen(path, "r");
    if (file == nullptr) {
        return std::nullopt;
    }
    unsigned long long bytes = 0;
    const int matched = std::fscanf(file, "%llu", &bytes);
    std::fclose(file);
    return matched == 1 ? std::optional<size_t>{narrow_cast<size_t>(bytes)} : std::nullopt;
}

// The container's cgroup v2 memory accounting -- the figure RouterOS (and the OOM killer) sees: process
// RSS plus page cache plus kernel/socket memory. The fields are the mutually-exclusive top-level
// categories of memory.current; the remainder ("other", computed at log time) is per-cpu charge cache,
// zswap, and anything else not broken out here. Absent if not cgroup v2 / not mounted in the container.
struct CgroupMemory {
    bool available = false;
    size_t current = 0;          // bytes
    std::optional<size_t> peak;  // bytes; memory.peak needs kernel >= 5.19
    size_t anon = 0;             // heap/stack
    size_t file = 0;             // page cache (includes shmem)
    size_t sock = 0;             // socket buffers
    size_t slab = 0;             // kernel slab (reclaimable + unreclaimable)
    size_t pagetables = 0;       // page tables
    size_t kernel_stack = 0;     // kernel stacks
    size_t percpu = 0;           // per-cpu allocations
    size_t vmalloc = 0;          // kernel vmalloc
    size_t shmem = 0;            // tmpfs/shared memory (a subset of file)
    size_t sec_pagetables = 0;   // secondary page tables (KVM/IOMMU)
    size_t zswap = 0;            // compressed swap pool
};

// Fills `out` with the process's own cgroup v2 directory under /sys/fs/cgroup, derived from
// /proc/self/cgroup ("0::<path>"). Inside a container the path is the namespaced root "/" (so the mount
// root); on a bare host it's the service/session sub-cgroup. false if not cgroup v2 / unreadable.
bool CgroupDir(char* out, size_t out_size) noexcept {
    std::FILE* file = std::fopen("/proc/self/cgroup", "r");
    if (file == nullptr) {
        return false;
    }
    char line[512];
    bool found = false;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        if (std::strncmp(line, "0::", 3) == 0) {  // the cgroup v2 unified-hierarchy entry
            char* path = line + 3;
            path[std::strcspn(path, "\n")] = '\0';  // drop the trailing newline
            // The namespaced root is "/", which maps to the mount root; otherwise append the sub-path.
            std::snprintf(out, out_size, "/sys/fs/cgroup%s", std::strcmp(path, "/") == 0 ? "" : path);
            found = true;
            break;
        }
    }
    std::fclose(file);
    return found;
}

CgroupMemory ReadCgroupMemory() noexcept {
    CgroupMemory mem;
    char dir[640];  // "/sys/fs/cgroup" + the <=508-char path from /proc/self/cgroup, with headroom
    if (!CgroupDir(dir, sizeof(dir))) {
        return mem;  // not cgroup v2, or /proc/self/cgroup unreadable
    }
    char path[700];
    std::snprintf(path, sizeof(path), "%s/memory.current", dir);
    const auto current = ReadByteCount(path);
    if (!current) {
        return mem;  // memory controller not enabled for this cgroup (e.g. the root cgroup)
    }
    mem.available = true;
    mem.current = *current;
    std::snprintf(path, sizeof(path), "%s/memory.peak", dir);
    mem.peak = ReadByteCount(path);

    std::snprintf(path, sizeof(path), "%s/memory.stat", dir);
    std::FILE* file = std::fopen(path, "r");
    if (file != nullptr) {
        size_t slab_reclaimable = 0;
        size_t slab_unreclaimable = 0;
        char key[64];
        unsigned long long value = 0;
        while (std::fscanf(file, "%63s %llu", key, &value) == 2) {
            const size_t v = narrow_cast<size_t>(value);
            if (std::strcmp(key, "anon") == 0) {
                mem.anon = v;
            } else if (std::strcmp(key, "file") == 0) {
                mem.file = v;
            } else if (std::strcmp(key, "sock") == 0) {
                mem.sock = v;
            } else if (std::strcmp(key, "slab_reclaimable") == 0) {
                slab_reclaimable = v;
            } else if (std::strcmp(key, "slab_unreclaimable") == 0) {
                slab_unreclaimable = v;
            } else if (std::strcmp(key, "pagetables") == 0) {
                mem.pagetables = v;
            } else if (std::strcmp(key, "kernel_stack") == 0) {
                mem.kernel_stack = v;
            } else if (std::strcmp(key, "percpu") == 0) {
                mem.percpu = v;
            } else if (std::strcmp(key, "vmalloc") == 0) {
                mem.vmalloc = v;
            } else if (std::strcmp(key, "shmem") == 0) {
                mem.shmem = v;
            } else if (std::strcmp(key, "sec_pagetables") == 0) {
                mem.sec_pagetables = v;
            } else if (std::strcmp(key, "zswap") == 0) {
                mem.zswap = v;
            }
        }
        mem.slab = slab_reclaimable + slab_unreclaimable;
        std::fclose(file);
    }
    return mem;
}

void LogCgroupMemory() {
    const auto cg = ReadCgroupMemory();
    if (!cg.available) {
        GetLogger().Info("cgroup memory unavailable (not cgroup v2, or /sys/fs/cgroup not mounted)");
        return;
    }
    const auto kib = [](size_t bytes) { return bytes / 1024; };
    if (cg.peak) {
        GetLogger().Info("cgroup current={} KiB (peak {} KiB)", kib(cg.current), kib(*cg.peak));
    } else {
        GetLogger().Info("cgroup current={} KiB", kib(cg.current));
    }
    // The remainder of current after the named categories (shmem excluded -- it is part of file). With
    // every additive category now broken out, `other` is essentially the per-cpu charge cache + rounding.
    const size_t known = cg.anon + cg.file + cg.sock + cg.slab + cg.pagetables + cg.sec_pagetables
        + cg.kernel_stack + cg.percpu + cg.vmalloc + cg.zswap;
    const size_t other = cg.current > known ? cg.current - known : 0;
    GetLogger().Info(
        "cgroup breakdown (KiB): anon={} file={} sock={} slab={} pagetables={} sec_pagetables={} "
        "kernel_stack={} percpu={} vmalloc={} shmem={} zswap={} other={}",
        kib(cg.anon), kib(cg.file), kib(cg.sock), kib(cg.slab), kib(cg.pagetables), kib(cg.sec_pagetables),
        kib(cg.kernel_stack), kib(cg.percpu), kib(cg.vmalloc), kib(cg.shmem), kib(cg.zswap), kib(other));
}

#endif  // __linux__

} // namespace

void LogMemoryReport() {
    const size_t peak = PeakRssKib();  // getrusage -- cross-platform high-water
#if defined(__linux__)
    const size_t rss = StatusValueKib("VmRSS").value_or(0);
#if defined(REFLECTOR_HAVE_MALLINFO2)
    const auto info = mallinfo2();
    GetLogger().Info(
        "rss={} KiB, peak={} KiB; heap in_use={} KiB, free_retained={} KiB, arena={} KiB, mmap={} KiB",
        rss, peak, info.uordblks / 1024, info.fordblks / 1024, info.arena / 1024, info.hblkhd / 1024);
#else
    GetLogger().Info("rss={} KiB, peak={} KiB (heap arena stats need glibc >= 2.33)", rss, peak);
#endif
    LogCgroupMemory();
#else
    // Non-Linux (macOS/FreeBSD): no /proc or cgroup; getrusage still gives the peak RSS.
    GetLogger().Info("peak={} KiB (detailed RSS/heap/cgroup stats are glibc/Linux-only)", peak);
#endif
}

} // namespace reflector
