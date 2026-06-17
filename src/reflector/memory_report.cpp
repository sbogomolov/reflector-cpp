#include "memory_report.h"

#include "logger.h"
#include "platform.h"
#include "util/narrow_cast.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
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
// RSS plus page cache plus kernel/socket memory. The memory.stat fields are top-level categories of
// current; each is nullopt when the kernel does not emit that line, so a field this kernel omits ("n/a")
// stays distinct from a real 0. The remainder ("other", computed at log time) is current minus the
// additive categories. Absent if not cgroup v2 / not mounted in the container.
struct CgroupMemory {
    bool available = false;
    size_t current = 0;  // bytes; the memory.stat fields below are bytes too
    std::optional<size_t> peak;  // memory.peak needs kernel >= 5.19
    std::optional<size_t> anon;
    std::optional<size_t> file;  // page cache; includes shmem
    std::optional<size_t> sock;
    std::optional<size_t> slab_reclaimable;
    std::optional<size_t> slab_unreclaimable;
    std::optional<size_t> pagetables;
    std::optional<size_t> sec_pagetables;  // KVM/IOMMU
    std::optional<size_t> kernel_stack;
    std::optional<size_t> percpu;
    std::optional<size_t> vmalloc;
    std::optional<size_t> shmem;  // subset of file -> excluded from the known-sum
    std::optional<size_t> zswap;
};

// True if `path` exists and is readable.
bool FileExists(const char* path) noexcept {
    std::FILE* file = std::fopen(path, "r");
    if (file == nullptr) {
        return false;
    }
    std::fclose(file);
    return true;
}

// Fills `out` with the cgroup v2 directory to read memory accounting from, chosen deterministically.
// memory.current/memory.stat exist only on non-root cgroups, and inside a cgroup namespace the cgroup2
// mount roots at the namespace root. So if /sys/fs/cgroup itself has memory.current we are namespaced (a
// container): the mount root is a delegated cgroup whose recursive accounting covers the whole namespace
// -- the figure the OOM killer enforces -- so read it, regardless of which leaf the process was moved into
// (e.g. RouterOS's /init, whose own accounting is empty because charges do not migrate). Otherwise
// /sys/fs/cgroup is the true host root (no accounting files), so read the process's own cgroup from
// /proc/self/cgroup ("0::<path>"). false if not cgroup v2 / unreadable.
bool CgroupDir(char* out, size_t out_size) noexcept {
    if (FileExists("/sys/fs/cgroup/memory.current")) {
        std::snprintf(out, out_size, "/sys/fs/cgroup");
        return true;
    }
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
                mem.slab_reclaimable = v;
            } else if (std::strcmp(key, "slab_unreclaimable") == 0) {
                mem.slab_unreclaimable = v;
            } else if (std::strcmp(key, "pagetables") == 0) {
                mem.pagetables = v;
            } else if (std::strcmp(key, "sec_pagetables") == 0) {
                mem.sec_pagetables = v;
            } else if (std::strcmp(key, "kernel_stack") == 0) {
                mem.kernel_stack = v;
            } else if (std::strcmp(key, "percpu") == 0) {
                mem.percpu = v;
            } else if (std::strcmp(key, "vmalloc") == 0) {
                mem.vmalloc = v;
            } else if (std::strcmp(key, "shmem") == 0) {
                mem.shmem = v;
            } else if (std::strcmp(key, "zswap") == 0) {
                mem.zswap = v;
            }
        }
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
    std::string head = "current=" + std::to_string(kib(cg.current));
    if (cg.peak) {
        head += " (peak=" + std::to_string(kib(*cg.peak)) + ")";
    }
    // Each field's value in KiB, or "n/a" when the kernel does not emit that memory.stat line.
    const auto kib_opt = [](std::optional<size_t> bytes) {
        return bytes ? std::to_string(*bytes / 1024) : std::string{"n/a"};
    };
    // The remainder of current after the additive categories (shmem excluded -- it is part of file). An
    // absent field counts as 0 here, so a row of n/a is exactly why `other` stays large on a sparse kernel.
    const auto val = [](std::optional<size_t> b) { return b.value_or(size_t{0}); };
    const size_t known = val(cg.anon) + val(cg.file) + val(cg.sock) + val(cg.slab_reclaimable)
        + val(cg.slab_unreclaimable) + val(cg.pagetables) + val(cg.sec_pagetables) + val(cg.kernel_stack)
        + val(cg.percpu) + val(cg.vmalloc) + val(cg.zswap);
    const size_t other = cg.current > known ? cg.current - known : 0;
    GetLogger().Info(
        "cgroup (KiB) {} | breakdown: anon={} file={} (shmem={}) sock={} slab_reclaimable={} "
        "slab_unreclaimable={} pagetables={} sec_pagetables={} kernel_stack={} percpu={} vmalloc={} "
        "zswap={} other={}",
        head, kib_opt(cg.anon), kib_opt(cg.file), kib_opt(cg.shmem), kib_opt(cg.sock),
        kib_opt(cg.slab_reclaimable), kib_opt(cg.slab_unreclaimable), kib_opt(cg.pagetables),
        kib_opt(cg.sec_pagetables), kib_opt(cg.kernel_stack), kib_opt(cg.percpu), kib_opt(cg.vmalloc),
        kib_opt(cg.zswap), kib(other));
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
