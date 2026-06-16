#pragma once

namespace reflector {

// Logs the process's memory footprint at Info level (under its own "MemoryReport" logger): current
// RSS, peak RSS, and — on glibc — the heap arena breakdown (bytes in use vs free-but-retained vs
// total arena vs mmap'd). The glibc breakdown is the diagnostic that reveals allocator retention: a
// small in-use figure under a large arena means freed memory the allocator is holding rather than
// returning to the OS. A deployment aid for tracking footprint where no shell is available; the
// caller gates it on Config::DebugMemory.
void LogMemoryReport();

} // namespace reflector
