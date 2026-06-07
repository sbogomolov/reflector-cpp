#pragma once

#include <fcntl.h>

namespace reflector {

// Make `fd` non-blocking, preserving its other open-file flags (a bare F_SETFL would clobber them).
// A no-op success if O_NONBLOCK is already set. Returns false with errno set on failure; the caller logs.
[[nodiscard]] inline bool SetNonBlocking(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    if ((flags & O_NONBLOCK) != 0) {
        return true;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace reflector
