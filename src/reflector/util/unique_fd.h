#pragma once

#include "reflector/util/no_copy.h"

#include <unistd.h>

#include <utility>

namespace reflector {

// Owns one file descriptor and closes it on destruction. Move-only; a moved-from UniqueFd holds -1.
// Replaces the `int fd_ = -1` + hand-written close/exchange the socket classes used to repeat.
class UniqueFd : NoCopy {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_{fd} {}

    UniqueFd(UniqueFd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            Reset(std::exchange(other.fd_, -1));
        }
        return *this;
    }

    ~UniqueFd() { Reset(); }

    [[nodiscard]] int Get() const noexcept { return fd_; }
    [[nodiscard]] bool IsValid() const noexcept { return fd_ >= 0; }
    // Contextual `if (fd)` / `if (!fd)`; explicit so it can't slip into arithmetic or comparisons.
    [[nodiscard]] explicit operator bool() const noexcept { return IsValid(); }

    // Relinquish the descriptor without closing it.
    [[nodiscard]] int Release() noexcept { return std::exchange(fd_, -1); }

    // Close the held descriptor (if any) and adopt `fd`.
    void Reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

} // namespace reflector
