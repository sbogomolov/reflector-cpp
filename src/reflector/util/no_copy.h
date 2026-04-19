#pragma once

namespace reflector {

class NoCopy {
protected:
    NoCopy() = default;
    ~NoCopy() = default;

    // Disallow copying
    NoCopy(const NoCopy& other) = delete;
    NoCopy& operator=(const NoCopy& other) = delete;

    // Allow moving
    NoCopy(NoCopy&& other) = default;
    NoCopy& operator=(NoCopy&& other) = default;
};

} // namespace reflector
