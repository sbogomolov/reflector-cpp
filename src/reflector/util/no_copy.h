#pragma once

namespace reflector {

class NoCopy {
protected:
    NoCopy() = default;
    ~NoCopy() = default;

    NoCopy(const NoCopy& other) = delete;
    NoCopy& operator=(const NoCopy& other) = delete;

    // Declaring the deleted copies suppresses the implicit moves, so re-default them.
    NoCopy(NoCopy&& other) = default;
    NoCopy& operator=(NoCopy&& other) = default;
};

} // namespace reflector
