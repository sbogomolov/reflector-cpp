#pragma once

namespace reflector {

class NoMove {
protected:
    NoMove() = default;
    ~NoMove() = default;

    NoMove(const NoMove&) = delete;
    NoMove& operator=(const NoMove&) = delete;
    NoMove(NoMove&&) = delete;
    NoMove& operator=(NoMove&&) = delete;
};

} // namespace reflector
