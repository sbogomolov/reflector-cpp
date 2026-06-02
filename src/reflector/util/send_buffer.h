#pragma once

#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace reflector {

// A FIFO byte buffer for un-flushed outbound data: append at the back, consume from a head offset, and
// reclaim the consumed prefix before the next append. Allocation is lazy — an empty buffer holds nothing
// — which suits a workload that buffers rarely and in small amounts (the caller enforces an upper bound
// on Size() and drops the connection on overflow). Deliberately a flat growable buffer, not std::deque:
// the rare reclaim memmove beats per-node allocation for a byte stream.
class SendBuffer {
public:
    SendBuffer() = default;

    // Move-only, with explicit moves: a moved-from buffer must be left genuinely empty (consumed_ reset
    // too), not just with a moved-out vector and a stale offset — otherwise Size() underflows and the next
    // Append erases past the end. The owning TcpSocket relies on a moved-from buffer being Empty().
    SendBuffer(SendBuffer&& other) noexcept
        : data_{std::move(other.data_)}, consumed_{std::exchange(other.consumed_, 0)} {}
    SendBuffer& operator=(SendBuffer&& other) noexcept {
        if (this != &other) {  // self-move would otherwise self-move data_ (unspecified) under a stale consumed_
            data_ = std::move(other.data_);
            consumed_ = std::exchange(other.consumed_, 0);
        }
        return *this;
    }

    [[nodiscard]] size_t Size() const noexcept { return data_.size() - consumed_; }
    [[nodiscard]] bool Empty() const noexcept { return Size() == 0; }

    void Append(std::span<const std::byte> bytes) {
        if (consumed_ > 0) {  // reclaim the already-consumed prefix before growing
            data_.erase(data_.begin(), data_.begin() + static_cast<std::ptrdiff_t>(consumed_));
            consumed_ = 0;
        }
        data_.insert(data_.end(), bytes.begin(), bytes.end());
    }

    [[nodiscard]] std::span<const std::byte> View() const noexcept {
        return {data_.data() + consumed_, Size()};
    }

    // Advance the head by `n` consumed bytes; on full drain, clear to release the data.
    void Consume(size_t n) noexcept {
        consumed_ += n;
        if (consumed_ >= data_.size()) {
            data_.clear();
            consumed_ = 0;
        }
    }

private:
    std::vector<std::byte> data_;
    size_t consumed_ = 0;
};

} // namespace reflector
