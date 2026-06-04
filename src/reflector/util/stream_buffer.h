#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <utility>

namespace reflector {

// A fixed-capacity FIFO byte buffer used in both directions of a proxied connection:
//   - send side: Append outbound bytes, drain to the socket via View()/Consume();
//   - receive side: read straight into the writable tail via ReserveTail()/Commit(), drain via View().
// Backing storage is allocated lazily on first use and never zero-filled — make_unique_for_overwrite leaves
// the spare tail uninitialized, which is safe because View() only ever exposes [head, tail): bytes an
// Append copied or a read wrote. An unused buffer holds no allocation, which suits the send side (most
// connections never backpressure). Capacity is fixed at construction: Append returns false (writing
// nothing) and ReserveTail yields an empty span once the buffer is full — the owner turns that into
// drop-and-close.
class StreamBuffer {
public:
    explicit StreamBuffer(size_t capacity) noexcept : capacity_{capacity} {}

    // Move-only with explicit moves: a moved-from buffer must be left genuinely empty (cursors reset), not
    // with a moved-out pointer under stale offsets — otherwise Size() is wrong and the next write touches
    // freed storage. The owning TcpSocket relies on a moved-from buffer being Empty().
    StreamBuffer(StreamBuffer&& other) noexcept
        : data_{std::move(other.data_)},
          capacity_{other.capacity_},
          head_{std::exchange(other.head_, 0)},
          tail_{std::exchange(other.tail_, 0)} {}
    StreamBuffer& operator=(StreamBuffer&& other) noexcept {
        if (this != &other) {  // self-move would otherwise self-move data_ (unspecified) under stale offsets
            data_ = std::move(other.data_);
            capacity_ = other.capacity_;
            head_ = std::exchange(other.head_, 0);
            tail_ = std::exchange(other.tail_, 0);
        }
        return *this;
    }

    [[nodiscard]] size_t Size() const noexcept { return tail_ - head_; }
    [[nodiscard]] bool Empty() const noexcept { return tail_ == head_; }
    [[nodiscard]] size_t Capacity() const noexcept { return capacity_; }

    [[nodiscard]] std::span<const std::byte> View() const noexcept {
        return {data_.get() + head_, Size()};
    }

    // Advance the head by `n` consumed bytes; on full drain, reset to the front to reclaim the whole buffer.
    void Consume(size_t n) noexcept {
        head_ += n;
        if (head_ >= tail_) {
            head_ = tail_ = 0;
        }
    }

    // Copy `bytes` onto the back (send side). Reclaims the consumed prefix first; returns false, writing
    // nothing, if they would not fit within the capacity — the owner aborts the connection.
    [[nodiscard]] bool Append(std::span<const std::byte> bytes) {
        Compact();
        if (tail_ + bytes.size() > capacity_) {
            return false;
        }
        if (!bytes.empty()) {
            Allocate();
            std::memcpy(data_.get() + tail_, bytes.data(), bytes.size());
            tail_ += bytes.size();
        }
        return true;
    }

    // Reclaim the consumed prefix and hand back the writable free tail to read into (receive side): the
    // span [Size(), Capacity()) of spare room, empty when the buffer is full. Commit the count read into it.
    [[nodiscard]] std::span<std::byte> ReserveTail() {
        Compact();
        Allocate();
        return {data_.get() + tail_, capacity_ - tail_};
    }

    // Extend the live region by `n` bytes just read into ReserveTail()'s span. read() never writes past that
    // span, so `n` overrunning the free tail is a caller bug, not a runtime (or wire-driven) condition: the
    // count is ours, never the peer's. Assert catches it in Debug/ASan; UB otherwise, like a narrow-contract
    // standard-library access.
    void Commit(size_t n) noexcept {
        assert(n <= capacity_ - tail_);
        tail_ += n;
    }

private:
    void Allocate() {
        if (!data_) {
            data_ = std::make_unique_for_overwrite<std::byte[]>(capacity_);
        }
    }

    // Slide the live [head, tail) bytes to the front so the whole spare capacity is contiguous at the tail.
    void Compact() noexcept {
        if (head_ == 0) {
            return;
        }
        if (tail_ > head_) {
            std::memmove(data_.get(), data_.get() + head_, tail_ - head_);
        }
        tail_ -= head_;
        head_ = 0;
    }

    std::unique_ptr<std::byte[]> data_;
    size_t capacity_;
    size_t head_ = 0;
    size_t tail_ = 0;
};

} // namespace reflector
