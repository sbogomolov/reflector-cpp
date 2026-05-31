#pragma once

#include "dispatcher.h"

#include <chrono>
#include <utility>

namespace reflector {

// Owns one periodic timer registration on a Dispatcher and cancels it on destruction — the RAII
// face of the dispatcher's private register/unregister pair (it is the dispatcher's friend, so its
// construction registers and its destruction unregisters). Move-only. Invalid (IsValid() == false)
// when the interval is <= 0 or the callback is unset.
class Timer {
public:
    Timer() noexcept = default;
    Timer(Dispatcher& dispatcher, std::chrono::milliseconds interval,
        const Dispatcher::OnTimerCallback& callback)
            : dispatcher_{&dispatcher}, id_{dispatcher.RegisterTimer(interval, callback)} {}

    Timer(Timer&& other) noexcept
            : dispatcher_{std::exchange(other.dispatcher_, nullptr)}, id_{other.id_} {}
    Timer& operator=(Timer&& other) noexcept {
        if (this != &other) {
            Reset();
            dispatcher_ = std::exchange(other.dispatcher_, nullptr);
            id_ = other.id_;
        }
        return *this;
    }
    ~Timer() noexcept { Reset(); }

    [[nodiscard]] bool IsValid() const noexcept { return dispatcher_ != nullptr && id_ != Dispatcher::TimerId{}; }

    // Cancels the timer now (unregisters from the dispatcher); IsValid() becomes false afterwards.
    // Idempotent — a no-op on an already-invalid timer. The destructor and move-assignment call it too.
    void Reset() noexcept {
        if (dispatcher_ != nullptr) {
            std::exchange(dispatcher_, nullptr)->UnregisterTimer(id_);
        }
    }

private:
    Dispatcher* dispatcher_ = nullptr;
    Dispatcher::TimerId id_{};
};

} // namespace reflector
