#pragma once

#include "dispatcher.h"
#include "util/no_copy.h"

#include <chrono>
#include <utility>

namespace reflector {

// RAII face of a single periodic timer on a Dispatcher. Holds one TimerId for its whole life
// (allocated at construction, registered nowhere yet); Start() registers it and Stop() unregisters
// it under that same stable id, so the timer can be toggled without churning ids. Stops on
// destruction. Move-only.
class Timer : NoCopy {
public:
    explicit Timer(Dispatcher& dispatcher)
            : dispatcher_{&dispatcher}, id_{dispatcher.AllocateTimerId()} {}

    Timer(Timer&& other) noexcept
            : dispatcher_{std::exchange(other.dispatcher_, nullptr)}
            , id_{other.id_}
            , running_{std::exchange(other.running_, false)} {}
    Timer& operator=(Timer&& other) noexcept {
        if (this != &other) {
            Stop();
            dispatcher_ = std::exchange(other.dispatcher_, nullptr);
            id_ = other.id_;
            running_ = std::exchange(other.running_, false);
        }
        return *this;
    }
    ~Timer() noexcept { Stop(); }

    // Registers the timer to fire every `interval` until Stop()/destruction; if already running,
    // RegisterTimer replaces the prior registration (a restart). A non-positive interval or unset
    // callback leaves it stopped (IsRunning() == false).
    void Start(std::chrono::milliseconds interval, const Dispatcher::OnTimerCallback& callback) {
        running_ = dispatcher_->RegisterTimer(id_, interval, callback);
    }

    void Stop() noexcept {
        if (running_ && dispatcher_ != nullptr) {
            dispatcher_->UnregisterTimer(id_);
            running_ = false;
        }
    }

    [[nodiscard]] bool IsRunning() const noexcept { return running_; }

private:
    Dispatcher* dispatcher_;
    Dispatcher::TimerId id_;
    bool running_ = false;
};

} // namespace reflector
