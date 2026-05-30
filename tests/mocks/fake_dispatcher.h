#pragma once

#include "reflector/dispatcher.h"

#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace reflector {

// Fake Dispatcher: records the per-fd callback a subscriber registers and lets a test fire it via
// FireReadable — standing in for the kqueue/epoll reactor with no real event queue. Mirrors the
// production contract (one callback per fd; re-registering a watched or invalid fd fails).
class FakeDispatcher : public Dispatcher {
public:
    [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override {
        if (fd < 0 || callbacks_.contains(fd)) {
            return {};
        }
        callbacks_.emplace(fd, on_readable);
        return MakeRegistration(fd);
    }

    // Production blocks here; the fake records the call and returns. Tests drive readiness via
    // FireReadable() rather than a real loop.
    void Run(const volatile std::sig_atomic_t& /*stop_requested*/) override { ++run_calls; }

    size_t run_calls = 0;

    // Invokes the callback registered for `fd`, as the reactor would when `fd` becomes readable.
    void FireReadable(int fd) {
        const auto it = callbacks_.find(fd);
        if (it != callbacks_.end()) {
            it->second(fd);
        }
    }

    // Fires every registered timer once, copying each callback before invoking (a callback may
    // unregister a timer mid-fire), mirroring FireReadable and the production copy-before-invoke.
    void FireTimers() {
        const auto snapshot = timers_;
        for (const auto& entry : snapshot) {
            entry.callback();
        }
    }

    [[nodiscard]] size_t TimerCount() const noexcept { return timers_.size(); }

    [[nodiscard]] bool IsWatching(int fd) const noexcept { return callbacks_.contains(fd); }
    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

private:
    bool Unregister(int fd) noexcept override { return callbacks_.erase(fd) > 0; }

    [[nodiscard]] TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) override {
        if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
            return TimerId{};
        }
        const auto id = static_cast<TimerId>(next_timer_id_++);
        timers_.push_back(TimerEntry{.id = id, .callback = callback});
        return id;
    }

    void UnregisterTimer(TimerId id) noexcept override {
        std::erase_if(timers_, [id](const TimerEntry& entry) { return entry.id == id; });
    }

    struct TimerEntry {
        TimerId id;
        OnTimerCallback callback;
    };

    std::unordered_map<int, OnReadableCallback> callbacks_;
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
};

} // namespace reflector
