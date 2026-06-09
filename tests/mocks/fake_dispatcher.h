#pragma once

#include "reflector/dispatcher.h"

#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <vector>

namespace reflector {

// Fake Dispatcher: records the per-fd callback a subscriber registers and lets a test fire it via
// FireReadable — standing in for the kqueue/epoll reactor with no real event queue. Mirrors the
// production contract (one callback per fd; re-registering a watched or invalid fd fails).
class FakeDispatcher : public Dispatcher {
public:
    [[nodiscard]] Dispatcher::Registration Register(int fd, FdCallbacks callbacks) override {
        if (fail_registers_remaining > 0) {
            --fail_registers_remaining;
            return {};  // seam: drive the EnsureListener / OnAccept registration-failure rollback paths
        }
        if (fd < 0 || !callbacks.read.IsValid() || callbacks_.contains(fd)) {
            return {};
        }
        callbacks_.emplace(fd, std::move(callbacks));
        return MakeRegistration(fd);
    }
    using Dispatcher::Register;  // un-hide the base 2-arg readability-only convenience

    // Write interest starts disarmed — mirroring production (read is always armed). Toggling updates
    // the armed flag; false on an unwatched fd.
    [[nodiscard]] bool SetWriteInterest(int fd, bool enabled) noexcept override {
        if (fail_set_write_interest_remaining > 0) {
            --fail_set_write_interest_remaining;
            return false;  // seam: drive Sync()'s SetWriteInterest-false -> Abort path
        }
        const auto it = callbacks_.find(fd);
        if (it == callbacks_.end()) {
            return false;
        }
        it->second.write_armed = enabled;
        return true;
    }

    [[nodiscard]] bool IsWriteArmed(int fd) const noexcept {
        const auto it = callbacks_.find(fd);
        return it != callbacks_.end() && it->second.write_armed;
    }

    // Production blocks here; the fake records the call and returns. Tests drive readiness via
    // FireReadable() rather than a real loop.
    void Run(const volatile std::sig_atomic_t& /*stop_requested*/) override { ++run_calls; }

    size_t run_calls = 0;

    // Test seam: while > 0, the next Register fails (and decrements). A real reactor only fails Register under
    // fd exhaustion; this drives the registration-failure rollback paths deterministically.
    int fail_registers_remaining = 0;
    // Test seam: while > 0, the next SetWriteInterest returns false (and decrements), driving Sync -> Abort.
    int fail_set_write_interest_remaining = 0;

    // Invokes the read callback for `fd`, as the reactor would when `fd` becomes readable. Read is
    // always armed and always present (Register requires it), so this is a no-op only on an unwatched
    // fd. Invokes the stored delegate directly (it may unregister the fd or toggle interest):
    // Delegate::operator() loads its members before the tail-call, so the call survives a self-erase --
    // matching production (PollOnce).
    void FireReadable(int fd) {
        const auto it = callbacks_.find(fd);
        if (it != callbacks_.end()) {
            it->second.read(fd);
        }
    }

    // Invokes the write callback for `fd`, as the reactor would when `fd` becomes writable. Unlike
    // FireReadable, write delivery is not gated on write_armed: a test fires this to model a
    // connect completing or a send buffer draining; whether write interest was armed is the proxy's
    // concern, asserted separately via IsWriteArmed.
    void FireWritable(int fd) {
        const auto it = callbacks_.find(fd);
        if (it != callbacks_.end() && it->second.write.IsValid()) {
            it->second.write(fd);
        }
    }

    // Fires every enabled timer once with the simulated fire time `now`. A callback may unregister a
    // timer (marked disabled, skipped here, swept after) or register one (appended past `count`, so it
    // first fires NEXT round -- production's fresh `next = now + interval` keeps a mid-fire-registered
    // timer out of the current walk; the fake has no deadlines, so the bound models it). Index by
    // position: an append-reallocation can't dangle the walk, and removal is deferred, so entries below
    // `count` never shift. Tests pass `now` to drive time-based callbacks (e.g. eviction).
    void FireTimers(std::chrono::steady_clock::time_point now) {
        firing_timers_ = true;
        const auto count = timers_.size();
        for (size_t idx = 0; idx < count; ++idx) {
            const TimerEntry& entry = timers_[idx];
            if (entry.enabled) {
                entry.callback(now);
            }
        }
        firing_timers_ = false;
        Sweep();
    }

    [[nodiscard]] size_t TimerCount() const noexcept { return timers_.size(); }

    [[nodiscard]] bool IsWatching(int fd) const noexcept { return callbacks_.contains(fd); }
    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

private:
    bool Unregister(int fd) noexcept override { return callbacks_.erase(fd) > 0; }

    [[nodiscard]] TimerId AllocateTimerId() noexcept override {
        return static_cast<TimerId>(next_timer_id_++);
    }

    [[nodiscard]] bool RegisterTimer(
        TimerId id, std::chrono::milliseconds interval, const OnTimerCallback& callback) override {
        if (static_cast<uint64_t>(id) >= next_timer_id_) {
            return false;
        }
        if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
            UnregisterTimer(id);  // invalid (re-)registration leaves the timer stopped, like Start with bad args
            return false;
        }
        for (TimerEntry& entry : timers_) {
            if (entry.id == id) {  // reuse a restart / re-registered disabled id, never an appended duplicate
                entry.callback = callback;
                entry.enabled = true;
                return true;
            }
        }
        timers_.push_back(TimerEntry{.id = id, .callback = callback});
        return true;
    }

    void UnregisterTimer(TimerId id) noexcept override {
        for (auto it = timers_.begin(); it != timers_.end(); ++it) {
            if (it->id == id && it->enabled) {  // at most one enabled timer per id
                if (firing_timers_) {
                    it->enabled = false;  // FireTimers is walking; defer the erase to its post-walk sweep
                } else {
                    timers_.erase(it);  // no walk in progress; erase in place
                }
                return;
            }
        }
    }

    // Erases the timers UnregisterTimer marked disabled mid-fire. Runs after FireTimers' walk -- never
    // during it, where a live erase would shift the vector. Named after production's Sweep.
    void Sweep() {
        std::erase_if(timers_, [](const TimerEntry& entry) { return !entry.enabled; });
    }

    struct TimerEntry {
        TimerId id;
        OnTimerCallback callback;
        bool enabled = true;
    };

    std::unordered_map<int, FdCallbacks> callbacks_;
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
    bool firing_timers_ = false;
};

} // namespace reflector
