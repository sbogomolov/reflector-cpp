#pragma once

#include "dispatcher.h"
#include "util/no_move.h"

#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace reflector {

// A minimal readiness reactor over kqueue (macOS) / epoll (Linux): callers register a callback per
// fd, and Run/PollOnce invoke it whenever that fd becomes readable. One callback per fd; the fd is
// the key. The production implementation of the Dispatcher interface.
class EventLoopDispatcher : public Dispatcher, NoMove {
public:
    EventLoopDispatcher();
    ~EventLoopDispatcher() noexcept override;

    [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override;

    // Fires (and reschedules to now + interval) every timer whose deadline is <= now. Public so the
    // timer path is driven directly in tests with an injected `now` — no clock-seam member, no friend.
    void FireDueTimers(std::chrono::steady_clock::time_point now);
    // The wait to pass to PollOnce so the loop wakes by the soonest timer deadline, capped at
    // MAX_POLL_INTERVAL. Pure; public for the same test reason.
    [[nodiscard]] std::chrono::milliseconds NextTimeout(std::chrono::steady_clock::time_point now) const;

    void Run(const volatile std::sig_atomic_t& stop_requested) override;
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class EventLoopDispatcherTest;

    static constexpr std::chrono::milliseconds MAX_POLL_INTERVAL{1000};

    struct TimerEntry {
        TimerId id;
        std::chrono::milliseconds interval;
        std::chrono::steady_clock::time_point next;
        OnTimerCallback callback;
    };

    [[nodiscard]] TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) override;
    void UnregisterTimer(TimerId id) noexcept override;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

    [[nodiscard]] bool AddReadEvent(int fd) noexcept;
    [[nodiscard]] bool RemoveReadEvent(int fd) noexcept;
    bool Unregister(int fd) noexcept override;

    // fd -> callback. The kernel reports the ready fd (kqueue ident / epoll data.fd) and we
    // look the callback up here rather than stashing a pointer in the event's user-data: a
    // stale event for an already-unregistered fd then fails the lookup safely instead of
    // dereferencing freed state — which a batched read could otherwise deliver.
    std::unordered_map<int, OnReadableCallback> callbacks_;
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
    int event_fd_ = -1;
};

} // namespace reflector
