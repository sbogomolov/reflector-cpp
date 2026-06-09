#pragma once

#include "dispatcher.h"
#include "util/no_move.h"
#include "util/unique_fd.h"

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

    [[nodiscard]] Dispatcher::Registration Register(int fd, FdCallbacks callbacks) override;
    using Dispatcher::Register;  // un-hide the base 2-arg readability-only convenience
    [[nodiscard]] bool SetWriteInterest(int fd, bool enabled) noexcept override;

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
        bool enabled = true;  // UnregisterTimer marks this false; the post-fire sweep erases it
    };

    [[nodiscard]] TimerId AllocateTimerId() noexcept override;
    [[nodiscard]] bool RegisterTimer(
        TimerId id, std::chrono::milliseconds interval, const OnTimerCallback& callback) override;
    void UnregisterTimer(TimerId id) noexcept override;
    // Erases the timers UnregisterTimer marked disabled mid-fire. Run after FireDueTimers' walk --
    // never during it, where a live erase would shift the vector.
    void Sweep() noexcept;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

    // Program `fd`'s kernel interest: read is ALWAYS armed, write per `enable_write`. Shared by Register
    // (initial state) and SetWriteInterest (write toggle). Refuses to arm write with no write handler (a
    // ready fd with nothing to invoke would busy-spin). On kqueue the read filter is always EV_ADD'd
    // while the write filter is EV_ADD'd only when arming — so EVFILT_WRITE never attaches to a BPF
    // capture fd that can't support it; on epoll it rewrites the full mask (EPOLLIN always set).
    [[nodiscard]] bool SetEvents(int fd, bool enable_write) noexcept;
    // Removes `fd` from the event queue entirely (both directions). Self-logs on failure, so the
    // `Register` rollback path may ignore the result — hence not [[nodiscard]].
    bool RemoveEvents(int fd) noexcept;
    bool Unregister(int fd) noexcept override;

    // fd -> callbacks (always-armed read handler + optional write handler + its write_armed flag). The
    // kernel reports the ready fd (kqueue ident / epoll data.fd) and we look the entry up here rather
    // than stashing a pointer in the event's user-data: a stale event for an already-unregistered fd
    // then fails the lookup safely instead of dereferencing freed state — which a batched read could
    // otherwise deliver. write_armed mirrors the kernel state so SetWriteInterest can rebuild the epoll
    // mask / pick the kqueue filter to toggle, and PollOnce can skip a write disarmed between the kernel
    // report and the dispatch.
    std::unordered_map<int, FdCallbacks> callbacks_;
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
    bool firing_timers_ = false;  // true while FireDueTimers walks; UnregisterTimer then defers the erase to the sweep
    UniqueFd event_fd_;
};

} // namespace reflector
