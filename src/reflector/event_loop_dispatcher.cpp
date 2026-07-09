#include "event_loop_dispatcher.h"

#include "error.h"
#include "logger.h"
#include "platform.h"

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <sys/event.h>
#endif

namespace {

using namespace reflector;

#if !defined(__linux__)
timespec ToTimespec(std::chrono::milliseconds timeout) noexcept {
    return timespec{
        .tv_sec = static_cast<time_t>(timeout.count() / 1000),
        .tv_nsec = static_cast<long>((timeout.count() % 1000) * 1000000),
    };
}
#endif

Logger& GetLogger() noexcept {
    static Logger logger{"Dispatcher"};
    return logger;
}

} // namespace

namespace reflector {

EventLoopDispatcher::EventLoopDispatcher() {
#if defined(__linux__)
    event_fd_.Reset(epoll_create1(0));
#else
    event_fd_.Reset(kqueue());
#endif

    if (!event_fd_) {
        GetLogger().Error("Cannot create dispatcher event queue: {}", Error::FromErrno());
    } else {
        GetLogger().Debug("Created dispatcher event queue fd {}", event_fd_.Get());
    }
}

EventLoopDispatcher::~EventLoopDispatcher() noexcept {
    if (!callbacks_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} fd callback registration(s) still active", callbacks_.size());
    }
    if (!timers_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} timer registration(s) still active", timers_.size());
    }

    if (event_fd_) {
        GetLogger().Debug("Closing dispatcher event queue fd {}", event_fd_.Get());
        event_fd_.Reset();
    }
}

Dispatcher::Registration EventLoopDispatcher::Register(int fd, FdCallbacks callbacks) {
    if (fd < 0) {
        GetLogger().Error("Cannot register fd callback: fd is invalid");
        return {};
    }
    if (!callbacks.read.IsValid()) {
        GetLogger().Error("Cannot register fd callback: a read handler is required for fd {}", fd);
        return {};
    }
    if (callbacks_.contains(fd)) {
        GetLogger().Error("Cannot register fd callback: a callback for fd {} is already registered", fd);
        return {};
    }
    // Insert first so SetEvents reads the requested initial write arm state from the entry, then
    // program the kernel interest (read always armed). Roll back (kernel + map) on failure, so a
    // partial registration never leaks.
    const auto it = callbacks_.emplace(fd, std::move(callbacks)).first;
    if (!SetEvents(fd, it->second.write_armed)) {
        RemoveEvents(fd);
        callbacks_.erase(it);
        GetLogger().Error("Cannot register fd callback: event registration failed for fd {}", fd);
        return {};
    }

    GetLogger().Debug("Registered fd callback for fd {}", fd);
    return MakeRegistration(fd);
}

bool EventLoopDispatcher::SetWriteInterest(int fd, bool enabled) noexcept {
    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Warning("Cannot set write interest for fd {}: not registered", fd);
        return false;
    }
    if (it->second.write_armed == enabled) {
        return true;
    }
    if (!SetEvents(fd, enabled)) {
        return false;
    }
    it->second.write_armed = enabled;
    return true;
}

bool EventLoopDispatcher::Unregister(int fd) noexcept {
    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Warning("Cannot unregister fd callback for fd {}: not found", fd);
        return false;
    }

    callbacks_.erase(it);
    if (!RemoveEvents(fd)) {
        GetLogger().Error("Cannot remove events for fd {} after unregistering its callback", fd);
    }

    GetLogger().Debug("Unregistered fd callback for fd {}", fd);
    return true;
}

void EventLoopDispatcher::Run(const volatile std::sig_atomic_t& stop_requested) {
    GetLogger().Info("Starting dispatcher event loop");
    if (!event_fd_) {
        GetLogger().Error("Cannot run dispatcher: event queue is invalid");
        return;
    }
    while (stop_requested == 0) {
        const auto now = std::chrono::steady_clock::now();
        // Fire what's due, then block only until the next deadline. FireDueTimers reschedules the
        // timers it fires to now + interval, so the same `now` drives a correct NextTimeout; a timer
        // that comes due during the wait fires on the next iteration (within one MAX_POLL_INTERVAL).
        FireDueTimers(now);
        PollOnce(NextTimeout(now));
    }
    GetLogger().Info("Stopped dispatcher event loop");
}

bool EventLoopDispatcher::PollOnce(std::chrono::milliseconds timeout) {
    if (!event_fd_) {
        GetLogger().Error("Cannot poll dispatcher: event queue is invalid");
        return false;
    }

#if defined(__linux__)
    epoll_event event{};
    const auto event_count = epoll_wait(event_fd_.Get(), &event, 1, static_cast<int>(timeout.count()));
    if (event_count < 0) {
        if (errno == EINTR) {
            // Expected when a signal interrupts polling; callers decide whether to retry or shut down.
            return false;
        }
        GetLogger().Error("Cannot poll dispatcher read events: {}", Error::FromErrno());
        return false;
    }
    if (event_count == 0) {
        return false;
    }
    const auto fd = event.data.fd;
    const auto events = event.events;
#else
    auto timeout_spec = ToTimespec(timeout);
    struct kevent event{};
    const auto event_count = kevent(event_fd_.Get(), nullptr, 0, &event, 1, &timeout_spec);
    if (event_count < 0) {
        if (errno == EINTR) {
            // Expected when a signal interrupts polling; callers decide whether to retry or shut down.
            return false;
        }
        GetLogger().Error("Cannot poll dispatcher read events: {}", Error::FromErrno());
        return false;
    }
    if (event_count == 0) {
        return false;
    }
    const auto fd = static_cast<int>(event.ident);
    if ((event.flags & EV_ERROR) != 0) {
        GetLogger().Error("Dispatcher read event failed for fd {}: {}", fd, event.data);
        return false;
    }
#endif

    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Warning("Dispatcher woke for unwatched fd {}", fd);
        return false;
    }

#if defined(__linux__)
    // EPOLLERR/EPOLLHUP can arrive without EPOLLIN/EPOLLOUT (a failed connect surfaces as EPOLLERR,
    // often with no EPOLLOUT; a peer hangup as EPOLLHUP). Fold the error into READABLE only: read is
    // always armed, so the read handler is woken to recv() the EOF/error and tear down — the uniform
    // error sink. Writability needs no fold; any error already reaches the read handler, and the write
    // handler fires only on genuine EPOLLOUT.
    const bool err = (events & (EPOLLERR | EPOLLHUP)) != 0;
    const bool readable = (events & EPOLLIN) != 0 || err;
    const bool writable = (events & EPOLLOUT) != 0;
#else
    const bool readable = event.filter == EVFILT_READ;
    const bool writable = event.filter == EVFILT_WRITE;
#endif

    // Read is always armed and always has a valid handler (Register requires one), so readability
    // dispatches unconditionally; write dispatches only when armed (SetEvents refuses to arm write with
    // no callback). Invoke the stored delegate directly -- Delegate::operator() loads its two members
    // before the tail-call, so a handler that unregisters this fd (freeing the node) or registers another
    // (rehashing callbacks_) can't disturb the call already in flight; the same property DispatchPacket
    // relies on. The write iterator is still re-resolved below, since the read handler may invalidate it.
    if (readable) {
        it->second.read(fd);
    }
    if (writable) {
        // The read handler, which runs only when readable, may have invalidated `it` — most often by tearing
        // this fd down (recv EOF/error -> close -> Unregister erases the entry), or by registering a new
        // fd elsewhere (e.g. an accept handler), whose insert can rehash callbacks_ and invalidate every
        // iterator. Re-resolve before the write (end() => this fd is gone). A write-only wakeup ran no
        // handler, so `it` is untouched and reused without a lookup.
        const auto live = readable ? callbacks_.find(fd) : it;
        if (live != callbacks_.end() && live->second.write_armed) {
            live->second.write(fd);
        }
    }
    return true;
}

EventLoopDispatcher::TimerId EventLoopDispatcher::AllocateTimerId() noexcept {
    return static_cast<TimerId>(next_timer_id_++);
}

bool EventLoopDispatcher::RegisterTimer(
    TimerId id, std::chrono::milliseconds interval, const OnTimerCallback& callback) {
    if (static_cast<uint64_t>(id) >= next_timer_id_) {
        GetLogger().Error("Cannot register timer: TimerId {} was not allocated by this dispatcher",
            static_cast<uint64_t>(id));
        return false;
    }
    if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
        UnregisterTimer(id);  // an invalid (re-)registration leaves the timer stopped, like Start with bad args
        GetLogger().Error("Cannot register timer: non-positive interval or invalid callback");
        return false;
    }
    // Reuse the existing entry for this id rather than append: an appended entry sits past FireDueTimers'
    // cursor and, with a real-clock `next`, can be due in the same walk -- firing twice. An active id is a
    // restart; an id left disabled by an UnregisterTimer earlier this round is reclaimed here.
    const TimerEntry registration{
        .id = id,
        .interval = interval,
        .next = std::chrono::steady_clock::now() + interval,
        .callback = callback,
    };
    const auto it = std::ranges::find_if(timers_, [id](const TimerEntry& entry) { return entry.id == id; });
    if (it != timers_.end()) {
        *it = registration;
    } else {
        timers_.push_back(registration);
    }
    GetLogger().Debug("Registered timer {} (interval {}ms); {} active", static_cast<uint64_t>(id),
        interval.count(), std::ranges::count_if(timers_, [](const TimerEntry& entry) { return entry.enabled; }));
    return true;
}

void EventLoopDispatcher::UnregisterTimer(TimerId id) noexcept {
    const auto it = std::ranges::find_if(timers_, [id](const TimerEntry& entry) {
        return entry.id == id && entry.enabled;  // at most one enabled timer per id
    });
    if (it == timers_.end()) {
        return;
    }
    if (firing_timers_) {
        it->enabled = false;  // FireDueTimers is walking; defer the erase to its post-walk sweep
    } else {
        timers_.erase(it);  // no walk in progress; erase in place
    }
    GetLogger().Debug("Unregistered timer {}; {} active", static_cast<uint64_t>(id),
        std::ranges::count_if(timers_, [](const TimerEntry& t) { return t.enabled; }));
}

void EventLoopDispatcher::FireDueTimers(std::chrono::steady_clock::time_point now) {
    // Fire every enabled timer whose deadline has passed, rescheduling it to now + interval first so a
    // periodic timer is no longer due this round. A callback may UnregisterTimer (marks disabled, skipped
    // below and swept after the walk) or RegisterTimer (appends, possibly reallocating) -- so index by
    // position and re-fetch each iteration, never holding an iterator across the callback. Removal is
    // deferred to the sweep, so the walk never shifts and needs no restart.
    firing_timers_ = true;
    for (size_t idx = 0; idx < timers_.size(); ++idx) {
        TimerEntry& entry = timers_[idx];
        if (entry.enabled && entry.next <= now) {
            entry.next = now + entry.interval;  // forward from now; never += interval (no backlog spin)
            entry.callback(now);  // may mutate timers_; entry's fields are loaded before the call
        }
    }
    firing_timers_ = false;
    Sweep();
}

void EventLoopDispatcher::Sweep() noexcept {
    std::erase_if(timers_, [](const TimerEntry& entry) { return !entry.enabled; });
}

std::chrono::milliseconds EventLoopDispatcher::NextTimeout(std::chrono::steady_clock::time_point now) const {
    auto timeout = MAX_POLL_INTERVAL;
    for (const auto& entry : timers_) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(entry.next - now);
        timeout = std::min(timeout, remaining);
    }
    return std::max(timeout, std::chrono::milliseconds{0});
}

bool EventLoopDispatcher::SetEvents(int fd, bool enable_write) noexcept {
    if (!event_fd_) {
        GetLogger().Error("Cannot set events for fd {}: event queue is invalid", fd);
        return false;
    }
    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Error("Cannot set events for fd {}: not registered", fd);
        return false;
    }
    // Refuse to arm write with no write handler: a writable fd with nothing to invoke would busy-spin
    // the level-triggered loop. (Read is always armed; Register guarantees a read handler.)
    if (enable_write && !it->second.write.IsValid()) {
        GetLogger().Error("Cannot arm write interest for fd {}: no write callback registered", fd);
        return false;
    }

#if defined(__linux__)
    // epoll has no per-direction toggle — rewrite the whole mask (read always on). MOD an already-
    // watched fd; on its first call (from Register) it is not in the set yet, so MOD returns ENOENT and
    // we ADD.
    epoll_event event{};
    event.events = EPOLLIN | (enable_write ? EPOLLOUT : 0u);
    event.data.fd = fd;
    if (epoll_ctl(event_fd_.Get(), EPOLL_CTL_MOD, fd, &event) != 0
        && (errno != ENOENT || epoll_ctl(event_fd_.Get(), EPOLL_CTL_ADD, fd, &event) != 0)) {
        GetLogger().Error("Cannot set events for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#else
    // Read is always armed; re-EV_ADD'ing an already-present filter is idempotent. The write filter is
    // EV_ADD'd only when arming — so EVFILT_WRITE is never EV_ADD'd on a BPF capture device (which
    // rejects it with EINVAL); disarming uses bare EV_DISABLE, tolerating ENOENT when it was never added.
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    if (kevent(event_fd_.Get(), &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot arm read interest for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
    const auto write_flags = static_cast<uint16_t>(enable_write ? (EV_ADD | EV_ENABLE) : EV_DISABLE);
    EV_SET(&change, fd, EVFILT_WRITE, write_flags, 0, 0, nullptr);
    if (kevent(event_fd_.Get(), &change, 1, nullptr, 0, nullptr) != 0 && (enable_write || errno != ENOENT)) {
        GetLogger().Error("Cannot set write interest for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#endif

    GetLogger().Debug("Set events for fd {}: write {}", fd, enable_write);
    return true;
}

bool EventLoopDispatcher::RemoveEvents(int fd) noexcept {
    if (!event_fd_) {
        GetLogger().Error("Cannot remove events for fd {}: event queue is invalid", fd);
        return false;
    }

#if defined(__linux__)
    // ENOENT is benign: the kernel auto-removes a closed fd, so a DEL issued after the owner already
    // closed it hits ENOENT (matching the kqueue branch below). Any other failure is a real error.
    if (epoll_ctl(event_fd_.Get(), EPOLL_CTL_DEL, fd, nullptr) != 0 && errno != ENOENT) {
        GetLogger().Error("Cannot remove events for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#else
    // Delete both filters. A filter can be absent — the write filter if write was never armed, or
    // either one if the fd was already closed (kqueue auto-removes a closed fd's filters) — so an
    // EV_DELETE returning ENOENT is benign; any other failure is a real error.
    bool ok = true;
    for (const auto filter : {EVFILT_READ, EVFILT_WRITE}) {
        struct kevent change{};
        EV_SET(&change, fd, static_cast<int16_t>(filter), EV_DELETE, 0, 0, nullptr);
        if (kevent(event_fd_.Get(), &change, 1, nullptr, 0, nullptr) != 0 && errno != ENOENT) {
            GetLogger().Error("Cannot remove events for fd {}: {}", fd, Error::FromErrno());
            ok = false;
        }
    }
    if (!ok) {
        return false;
    }
#endif

    GetLogger().Debug("Removed events for fd {}", fd);
    return true;
}

} // namespace reflector
