#include "event_loop_dispatcher.h"

#include "error.h"
#include "logger.h"

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <vector>
#include <unistd.h>

#if !defined(__APPLE__) && !defined(__linux__)
#error "EventLoopDispatcher only supports macOS and Linux"
#endif

#if defined(__APPLE__)
#include <sys/event.h>
#elif defined(__linux__)
#include <sys/epoll.h>
#endif

namespace {

using namespace reflector;

#if defined(__APPLE__)
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
#if defined(__APPLE__)
    event_fd_ = kqueue();
#elif defined(__linux__)
    event_fd_ = epoll_create1(0);
#endif

    if (event_fd_ < 0) {
        GetLogger().Error("Cannot create dispatcher event queue: {}", Error::FromErrno());
    } else {
        GetLogger().Debug("Created dispatcher event queue fd {}", event_fd_);
    }
}

EventLoopDispatcher::~EventLoopDispatcher() noexcept {
    if (!callbacks_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} fd callback registration(s) still active", callbacks_.size());
    }
    if (!timers_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} timer registration(s) still active", timers_.size());
    }

    if (event_fd_ >= 0) {
        GetLogger().Debug("Closing dispatcher event queue fd {}", event_fd_);
        close(event_fd_);
        event_fd_ = -1;
    }
}

Dispatcher::Registration EventLoopDispatcher::Register(int fd, const OnReadableCallback& on_readable) {
    if (fd < 0) {
        GetLogger().Error("Cannot register fd callback: fd is invalid");
        return {};
    }
    if (callbacks_.contains(fd)) {
        GetLogger().Error("Cannot register fd callback: a callback for fd {} is already registered", fd);
        return {};
    }
    if (!AddReadEvent(fd)) {
        GetLogger().Error("Cannot register fd callback: read event registration failed for fd {}", fd);
        return {};
    }

    callbacks_.emplace(fd, on_readable);
    GetLogger().Debug("Registered fd callback for fd {}", fd);
    return MakeRegistration(fd);
}

bool EventLoopDispatcher::Unregister(int fd) noexcept {
    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Warning("Cannot unregister fd callback for fd {}: not found", fd);
        return false;
    }

    callbacks_.erase(it);
    if (!RemoveReadEvent(fd)) {
        GetLogger().Error("Cannot remove read event for fd {} after unregistering its callback", fd);
    }

    GetLogger().Debug("Unregistered fd callback for fd {}", fd);
    return true;
}

void EventLoopDispatcher::Run(const volatile std::sig_atomic_t& stop_requested) {
    GetLogger().Info("Starting dispatcher event loop");
    if (event_fd_ < 0) {
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
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot poll dispatcher: event queue is invalid");
        return false;
    }

#if defined(__APPLE__)
    auto timeout_spec = ToTimespec(timeout);
    struct kevent event{};
    const auto event_count = kevent(event_fd_, nullptr, 0, &event, 1, &timeout_spec);
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
#elif defined(__linux__)
    epoll_event event{};
    const auto event_count = epoll_wait(event_fd_, &event, 1, static_cast<int>(timeout.count()));
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
    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
        GetLogger().Error("Dispatcher read event failed for fd {} (events: {:#x})", fd, events);
        return false;
    }
#endif

    const auto it = callbacks_.find(fd);
    if (it == callbacks_.end()) {
        GetLogger().Warning("Dispatcher woke for unwatched fd {}", fd);
        return false;
    }
    // Copy the callback before invoking: it may unregister this fd (erasing the map entry),
    // which would otherwise dangle the reference we are calling through.
    auto on_readable = it->second;
    on_readable(fd);
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
    UnregisterTimer(id);  // restart: a re-register under the same id replaces the prior registration
    if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
        GetLogger().Error("Cannot register timer: non-positive interval or invalid callback");
        return false;
    }
    timers_.push_back(TimerEntry{
        .id = id,
        .interval = interval,
        .next = std::chrono::steady_clock::now() + interval,
        .callback = callback,
    });
    GetLogger().Debug("Registered timer {} (interval {}ms); {} active",
        static_cast<uint64_t>(id), interval.count(), timers_.size());
    return true;
}

void EventLoopDispatcher::UnregisterTimer(TimerId id) noexcept {
    if (std::erase_if(timers_, [id](const TimerEntry& entry) { return entry.id == id; }) > 0) {
        GetLogger().Debug("Unregistered timer {}; {} active", static_cast<uint64_t>(id), timers_.size());
    }
}

void EventLoopDispatcher::FireDueTimers(std::chrono::steady_clock::time_point now) {
    // Walk timers_ live (no snapshot): a callback may RegisterTimer (append, possibly reallocating)
    // or UnregisterTimer (erase, shifting elements), so after each fire we re-check that our slot
    // still holds the entry we fired (by id) and restart from the front otherwise — the same merge
    // walk DispatchPacket uses. Rescheduling a fired timer to now + interval (before invoking) makes
    // it no longer due, so a restart never re-fires it: that reschedule is the timer equivalent of
    // DispatchPacket's last_dispatched_id. A timer unregistered by an earlier callback in the round
    // is simply gone from timers_, so it is correctly not fired (a snapshot would fire it anyway).
    for (size_t idx = 0; idx < timers_.size();) {
        TimerEntry& entry = timers_[idx];
        if (entry.next <= now) {
            const auto id = entry.id;
            entry.next = now + entry.interval;  // forward from now; never += interval (no backlog spin)
            entry.callback(now);  // may mutate timers_; entry's pointers are loaded before the call

            if (idx >= timers_.size() || timers_[idx].id != id) {
                idx = 0;
                continue;
            }
        }
        ++idx;
    }
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

bool EventLoopDispatcher::AddReadEvent(int fd) noexcept {
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot add read event for fd {}: event queue is invalid", fd);
        return false;
    }

#if defined(__APPLE__)
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot add read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#elif defined(__linux__)
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = fd;
    if (epoll_ctl(event_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
        if (errno == EEXIST) {
            GetLogger().Debug("Read event already registered for fd {}", fd);
            return true;
        }
        GetLogger().Error("Cannot add read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#endif

    GetLogger().Debug("Registered read event for fd {}", fd);
    return true;
}

bool EventLoopDispatcher::RemoveReadEvent(int fd) noexcept {
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot remove read event for fd {}: event queue is invalid", fd);
        return false;
    }

#if defined(__APPLE__)
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot remove read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#elif defined(__linux__)
    if (epoll_ctl(event_fd_, EPOLL_CTL_DEL, fd, nullptr) != 0) {
        GetLogger().Error("Cannot remove read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#endif

    GetLogger().Debug("Removed read event for fd {}", fd);
    return true;
}

} // namespace reflector
