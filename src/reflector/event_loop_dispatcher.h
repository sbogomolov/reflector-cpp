#pragma once

#include "dispatcher.h"
#include "util/no_move.h"

#include <chrono>
#include <csignal>
#include <cstddef>
#include <unordered_map>

namespace reflector {

// A minimal readiness reactor over kqueue (macOS) / epoll (Linux): callers register a callback per
// fd, and Run/PollOnce invoke it whenever that fd becomes readable. One callback per fd; the fd is
// the key. The production implementation of the Dispatcher interface.
class EventLoopDispatcher : public Dispatcher, NoMove {
public:
    EventLoopDispatcher();
    ~EventLoopDispatcher() noexcept override;

    [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override;

    void Run(const volatile std::sig_atomic_t& stop_requested) override;
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class EventLoopDispatcherTest;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

    [[nodiscard]] bool AddReadEvent(int fd) noexcept;
    [[nodiscard]] bool RemoveReadEvent(int fd) noexcept;
    bool Unregister(int fd) noexcept override;

    // fd -> callback. The kernel reports the ready fd (kqueue ident / epoll data.fd) and we
    // look the callback up here rather than stashing a pointer in the event's user-data: a
    // stale event for an already-unregistered fd then fails the lookup safely instead of
    // dereferencing freed state — which a batched read could otherwise deliver.
    std::unordered_map<int, OnReadableCallback> callbacks_;
    int event_fd_ = -1;
};

} // namespace reflector
