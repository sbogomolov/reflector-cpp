#pragma once

#include "util/delegate.h"
#include "util/no_copy.h"
#include "util/no_move.h"

#include <chrono>
#include <csignal>
#include <cstddef>
#include <unordered_map>

namespace reflector {

// Invoked with the fd that became readable. DefaultPacketDispatcher binds one of these per capture
// socket; other readable fds (e.g. the interface-address monitor) bind their own.
using OnReadableCallback = Delegate<void(int)>;

// A minimal readiness reactor over kqueue (macOS) / epoll (Linux): callers register a
// callback per fd, and Run/PollOnce invoke it whenever that fd becomes readable. It knows
// nothing about packets — DefaultPacketDispatcher layers the capture/parse/filter logic on top by
// registering one fd callback per capture socket. One callback per fd; the fd is the key.
class Dispatcher : NoMove {
public:
    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration() noexcept;

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept;
        bool Reset() noexcept;

    private:
        friend class Dispatcher;

        Registration(Dispatcher* dispatcher, int fd) noexcept;

        Dispatcher* dispatcher_ = nullptr;
        int fd_ = -1;
    };

    Dispatcher();
    ~Dispatcher() noexcept;

    // Watches `fd` for readability and invokes `on_readable(fd)` whenever it has data; one
    // registration per fd (re-registering an already-watched fd fails). The returned
    // Registration must not outlive this Dispatcher — its destructor unregisters through a
    // raw pointer, and the owning subscriber is always torn down before the Dispatcher.
    [[nodiscard]] Registration Register(int fd, const OnReadableCallback& on_readable);

    void Run(const volatile std::sig_atomic_t& stop_requested);
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class DispatcherTest;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

    [[nodiscard]] bool AddReadEvent(int fd) noexcept;
    [[nodiscard]] bool RemoveReadEvent(int fd) noexcept;
    bool Unregister(int fd) noexcept;

    // fd -> callback. The kernel reports the ready fd (kqueue ident / epoll data.fd) and we
    // look the callback up here rather than stashing a pointer in the event's user-data: a
    // stale event for an already-unregistered fd then fails the lookup safely instead of
    // dereferencing freed state — which a batched read could otherwise deliver.
    std::unordered_map<int, OnReadableCallback> callbacks_;
    int event_fd_ = -1;
};

} // namespace reflector
