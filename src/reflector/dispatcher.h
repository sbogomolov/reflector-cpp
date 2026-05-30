#pragma once

#include "util/delegate.h"
#include "util/registration.h"

#include <chrono>
#include <csignal>
#include <cstdint>

namespace reflector {

// Invoked with the fd that became readable. EventLoopDispatcher binds one of these per watched
// fd; subscribers (e.g. DefaultPacketDispatcher, the interface-address monitor) bind their own.
using OnReadableCallback = Delegate<void(int)>;

// A readiness reactor: callers register a callback per fd and are invoked whenever that fd becomes
// readable. It knows nothing about packets — subscribers layer their own parse/filter logic on
// top. EventLoopDispatcher is the production implementation (kqueue/epoll); tests substitute a fake.
class Dispatcher {
public:
    // RAII handle for one fd registration (keyed by the fd); resetting it unregisters the callback.
    using Registration = reflector::Registration<Dispatcher, int>;
    using OnTimerCallback = Delegate<void()>;
    // Strong id so a timer registration is never confused with the fd `int` registration. 0 is the
    // invalid sentinel; real ids start at 1.
    enum class TimerId : uint64_t {};

    virtual ~Dispatcher() noexcept = default;

    // Watches `fd` for readability and invokes `on_readable(fd)` whenever it has data; one
    // registration per fd (re-registering an already-watched fd fails). The returned registration
    // must not outlive this dispatcher.
    [[nodiscard]] virtual Registration Register(int fd, const OnReadableCallback& on_readable) = 0;

    // Runs the readiness loop until `stop_requested` becomes non-zero, dispatching each registered
    // callback as its fd becomes readable. (The production reactor blocks in the kernel between
    // events; a fake need not run a real loop.)
    virtual void Run(const volatile std::sig_atomic_t& stop_requested) = 0;

protected:
    [[nodiscard]] Registration MakeRegistration(int fd) noexcept { return Registration{this, fd}; }

private:
    friend Registration;
    // Timer is the RAII face of the timer registration: it calls RegisterTimer on construction and
    // UnregisterTimer on destruction, so the raw pair below stays private — a periodic timer is only
    // ever obtained as a Timer (never a bare TimerId the caller must remember to release).
    friend class Timer;

    virtual bool Unregister(int fd) noexcept = 0;

    // RegisterTimer rejects interval <= 0 / an invalid callback by returning TimerId{} (a
    // non-positive interval would busy-loop and an unset Delegate is UB to invoke); UnregisterTimer
    // is a no-op for an unknown/already-removed id.
    [[nodiscard]] virtual TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) = 0;
    virtual void UnregisterTimer(TimerId id) noexcept = 0;
};

} // namespace reflector
