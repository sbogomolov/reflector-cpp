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

// Invoked with the fd that became writable. A non-blocking connect() signals completion by
// becoming writable, and a partially-drained send buffer flushes on the next writable. Write
// interest starts disarmed (see SetWriteInterest) so a readability-only consumer never sees it.
using OnWritableCallback = Delegate<void(int)>;

// A readiness reactor: callers register a callback per fd and are invoked whenever that fd becomes
// readable. It knows nothing about packets — subscribers layer their own parse/filter logic on
// top. EventLoopDispatcher is the production implementation (kqueue/epoll); tests substitute a fake.
class Dispatcher {
public:
    // RAII handle for one fd registration (keyed by the fd); resetting it unregisters the callback.
    using Registration = reflector::Registration<Dispatcher, int>;
    // Invoked when a periodic timer comes due, with the reactor's fire-cycle `now` — passed so the
    // callback reuses that one clock read (consistent across every timer fired in the cycle) instead
    // of reading the clock again.
    using OnTimerCallback = Delegate<void(std::chrono::steady_clock::time_point)>;
    // Strong id so a timer registration is never confused with the fd `int` registration. 0 is the
    // invalid sentinel; real ids start at 1.
    enum class TimerId : uint64_t {};

    // The read/write handlers for one watched fd. Read is REQUIRED and ALWAYS armed — an error/hangup
    // surfaces as readability (recv() reveals it), so the always-armed read handler is the uniform home
    // for teardown, and a never-zero interest mask means an errored fd can never busy-spin with nothing
    // armed. Write is OPTIONAL and the only flippable direction: a connecting socket sets
    // {.write_armed = true} to learn of connect-completion; a backed-up send buffer arms it to flush.
    struct FdCallbacks {
        OnReadableCallback read{};   // required; {} DMI keeps a designated init that omits `write` clean
        OnWritableCallback write{};  // under GCC's -Wmissing-field-initializers. Bool last: no padding
        bool write_armed = false;    // wasted between the two pointer-sized delegates.
    };

    virtual ~Dispatcher() noexcept = default;

    // Watches `fd` per `callbacks`: read (always armed) plus optional write per `write_armed`. Fails if
    // `callbacks.read` is unset (read is required) or `fd` is already watched (one registration per fd).
    // The returned registration must not outlive this dispatcher.
    [[nodiscard]] virtual Registration Register(int fd, FdCallbacks callbacks) = 0;

    // Readability-only convenience (no write handler) — the common case, unchanged for every existing
    // consumer. Non-virtual so the one pure virtual is the FdCallbacks form.
    [[nodiscard]] Registration Register(int fd, const OnReadableCallback& on_readable) {
        return Register(fd, FdCallbacks{.read = on_readable});
    }

    // Toggle writability notification for an already-registered fd (epoll EPOLL_CTL_MOD +/- EPOLLOUT;
    // kqueue EVFILT_WRITE EV_ENABLE/EV_DISABLE). Arm to learn when a non-blocking connect completes
    // or a backed-up send buffer can flush; disarm once it drains, to avoid a writable-spin on the
    // level-triggered reactor. Idempotent; returns false on an unknown fd.
    [[nodiscard]] virtual bool SetWriteInterest(int fd, bool enabled) noexcept = 0;


    // Runs the readiness loop until `stop_requested` becomes non-zero, dispatching each registered
    // callback as its fd becomes readable. (The production reactor blocks in the kernel between
    // events; a fake need not run a real loop.)
    virtual void Run(const volatile std::sig_atomic_t& stop_requested) = 0;

protected:
    [[nodiscard]] Registration MakeRegistration(int fd) noexcept { return Registration{this, fd}; }

private:
    friend Registration;
    // Timer is the RAII face of a timer registration: it holds one TimerId for its whole life and
    // (un)registers under it via Start/Stop, so the trio below stays private — a periodic timer is
    // only ever driven through a Timer (never a bare TimerId the caller must remember to release).
    friend class Timer;

    virtual bool Unregister(int fd) noexcept = 0;

    // AllocateTimerId reserves a unique id without registering anything (a Timer holds it for life).
    // RegisterTimer registers `callback` to fire every `interval` under that id, first dropping any
    // prior registration of the id (a re-register is a restart). It returns false on an id this
    // dispatcher never allocated, a non-positive interval (would busy-loop), or an unset callback (UB
    // to invoke). UnregisterTimer is a no-op for an unknown/already-removed id.
    [[nodiscard]] virtual TimerId AllocateTimerId() noexcept = 0;
    [[nodiscard]] virtual bool RegisterTimer(
        TimerId id, std::chrono::milliseconds interval, const OnTimerCallback& callback) = 0;
    virtual void UnregisterTimer(TimerId id) noexcept = 0;
};

} // namespace reflector
