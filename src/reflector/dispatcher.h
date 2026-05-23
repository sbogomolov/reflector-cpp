#pragma once

#include "util/delegate.h"
#include "util/no_copy.h"

namespace reflector {

class Dispatcher;

// Invoked with the fd that became readable. EventLoopDispatcher binds one of these per watched
// fd; subscribers (e.g. DefaultPacketDispatcher, the interface-address monitor) bind their own.
using OnReadableCallback = Delegate<void(int)>;

// RAII handle for one fd registration. Resetting it (or destroying it) unregisters the callback
// from the dispatcher that issued it. Movable, non-copyable. Must not outlive that dispatcher.
class DispatcherRegistration : NoCopy {
public:
    DispatcherRegistration() noexcept = default;
    ~DispatcherRegistration() noexcept;

    DispatcherRegistration(DispatcherRegistration&& other) noexcept;
    DispatcherRegistration& operator=(DispatcherRegistration&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept;
    bool Reset() noexcept;

private:
    friend class Dispatcher;

    DispatcherRegistration(Dispatcher* dispatcher, int fd) noexcept;

    Dispatcher* dispatcher_ = nullptr;
    int fd_ = -1;
};

// A readiness reactor: callers register a callback per fd and are invoked whenever that fd becomes
// readable. It knows nothing about packets — subscribers layer their own parse/filter logic on
// top. EventLoopDispatcher is the production implementation (kqueue/epoll); tests substitute a fake.
class Dispatcher {
public:
    virtual ~Dispatcher() noexcept = default;

    // Watches `fd` for readability and invokes `on_readable(fd)` whenever it has data; one
    // registration per fd (re-registering an already-watched fd fails). The returned registration
    // must not outlive this dispatcher.
    [[nodiscard]] virtual DispatcherRegistration Register(int fd, const OnReadableCallback& on_readable) = 0;

protected:
    // Implementations mint the RAII handle for a freshly watched fd through this; the registration
    // constructor is otherwise private.
    [[nodiscard]] DispatcherRegistration MakeRegistration(int fd) noexcept;

private:
    friend class DispatcherRegistration;

    virtual bool Unregister(int fd) noexcept = 0;
};

} // namespace reflector
