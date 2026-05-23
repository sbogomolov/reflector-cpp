#pragma once

#include "util/delegate.h"
#include "util/registration.h"

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

    virtual ~Dispatcher() noexcept = default;

    // Watches `fd` for readability and invokes `on_readable(fd)` whenever it has data; one
    // registration per fd (re-registering an already-watched fd fails). The returned registration
    // must not outlive this dispatcher.
    [[nodiscard]] virtual Registration Register(int fd, const OnReadableCallback& on_readable) = 0;

protected:
    [[nodiscard]] Registration MakeRegistration(int fd) noexcept { return Registration{this, fd}; }

private:
    friend Registration;

    virtual bool Unregister(int fd) noexcept = 0;
};

} // namespace reflector
