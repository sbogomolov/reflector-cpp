#pragma once

#include "reflector/dispatcher.h"

#include <csignal>
#include <cstddef>
#include <unordered_map>

namespace reflector {

// Fake Dispatcher: records the per-fd callback a subscriber registers and lets a test fire it via
// FireReadable — standing in for the kqueue/epoll reactor with no real event queue. Mirrors the
// production contract (one callback per fd; re-registering a watched or invalid fd fails).
class FakeDispatcher : public Dispatcher {
public:
    [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override {
        if (fd < 0 || callbacks_.contains(fd)) {
            return {};
        }
        callbacks_.emplace(fd, on_readable);
        return MakeRegistration(fd);
    }

    // Tests drive readiness directly via FireReadable(), so the loop is never run.
    void Run(const volatile std::sig_atomic_t& /*stop_requested*/) override {}

    // Invokes the callback registered for `fd`, as the reactor would when `fd` becomes readable.
    void FireReadable(int fd) {
        const auto it = callbacks_.find(fd);
        if (it != callbacks_.end()) {
            it->second(fd);
        }
    }

    [[nodiscard]] bool IsWatching(int fd) const noexcept { return callbacks_.contains(fd); }
    [[nodiscard]] size_t RegistrationCount() const noexcept { return callbacks_.size(); }

private:
    bool Unregister(int fd) noexcept override { return callbacks_.erase(fd) > 0; }

    std::unordered_map<int, OnReadableCallback> callbacks_;
};

} // namespace reflector
