#include "dispatcher.h"

#include <utility>

namespace reflector {

DispatcherRegistration::DispatcherRegistration(Dispatcher* dispatcher, int fd) noexcept
        : dispatcher_{dispatcher}, fd_{fd} {}

DispatcherRegistration::~DispatcherRegistration() noexcept {
    Reset();
}

DispatcherRegistration::DispatcherRegistration(DispatcherRegistration&& other) noexcept
        : dispatcher_{std::exchange(other.dispatcher_, nullptr)}
        , fd_{std::exchange(other.fd_, -1)} {}

DispatcherRegistration& DispatcherRegistration::operator=(DispatcherRegistration&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    Reset();
    dispatcher_ = std::exchange(other.dispatcher_, nullptr);
    fd_ = std::exchange(other.fd_, -1);
    return *this;
}

bool DispatcherRegistration::IsValid() const noexcept {
    return dispatcher_ != nullptr && fd_ >= 0;
}

bool DispatcherRegistration::Reset() noexcept {
    if (dispatcher_ == nullptr || fd_ < 0) {
        dispatcher_ = nullptr;
        fd_ = -1;
        return false;
    }
    auto* dispatcher = std::exchange(dispatcher_, nullptr);
    const auto fd = std::exchange(fd_, -1);
    return dispatcher->Unregister(fd);
}

DispatcherRegistration Dispatcher::MakeRegistration(int fd) noexcept {
    return DispatcherRegistration{this, fd};
}

} // namespace reflector
