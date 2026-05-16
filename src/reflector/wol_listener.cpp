#include "wol_listener.h"

#include "logger.h"

#include <algorithm>
#include <utility>

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"WolListener"};
    return logger;
}

} // namespace

struct WolListener::RegistrationEntry {
    RegistrationEntry(WolListener& listener, Dispatcher::Registration dispatcher_reg, uint16_t port) noexcept
            : listener{&listener}, dispatcher_reg{std::move(dispatcher_reg)}, port{port} {}

    WolListener* listener;
    Dispatcher::Registration dispatcher_reg;
    uint16_t port;
};

WolListener::Registration::Registration(WeakPtrUnsynchronized<RegistrationEntry> registration_entry) noexcept
        : registration_entry_{std::move(registration_entry)} {}

WolListener::Registration::~Registration() noexcept {
    Reset();
}

WolListener::Registration::Registration(Registration&& other) noexcept
        : registration_entry_{std::move(other.registration_entry_)} {}

WolListener::Registration& WolListener::Registration::operator=(Registration&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Reset();
    registration_entry_ = std::move(other.registration_entry_);
    return *this;
}

bool WolListener::Registration::IsValid() const noexcept {
    const auto registration = registration_entry_.lock();
    return registration && registration->dispatcher_reg.IsValid();
}

bool WolListener::Registration::Reset() noexcept {
    const auto registration = registration_entry_.lock();
    if (!registration) {
        registration_entry_.reset();
        return false;
    }

    registration_entry_.reset();
    return registration->listener->Unregister(registration);
}

WolListener::WolListener(Dispatcher& dispatcher, std::string_view interface, IpAddress::Family family)
        : dispatcher_{&dispatcher}, interface_{interface}, family_{family} {}

WolListener::~WolListener() noexcept {
    if (!registrations_.empty()) {
        GetLogger().Error("Destroying wol listener on interface \"{}\" with {} callback registration(s) still active",
            interface_, registrations_.size());
    }
    while (!registrations_.empty()) {
        Unregister(registrations_.back());
    }

    if (!listeners_.empty()) {
        GetLogger().Error("Destroying wol listener on interface \"{}\" with {} UDP port listener(s) still active",
            interface_, listeners_.size());
    }
}

WolListener::Registration WolListener::Register(uint16_t port, const PacketCallback& callback) {
    if (port == 0) {
        GetLogger().Error("Cannot register wol callback on interface \"{}\": port 0 is invalid", interface_);
        return Registration{};
    }

    const auto fd = AcquirePort(port);
    if (fd < 0) {
        GetLogger().Error("Cannot register wol callback on interface \"{}\": listener setup failed for port {}",
            interface_, port);
        return Registration{};
    }

    auto dispatcher_reg = dispatcher_->Register(fd, PacketFilter{}, callback);
    if (!dispatcher_reg.IsValid()) {
        GetLogger().Error("Cannot register wol callback on interface \"{}\" port {}: dispatcher registration failed",
            interface_, port);
        ReleasePort(port);
        return Registration{};
    }

    GetLogger().Debug("Registered wol callback on interface \"{}\" port {}", interface_, port);
    auto registration_entry = SharedPtrUnsynchronized<RegistrationEntry>{
        new RegistrationEntry{*this, std::move(dispatcher_reg), port}};
    Registration registration{registration_entry};
    registrations_.push_back(std::move(registration_entry));
    return registration;
}

int WolListener::AcquirePort(uint16_t port) {
    const auto it = std::ranges::find_if(listeners_, [port](const auto& entry) {
        return entry.port == port;
    });
    if (it != listeners_.end()) {
        ++it->refcount;
        return it->listener.Socket().Fd();
    }

    UdpListener listener{UdpListener::Options{
        .interface = interface_,
        .local_ip = family_ == IpAddress::Family::V6 ? IpAddress::AnyV6() : IpAddress::AnyV4(),
        .local_port = port,
    }};
    if (!listener.IsValid()) {
        GetLogger().Error("Cannot create UDP listener on interface \"{}\" port {}", interface_, port);
        return -1;
    }

    listeners_.push_back(PortListener{
        .listener = std::move(listener),
        .refcount = 1,
        .port = port,
    });
    GetLogger().Debug("Created UDP listener on interface \"{}\" port {}", interface_, port);
    return listeners_.back().listener.Socket().Fd();
}

void WolListener::ReleasePort(uint16_t port) noexcept {
    const auto it = std::ranges::find_if(listeners_, [port](const auto& entry) {
        return entry.port == port;
    });
    if (it == listeners_.end()) {
        GetLogger().Warning("Cannot release UDP listener on interface \"{}\" port {}: not found", interface_, port);
        return;
    }

    if (--it->refcount > 0) {
        return;
    }

    GetLogger().Debug("Removing UDP listener on interface \"{}\" port {}", interface_, port);
    listeners_.erase(it);
}

bool WolListener::Unregister(SharedPtrUnsynchronized<RegistrationEntry> registration) noexcept {
    if (!registration) {
        return false;
    }

    const auto it = std::ranges::find(registrations_, registration);
    if (it == registrations_.end()) {
        GetLogger().Warning("Cannot unregister wol callback on interface \"{}\" port {}: not found",
            interface_, registration->port);
        return false;
    }

    // Pass-by-value above keeps the entry alive through the erase below — callers (e.g.
    // ~WolListener) typically hand us a SharedPtr stored *in* registrations_, and erasing
    // it would otherwise drop the last strong ref and free the entry under our feet.
    // Tear down the dispatcher registration before releasing the port: the last release may
    // destroy the underlying UdpListener, and the dispatcher must not still hold its fd.
    registration->dispatcher_reg.Reset();
    registrations_.erase(it);
    ReleasePort(registration->port);
    return true;
}

} // namespace reflector
