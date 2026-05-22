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
    WolListener* listener;
    PacketDispatcher::Registration dispatcher_reg;
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

WolListener::WolListener(PacketDispatcher& packet_dispatcher, RawSocket& capture)
        : packet_dispatcher_{&packet_dispatcher}, capture_{&capture} {}

WolListener::~WolListener() noexcept {
    if (!registrations_.empty()) {
        GetLogger().Error("Destroying wol listener on interface \"{}\" with {} callback registration(s) still active",
            capture_->Interface(), registrations_.size());
    }
    while (!registrations_.empty()) {
        Unregister(registrations_.back());
    }
}

WolListener::Registration WolListener::Register(uint16_t port, const PacketCallback& callback) {
    if (port == 0) {
        GetLogger().Error("Cannot register wol callback on interface \"{}\": port 0 is invalid", capture_->Interface());
        return Registration{};
    }

    PacketFilter filter{.dest_port = port};
    auto dispatcher_reg = packet_dispatcher_->Register(*capture_, filter, callback);
    if (!dispatcher_reg.IsValid()) {
        GetLogger().Error("Cannot register wol callback on interface \"{}\" port {}: dispatcher registration failed",
            capture_->Interface(), port);
        return Registration{};
    }

    GetLogger().Debug("Registered wol callback on interface \"{}\" port {}", capture_->Interface(), port);
    auto registration_entry = SharedPtrUnsynchronized<RegistrationEntry>{
        new RegistrationEntry{this, std::move(dispatcher_reg), port}};
    Registration registration{registration_entry};
    registrations_.push_back(std::move(registration_entry));
    return registration;
}

bool WolListener::Unregister(SharedPtrUnsynchronized<RegistrationEntry> registration) noexcept {
    if (!registration) {
        return false;
    }

    const auto it = std::ranges::find(registrations_, registration);
    if (it == registrations_.end()) {
        GetLogger().Warning("Cannot unregister wol callback on interface \"{}\" port {}: not found",
            capture_->Interface(), registration->port);
        return false;
    }

    // Pass-by-value above keeps the entry alive through the erase below — callers (e.g.
    // ~WolListener) typically hand us a SharedPtr stored *in* registrations_, and erasing
    // it would otherwise drop the last strong ref and free the entry under our feet.
    registration->dispatcher_reg.Reset();
    registrations_.erase(it);
    return true;
}

} // namespace reflector
