#include "wol_listener.h"

#include <algorithm>
#include <utility>

namespace reflector {

WolListener::Registration::Registration(
    WolListener& listener, Dispatcher::Registration dispatcher_reg, uint16_t port) noexcept
        : listener_{&listener}, dispatcher_reg_{std::move(dispatcher_reg)}, port_{port} {}

WolListener::Registration::~Registration() noexcept {
    Reset();
}

WolListener::Registration::Registration(Registration&& other) noexcept
        : listener_{std::exchange(other.listener_, nullptr)}
        , dispatcher_reg_{std::move(other.dispatcher_reg_)}
        , port_{std::exchange(other.port_, 0)} {}

WolListener::Registration& WolListener::Registration::operator=(Registration&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Reset();
    listener_ = std::exchange(other.listener_, nullptr);
    dispatcher_reg_ = std::move(other.dispatcher_reg_);
    port_ = std::exchange(other.port_, 0);
    return *this;
}

bool WolListener::Registration::Reset() noexcept {
    if (listener_ == nullptr) {
        return false;
    }

    // Tear down the dispatcher registration before releasing the port: the last release may
    // destroy the underlying UdpListener, and the dispatcher must not still hold its fd.
    dispatcher_reg_.Reset();
    auto* listener = std::exchange(listener_, nullptr);
    const auto port = std::exchange(port_, 0);
    listener->ReleasePort(port);
    return true;
}

WolListener::WolListener(Dispatcher& dispatcher, std::string_view interface)
        : dispatcher_{&dispatcher}, interface_{interface} {}

WolListener::~WolListener() noexcept {
    if (!listeners_.empty()) {
        logger_.Error("Destroying wol listener on interface \"{}\" with {} UDP port listener(s) still active",
            interface_, listeners_.size());
    }
}

WolListener::Registration WolListener::Register(uint16_t port, const PacketCallback& callback) {
    if (port == 0) {
        logger_.Error("Cannot register wol callback on interface \"{}\": port 0 is invalid", interface_);
        return Registration{};
    }

    auto* port_listener = AcquirePort(port);
    if (port_listener == nullptr) {
        logger_.Error("Cannot register wol callback on interface \"{}\": listener setup failed for port {}",
            interface_, port);
        return Registration{};
    }

    auto dispatcher_reg = dispatcher_->Register(port_listener->listener.Socket(), PacketFilter{}, callback);
    if (!dispatcher_reg.IsValid()) {
        logger_.Error("Cannot register wol callback on interface \"{}\" port {}: dispatcher registration failed",
            interface_, port);
        ReleasePort(port);
        return Registration{};
    }

    logger_.Debug("Registered wol callback on interface \"{}\" port {}", interface_, port);
    return Registration{*this, std::move(dispatcher_reg), port};
}

WolListener::PortListener* WolListener::AcquirePort(uint16_t port) {
    const auto it = std::ranges::find_if(listeners_, [port](const auto& entry) {
        return entry.port == port;
    });
    if (it != listeners_.end()) {
        ++it->refcount;
        return &*it;
    }

    UdpListener listener{UdpListener::Options{
        .interface = interface_,
        .local_ip = IpAddress::Any(),
        .local_port = port,
    }};
    if (!listener.IsValid()) {
        logger_.Error("Cannot create UDP listener on interface \"{}\" port {}", interface_, port);
        return nullptr;
    }

    listeners_.push_back(PortListener{
        .listener = std::move(listener),
        .refcount = 1,
        .port = port,
    });
    logger_.Debug("Created UDP listener on interface \"{}\" port {}", interface_, port);
    return &listeners_.back();
}

void WolListener::ReleasePort(uint16_t port) noexcept {
    const auto it = std::ranges::find_if(listeners_, [port](const auto& entry) {
        return entry.port == port;
    });
    if (it == listeners_.end()) {
        logger_.Warning("Cannot release UDP listener on interface \"{}\" port {}: not found", interface_, port);
        return;
    }

    if (--it->refcount > 0) {
        return;
    }

    logger_.Debug("Removing UDP listener on interface \"{}\" port {}", interface_, port);
    listeners_.erase(it);
}

} // namespace reflector
