#pragma once

#include "reflector/address_monitor.h"

namespace reflector {

// Fake AddressMonitor: stands in for the real netlink/route monitor so an owner can be wired
// without opening a kernel socket. It records the callback Start() is given and lets a test drive
// it via FireChange; `start_succeeds` makes Start() report failure so the owner's fallback path
// can be exercised.
class FakeAddressMonitor : public AddressMonitor {
public:
    [[nodiscard]] bool Start(const OnInterfaceChanged& on_change) noexcept override {
        on_change_ = on_change;
        return start_succeeds;
    }

    // Invokes the subscribed callback as a kernel address-change notification would.
    void FireChange(unsigned interface_index) {
        if (on_change_.IsValid()) {
            on_change_(interface_index);
        }
    }

    // True once Start() has been given a bound callback.
    [[nodiscard]] bool Started() const noexcept { return on_change_.IsValid(); }

    bool start_succeeds = true;

private:
    OnInterfaceChanged on_change_;
};

} // namespace reflector
