#pragma once

#include "reflector/address_monitor.h"

#include <array>
#include <span>

namespace reflector {

// Fake AddressMonitor: stands in for the real netlink/route monitor so an owner can be wired
// without opening a kernel socket. It records the callback Start() is given and lets a test drive
// it via FireChange; `start_succeeds` makes Start() report failure so the owner's fallback path
// can be exercised.
class FakeAddressMonitor : public AddressMonitor {
public:
    [[nodiscard]] bool Start(const OnInterfacesChanged& on_change) noexcept override {
        on_change_ = on_change;
        return start_succeeds;
    }

    // Invokes the subscribed callback as one drain of kernel notifications would.
    void FireChanges(std::span<const unsigned> indexes, bool refresh_all = false) {
        if (on_change_.IsValid()) {
            on_change_(indexes, refresh_all);
        }
    }

    // The single-interface drain, which is what most tests want.
    void FireChange(unsigned interface_index) {
        const std::array indexes{interface_index};
        FireChanges(indexes);
    }

    // The drain that lost notifications and so can only say "re-resolve everything".
    void FireOverflow() { FireChanges({}, true); }

    // True once Start() has been given a bound callback.
    [[nodiscard]] bool Started() const noexcept { return on_change_.IsValid(); }

    bool start_succeeds = true;

private:
    OnInterfacesChanged on_change_;
};

} // namespace reflector
