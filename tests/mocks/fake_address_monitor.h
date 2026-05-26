#pragma once

#include "reflector/address_monitor.h"

namespace reflector {

// Fake AddressMonitor: stands in for the real netlink/route monitor so an owner can be wired
// without opening a kernel socket. Start() simply succeeds.
class FakeAddressMonitor : public AddressMonitor {
public:
    [[nodiscard]] bool Start(const OnInterfaceChanged& /*on_change*/) noexcept override { return true; }
};

} // namespace reflector
