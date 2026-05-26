#pragma once

#include "util/delegate.h"

namespace reflector {

// Watches the kernel for interface address changes and reports the affected interface index, so a
// long-running daemon can refresh its cached source addresses (e.g. once an IPv6 address finishes
// DAD, or on DHCP renewal). DefaultAddressMonitor is the production implementation; tests
// substitute a fake. The owner constructs the monitor, then calls Start() once with a callback —
// watching begins there, so the owner can bind a callback into itself first.
class AddressMonitor {
public:
    // Invoked with the index of an interface whose addresses changed, or 0 ("all interfaces")
    // when notifications may have been dropped (kernel buffer overflow) and everything should be
    // re-resolved. Kernel interface indices are >= 1, so 0 is an unambiguous sentinel.
    using OnInterfaceChanged = Delegate<void(unsigned interface_index)>;

    virtual ~AddressMonitor() noexcept = default;

    // Begin watching for interface address changes, delivering each changed interface index to
    // `on_change`. Call exactly once, after construction. Returns false (after logging the cause)
    // if the monitor could not start watching; whether to proceed without it is the caller's call.
    [[nodiscard]] virtual bool Start(const OnInterfaceChanged& on_change) noexcept = 0;
};

} // namespace reflector
