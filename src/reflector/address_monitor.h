#pragma once

#include "util/delegate.h"

#include <span>

namespace reflector {

// Watches the kernel for interface address changes and reports the affected interface index, so a
// long-running daemon can refresh its cached source addresses (e.g. once an IPv6 address finishes
// DAD, or on DHCP renewal). DefaultAddressMonitor is the production implementation; tests
// substitute a fake. The owner constructs the monitor, then calls Start() once with a callback —
// watching begins there, so the owner can bind a callback into itself first.
class AddressMonitor {
public:
    // Invoked once per drain of the kernel's notification socket, with the indexes whose addresses
    // changed. `refresh_all` means the drain could not deliver a list — notifications were dropped
    // (kernel buffer overflow), or more interfaces changed than one drain can carry — so every
    // interface must be re-resolved and `indexes` is empty. One call per drain rather than one per
    // index: a burst commonly names several, and the work a subscriber does per call is not
    // proportional to how many it names.
    using OnInterfacesChanged = Delegate<void(std::span<const unsigned> indexes, bool refresh_all)>;

    virtual ~AddressMonitor() noexcept = default;

    // Begin watching for interface address changes, delivering each drain's changed indexes to
    // `on_change`. Call exactly once, after construction. Returns false (after logging the cause)
    // if the monitor could not start watching; whether to proceed without it is the caller's call.
    [[nodiscard]] virtual bool Start(const OnInterfacesChanged& on_change) noexcept = 0;
};

} // namespace reflector
