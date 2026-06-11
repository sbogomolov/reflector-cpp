#pragma once

#include "interface.h"
#include "ip_address.h"
#include "logger.h"
#include "util/address_family_pair.h"

namespace reflector {

// Gates a reflector's per-family reflection on its interfaces' live send capability: the config's
// static family policy (uses / requires) ANDed with whether EVERY interface it tracks can send the
// family. A WoL-style reflector tracks one interface (its target); an mDNS/SSDP-style reflector
// tracks two (source and target) and reflects a family only when both can send it. Observe() emits
// one-shot transition notices when a family's combined capability flips — regained → Info; lost →
// Error when the config requires the family (reflection is broken until an address returns), Info
// when it merely uses it.
class FamilyCapability {
public:
    // Per-family config policy. Requiring a family implies using it. (`required`, not the
    // natural `requires` — that's a keyword.)
    struct Policy {
        AddressFamilyPair<bool> uses;
        AddressFamilyPair<bool> required;
    };

    // Snapshots the policy of any of the per-protocol configs (they share the Uses/Requires shape).
    template <class Config>
    [[nodiscard]] static Policy PolicyOf(const Config& config) noexcept {
        return Policy{
            .uses = {config.UsesIPv4(), config.UsesIPv6()},
            .required = {config.RequiresIPv4(), config.RequiresIPv6()},
        };
    }

    // Tracks one interface (e.g. WoL's target). `iface` and `logger` (the owning reflector's, so
    // notices carry its prefix) must outlive this object.
    FamilyCapability(const Interface& iface, Logger& logger, Policy policy);
    // Tracks the COMBINED capability of two interfaces (e.g. mDNS/SSDP source + target): a family
    // is sendable only when BOTH can send it. All three references must outlive this object.
    FamilyCapability(const Interface& first, const Interface& second, Logger& logger, Policy policy);

    // Re-reads both families' combined capability and logs a notice for each flip. The owner calls
    // this when an interface's addresses may have changed (Reflector::OnInterfaceChanged).
    void Observe() noexcept;

    // True if the config uses `family` and every tracked interface can currently send it.
    [[nodiscard]] bool CanSend(IpAddress::Family family) const noexcept;

private:
    // Delegated-to ctor; `second` is null when only one interface is tracked.
    FamilyCapability(const Interface* first, const Interface* second, Logger& logger, Policy policy) noexcept;

    template <IpAddress::Family family>
    void ObserveFamily() noexcept;

    const Interface* first_;
    const Interface* second_;  // null for a single-interface tracker
    Logger* logger_;
    Policy policy_;
    // Combined capability when last observed, for the one-shot notices; CanSend reads live.
    AddressFamilyPair<bool> can_send_;
};

} // namespace reflector
