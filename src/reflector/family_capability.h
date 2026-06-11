#pragma once

#include "interface.h"
#include "ip_address.h"
#include "logger.h"
#include "util/address_family_pair.h"

#include <string_view>

namespace reflector {

// Gates a reflector's per-family use of a borrowed Interface: the config's static family policy
// (uses / requires) ANDed with the interface's live send capability, plus one-shot transition
// notices when the capability flips — regained → Info; lost → Error when the config requires the
// family (reflection is broken until the address returns), Info when it merely uses it.
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

    // Borrows `iface` and `logger` (the owning reflector's, so notices carry its prefix); both
    // must outlive this object. `role` names the interface in notices ("source" / "target").
    FamilyCapability(const Interface& iface, std::string_view role, Logger& logger, Policy policy);

    // Re-reads both families' capability and logs a notice for each flip. The owner calls this
    // when the interface's addresses may have changed (Reflector::OnInterfaceChanged).
    void Observe() noexcept;

    // True if the config uses `family` and the interface can currently send it.
    [[nodiscard]] bool CanSend(IpAddress::Family family) const noexcept;

private:
    template <IpAddress::Family family>
    void ObserveFamily() noexcept;

    const Interface* iface_;
    Logger* logger_;
    std::string_view role_;
    Policy policy_;
    // Capability when last observed, for the one-shot notices; CanSend reads live.
    AddressFamilyPair<bool> can_send_;
};

} // namespace reflector
