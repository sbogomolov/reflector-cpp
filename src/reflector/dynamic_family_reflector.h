#pragma once

#include "family_capability.h"
#include "interface.h"
#include "ip_address.h"
#include "link_socket.h"
#include "packet_dispatcher.h"
#include "reflector.h"
#include "util/address_family_pair.h"

#include <string>
#include <vector>

namespace reflector {

// A reflector whose per-family multicast groups are joined and captured while the family is
// reflectable (both interfaces can send it) and torn down when it isn't. The subclass says HOW to
// bring a family up (which groups + which capture callbacks via BringUpFamily); this base owns the
// per-family setup and reconciles each family to its live reflectability on every interface change.
class DynamicFamilyReflector : public Reflector {
public:
    // Brings up a family that became reflectable, tears down one that stopped being so, logging the
    // transition. Reads live interface state.
    void OnInterfaceChanged() noexcept override;

protected:
    // A family's live setup while it is being reflected: the group memberships and the capture
    // registrations on both sockets (a family may have several groups). Empty (IsUp() false) while
    // the family is not reflected.
    struct FamilySetup {
        std::vector<LinkSocket::MulticastMembership> memberships;
        std::vector<PacketDispatcher::Registration> registrations;
        [[nodiscard]] bool IsUp() const noexcept { return !registrations.empty(); }
    };

    DynamicFamilyReflector(std::string logger_name, const Interface& source, const Interface& target,
        FamilyCapability::Policy policy);

    // Brings every group of `family` up (subclass-specific groups + capture callbacks), all-or-
    // nothing: returns false (after logging, leaving nothing half-set-up) on any failure.
    [[nodiscard]] virtual bool BringUpFamily(IpAddress::Family family) = 0;

    // Brings up each currently-reflectable family (for construction). Returns false if any bring-up
    // fails, having torn down anything brought up so far.
    [[nodiscard]] bool BringUpReflectableFamilies();

    FamilyCapability capability_;  // a family is sendable only when BOTH interfaces can send it
    AddressFamilyPair<FamilySetup> families_;

private:
    // Reconciles `family` to its desired state: brings it up when it became reflectable, tears it
    // down when it stopped. A no-op when already in the desired state.
    void SyncFamily(IpAddress::Family family) noexcept;
};

} // namespace reflector
