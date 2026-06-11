#include "family_capability.h"

namespace reflector {

FamilyCapability::FamilyCapability(const Interface& iface, std::string_view role, Logger& logger,
    Policy policy)
        : iface_{&iface}
        , logger_{&logger}
        , role_{role}
        , policy_{policy}
        , can_send_{iface.CanSend(IpAddress::Family::V4), iface.CanSend(IpAddress::Family::V6)} {}

void FamilyCapability::Observe() noexcept {
    using enum IpAddress::Family;
    ObserveFamily<V4>();
    ObserveFamily<V6>();
}

template <IpAddress::Family family>
void FamilyCapability::ObserveFamily() noexcept {
    const bool can_send = iface_->CanSend(family);
    auto& last_can_send = can_send_.Get<family>();
    if (can_send == last_can_send) {
        return;
    }
    last_can_send = can_send;
    if (!policy_.uses.Get<family>()) {
        return;  // tracked silently — the config never reflects this family
    }
    if (can_send) {
        logger_->Info("Starting {} reflection: the {} interface has a source address", family, role_);
    } else if (policy_.required.Get<family>()) {
        logger_->Error("Cannot reflect {} packets: the {} interface lost its source address",
            family, role_);
    } else {
        logger_->Info("Stopping {} reflection: the {} interface lost its source address",
            family, role_);
    }
}

bool FamilyCapability::CanSend(IpAddress::Family family) const noexcept {
    return policy_.uses.Get(family) && iface_->CanSend(family);
}

} // namespace reflector
