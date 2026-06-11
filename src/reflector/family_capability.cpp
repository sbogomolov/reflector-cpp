#include "family_capability.h"

namespace reflector {

FamilyCapability::FamilyCapability(const Interface& iface, Logger& logger, Policy policy)
        : FamilyCapability{&iface, nullptr, logger, policy} {}

FamilyCapability::FamilyCapability(const Interface& first, const Interface& second, Logger& logger,
    Policy policy)
        : FamilyCapability{&first, &second, logger, policy} {}

FamilyCapability::FamilyCapability(const Interface* first, const Interface* second, Logger& logger,
    Policy policy) noexcept
        : first_{first}
        , second_{second}
        , logger_{&logger}
        , policy_{policy}
        , can_send_{CanSend(IpAddress::Family::V4), CanSend(IpAddress::Family::V6)} {}

void FamilyCapability::Observe() noexcept {
    using enum IpAddress::Family;
    ObserveFamily<V4>();
    ObserveFamily<V6>();
}

template <IpAddress::Family family>
void FamilyCapability::ObserveFamily() noexcept {
    const bool can_send = CanSend(family);
    auto& last_can_send = can_send_.Get<family>();
    if (can_send == last_can_send) {
        return;
    }
    last_can_send = can_send;
    // An unused family's CanSend is always false, so it never reaches a transition here — it stays
    // silent without a separate guard.
    if (can_send) {
        logger_->Info("Starting {} reflection: a source address is available", family);
    } else if (policy_.required.Get<family>()) {
        logger_->Error("Cannot reflect {} packets: a source address is no longer available", family);
    } else {
        logger_->Info("Stopping {} reflection: a source address is no longer available", family);
    }
}

bool FamilyCapability::CanSend(IpAddress::Family family) const noexcept {
    return policy_.uses.Get(family) && first_->CanSend(family)
        && (second_ == nullptr || second_->CanSend(family));
}

} // namespace reflector
