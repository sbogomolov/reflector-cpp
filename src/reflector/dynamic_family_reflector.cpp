#include "dynamic_family_reflector.h"

#include <utility>

namespace reflector {

DynamicFamilyReflector::DynamicFamilyReflector(std::string logger_name, const Interface& source,
    const Interface& target, FamilyCapability::Policy policy)
        : Reflector{std::move(logger_name)}
        , capability_{source, target, logger_, policy} {}

bool DynamicFamilyReflector::BringUpReflectableFamilies() {
    for (const auto family : {IpAddress::Family::V4, IpAddress::Family::V6}) {
        if (capability_.CanSend(family) && !BringUpFamily(family)) {
            families_.V4() = {};  // a setup failure tears down anything brought up so far
            families_.V6() = {};
            return false;
        }
    }
    return true;
}

void DynamicFamilyReflector::SyncFamily(IpAddress::Family family) noexcept {
    const bool want = capability_.CanSend(family);
    auto& setup = families_.Get(family);
    if (want == setup.IsUp()) {
        return;  // already in the desired state
    }
    if (want) {
        // A transient bring-up failure (logged) leaves the family down; the next change retries.
        if (!BringUpFamily(family)) {
            setup = {};
        }
    } else {
        setup = {};  // tear down: RAII leaves the groups and unregisters the captures
    }
}

void DynamicFamilyReflector::OnInterfaceChanged() noexcept {
    capability_.Observe();  // log each family's reflectability transition
    using enum IpAddress::Family;
    SyncFamily(V4);
    SyncFamily(V6);
}

} // namespace reflector
