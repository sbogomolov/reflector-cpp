#pragma once

#include "reflector/interface.h"
#include "reflector/ip_address.h"

#include <optional>
#include <string_view>
#include <utility>

namespace reflector {

// Interface fake with a fixed identity and directly settable addresses — no kernel lookups.
// Defaults: loopback per-family sources, index 0 (= "no egress pin").
class FakeInterface : public Interface {
public:
    explicit FakeInterface(std::string_view name = "fake0", unsigned index = 0,
        const InterfaceAddresses& addresses = {.v4 = IpAddress::LoopbackV4(), .v6 = IpAddress::LoopbackV6()})
            : Interface{name, index, addresses} {}

    void SetV4(std::optional<IpAddress> v4) noexcept { addresses_.v4 = std::move(v4); }
    void SetV6(std::optional<IpAddress> v6) noexcept { addresses_.v6 = std::move(v6); }
    void SetV6Routable(std::optional<IpAddress> v6_routable) noexcept {
        addresses_.v6_routable = std::move(v6_routable);
    }

    // Capability shorthand: a present (loopback) or absent source address for `family`.
    void SetHasSource(IpAddress::Family family, bool has) noexcept {
        if (family == IpAddress::Family::V4) {
            addresses_.v4 = has ? std::optional{IpAddress::LoopbackV4()} : std::nullopt;
        } else {
            addresses_.v6 = has ? std::optional{IpAddress::LoopbackV6()} : std::nullopt;
        }
    }

    void Refresh() noexcept override { ++refresh_count; }

    unsigned refresh_count = 0;
};

} // namespace reflector
