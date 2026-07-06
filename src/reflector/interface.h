#pragma once

#include "interface_address.h"
#include "ip_address.h"
#include "logger.h"
#include "mac_address.h"
#include "util/no_move.h"

#include <optional>
#include <string>
#include <string_view>

namespace reflector {

// A network interface's identity and source addresses: the name (the config key; also the
// SO_BINDTODEVICE egress pin), the kernel index (AF_PACKET bind, IPv6 scope id, IP_BOUND_IF),
// and the resolved source MAC/IPs that injected frames originate from. One instance per
// interface, owned by Application and borrowed by everything else (RawSocket, reflectors,
// DialProxy, TcpSocket egress pinning), so an address refresh lands in exactly one place.
//
// Immovable: RawSocket and DialProxy keep references to it for their lifetime, so instances
// need address-stable storage (Application holds them behind unique_ptr).
class Interface : NoMove {
public:
    // Resolves the kernel index and the initial addresses. IsValid() is false if the name is
    // over-long or unknown to the kernel.
    explicit Interface(std::string_view name);
    virtual ~Interface() noexcept = default;

    [[nodiscard]] bool IsValid() const noexcept { return index_ != 0; }
    [[nodiscard]] std::string_view Name() const noexcept { return name_; }
    [[nodiscard]] unsigned Index() const noexcept { return index_; }
    [[nodiscard]] MacAddress Mac() const noexcept { return addresses_.mac; }

    // The source address for `family` — what sends and binds on this interface originate from.
    // nullopt if the interface has none (then CanSend(family) is also false). IPv6 prefers the
    // link-local address, falling back to ULA then GUA. For a send with a known destination use
    // SourceAddressFor, which also matches the IPv6 scope.
    [[nodiscard]] std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept;
    // The source address for a send to `destination` — family-matched, and for IPv6 also
    // scope-matched: a link-local source for a link-local-scoped destination, a routable (ULA/GUA)
    // source for a site/global one. Falls back to the other scope's address when the matching one
    // is absent — a scope mismatch, but better than dropping the send.
    [[nodiscard]] std::optional<IpAddress> SourceAddressFor(const IpAddress& destination) const noexcept;
    [[nodiscard]] bool CanSend(IpAddress::Family family) const noexcept;

    // Re-resolves the source addresses; Application calls this when the address monitor reports
    // a change on this interface. Virtual so tests substitute a no-syscall fake.
    virtual void Refresh() noexcept;

protected:
    // Test seam: fixed identity, no kernel lookups (see FakeInterface).
    Interface(std::string_view name, unsigned index, const InterfaceAddresses& addresses) noexcept;

    InterfaceAddresses addresses_;

private:
    Logger logger_;
    std::string name_;
    unsigned index_ = 0;
};

} // namespace reflector
