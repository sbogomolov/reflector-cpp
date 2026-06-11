#pragma once

#include "config.h"
#include "family_capability.h"
#include "ip_address.h"
#include "link_socket.h"
#include "mac_address.h"
#include "mdns_message.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "reflector.h"
#include "util/address_family_pair.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace reflector {

// Reflects multicast DNS between two interfaces. Captures on both source_if and target_if (joining
// the mDNS group on each), then relays directionally: queries source->target, responses
// target->source. Unsolicited announcements are responses, so they flow target->source too. The
// target->source direction can be restricted to one device by its frame source MAC (config.mac).
// A family is reflected only while BOTH interfaces can send it; its group joins and captures are
// brought up / torn down as addresses come and go (OnInterfaceChanged). Both sockets must outlive
// this reflector.
class MdnsReflector : public Reflector {
public:
    MdnsReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const MdnsConfig& config);

    // Brings a family up (joins the group, registers both directions) when it becomes reflectable,
    // or tears it down when it stops being so, logging the transition. Reads live interface state.
    void OnInterfaceChanged() noexcept override;

private:
    static constexpr uint16_t MDNS_PORT = 5353;
    static constexpr uint8_t MDNS_TTL = 255;

    // A family's live setup while it is being reflected: the group memberships and the capture
    // registrations on both sockets. Empty (and IsUp() false) while the family is not reflected.
    struct FamilySetup {
        std::vector<LinkSocket::MulticastMembership> memberships;
        std::vector<PacketDispatcher::Registration> registrations;
        [[nodiscard]] bool IsUp() const noexcept { return !registrations.empty(); }
    };

    [[nodiscard]] bool ValidateConfig(const MdnsConfig& config);
    void Initialize(const MdnsConfig& config);
    // Brings `family` up: joins the mDNS group + registers both directions on both sockets. Returns
    // false (after logging, leaving nothing half-set-up) if a join or registration fails.
    [[nodiscard]] bool BringUpFamily(IpAddress::Family family);
    // Reconciles `family` to its desired state: brings it up when it became reflectable, tears it
    // down when it stopped being so. A no-op when already in the desired state.
    void SyncFamily(IpAddress::Family family) noexcept;

    void OnSourcePacket(const Packet& packet) noexcept;  // source->target: relay queries
    void OnTargetPacket(const Packet& packet) noexcept;  // target->source: relay responses
    // True if `packet` is an mDNS message of `kind` (and should be relayed). A payload that isn't
    // a DNS message at all is logged and dropped (it shouldn't appear on the group); a message of
    // the other kind is dropped silently (normal bidirectional traffic).
    [[nodiscard]] bool ShouldRelay(const Packet& packet, MdnsMessageKind kind) noexcept;
    void Relay(LinkSocket& egress, const Packet& packet) noexcept;

    LinkSocket& source_socket_;
    LinkSocket& target_socket_;
    PacketDispatcher& packet_dispatcher_;  // retained for dynamic (re-)registration on address changes
    std::optional<MacAddress> config_mac_;  // device-scoping filter for the target->source capture
    FamilyCapability capability_;            // a family is sendable only when BOTH interfaces can
    AddressFamilyPair<FamilySetup> families_;
};

} // namespace reflector
