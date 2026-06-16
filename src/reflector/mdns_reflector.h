#pragma once

#include "config/config.h"
#include "dynamic_family_reflector.h"
#include "ip_address.h"
#include "link_socket.h"
#include "mdns_message.h"
#include "packet.h"
#include "packet_dispatcher.h"

#include <cstdint>
#include <optional>

namespace reflector {

// Reflects multicast DNS between two interfaces. Captures on both source_if and target_if (joining
// the mDNS group on each), then relays directionally: queries source->target, responses
// target->source. Unsolicited announcements are responses, so they flow target->source too. The
// target->source direction can be restricted to one device by its frame source MAC (config.mac).
// A family is reflected only while BOTH interfaces can send it; its group join and captures are
// brought up / torn down as addresses come and go (DynamicFamilyReflector). Both sockets must
// outlive this reflector.
//
// KNOWN LIMITATION: legacy one-shot queries (RFC 6762 §6.7 — a querier asking from an ephemeral
// source port and expecting a UNICAST reply) are not bridged. A query is always re-emitted from the
// standard 5353 source port, so the responder multicasts its answer to the group; that multicast
// reflects back to the querier's segment but never reaches its ephemeral port, so the querier sees
// nothing. Full mDNS resolvers (which query and listen on 5353) work end to end; only the legacy
// unicast-reply path is unsupported. Bridging it would need SSDP-style per-query reserved-port
// sessions (see SsdpReflector); out of scope, as modern resolvers dominate.
class MdnsReflector : public DynamicFamilyReflector {
public:
    MdnsReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const MdnsConfig& config);

private:
    static constexpr uint16_t MDNS_PORT = 5353;
    static constexpr uint8_t MDNS_TTL = 255;

    [[nodiscard]] bool ValidateConfig(const MdnsConfig& config);
    void Initialize(const MdnsConfig& config);
    // Joins the family's single mDNS group + registers both directions on both sockets.
    [[nodiscard]] bool BringUpFamily(IpAddress::Family family) override;

    void OnSourcePacket(const Packet& packet) noexcept;  // source->target: relay queries
    void OnTargetPacket(const Packet& packet) noexcept;  // target->source: relay responses
    // True if `packet` is an mDNS message of `kind` (and should be relayed). A payload that isn't
    // a DNS message at all is logged and dropped (it shouldn't appear on the group); a message of
    // the other kind is dropped silently (normal bidirectional traffic).
    [[nodiscard]] bool ShouldRelay(const Packet& packet, MdnsMessageKind kind) noexcept;
    void Relay(LinkSocket& egress, const Packet& packet) noexcept;

    LinkSocket* source_socket_;
    LinkSocket* target_socket_;
    PacketDispatcher* packet_dispatcher_;  // retained for dynamic (re-)registration on address changes
    std::optional<MacAddress> config_mac_;  // device-scoping filter for the target->source capture
};

} // namespace reflector
