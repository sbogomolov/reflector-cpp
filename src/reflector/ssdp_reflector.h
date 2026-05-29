#pragma once

#include "config.h"
#include "ip_address.h"
#include "link_socket.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "reflector.h"
#include "ssdp_message.h"

#include <cstdint>

namespace reflector {

// Reflects SSDP (UPnP/DLNA discovery) between two interfaces. Captures on both source_if and
// target_if (joining each SSDP group on each — IPv4 has one group, IPv6 has two), then relays
// directionally: M-SEARCH searches source->target, NOTIFY advertisements target->source. The
// target->source direction can be restricted to one device by its frame source MAC (config.mac).
// Both sockets must outlive this reflector. (Multicast-only: the unicast M-SEARCH response is not
// bridged — see the SSDP design doc.)
class SsdpReflector : public Reflector {
public:
    SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const SsdpConfig& config);

private:
    static constexpr uint16_t SSDP_PORT = 1900;
    static constexpr uint8_t SSDP_TTL = 2;

    [[nodiscard]] bool ValidateConfig(const SsdpConfig& config);
    void Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const SsdpConfig& config);
    // Joins one SSDP `group` on both sockets and registers both directions for it. Returns false
    // (after logging) if a join or registration fails.
    [[nodiscard]] bool SetUpGroup(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const IpAddress& group, const SsdpConfig& config);

    void OnSourcePacket(const Packet& packet) noexcept;  // source->target: relay searches
    void OnTargetPacket(const Packet& packet) noexcept;  // target->source: relay advertisements
    // True if `packet` is an SSDP message of `kind` (and should be relayed). A payload that isn't an
    // SSDP request at all is logged and dropped (it shouldn't appear on the group); a message of the
    // other kind is dropped silently (normal bidirectional traffic).
    [[nodiscard]] bool ShouldRelay(const Packet& packet, SsdpMessageKind kind) noexcept;
    void Relay(LinkSocket& egress, const Packet& packet) noexcept;

    LinkSocket& source_socket_;
    LinkSocket& target_socket_;
};

} // namespace reflector
