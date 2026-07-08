#include "mdns_reflector.h"

#include "mdns_message.h"
#include "util/delegate.h"

#include <format>
#include <string>
#include <utility>

namespace {

using namespace reflector;

std::string LoggerName(const MdnsConfig& config) {
    return std::format("MdnsReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
}

} // namespace

namespace reflector {

MdnsReflector::MdnsReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const MdnsConfig& config)
        : DynamicFamilyReflector{LoggerName(config), source_socket.GetInterface(),
              target_socket.GetInterface(), FamilyCapability::PolicyOf(config)}
        , source_socket_{&source_socket}
        , target_socket_{&target_socket}
        , packet_dispatcher_{&packet_dispatcher}
        , config_mac_{config.mac} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(config);
}

bool MdnsReflector::ValidateConfig(const MdnsConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create mdns reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void MdnsReflector::Initialize(const MdnsConfig& config) {
    // mDNS is bidirectional, so a handled family must be sendable on BOTH interfaces (capability_
    // tracks the AND): the target re-emits relayed queries, the source re-emits relayed responses.
    // A required family must already be reflectable; an optional one comes up later if it ever is.
    if (config.RequiresIPv4() && !capability_.CanSend(IpAddress::Family::V4)) {
        logger_.Error("Cannot create mdns reflector \"{}\": IPv4 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }
    if (config.RequiresIPv6() && !capability_.CanSend(IpAddress::Family::V6)) {
        logger_.Error("Cannot create mdns reflector \"{}\": IPv6 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }

    if (!BringUpReflectableFamilies()) {
        return;
    }

    valid_ = true;
    logger_.Info("Created mdns reflector (IPv4: {}, IPv6: {})",
        capability_.CanSend(IpAddress::Family::V4) ? "enabled" : "disabled",
        capability_.CanSend(IpAddress::Family::V6) ? "enabled" : "disabled");
}

bool MdnsReflector::BringUpFamily(IpAddress::Family family) {
    const auto group = IpAddress::MdnsGroupFor(family);

    // Program gate 2 so each interface actually receives the group's multicast. A failed join or
    // registration drops every token taken here when it leaves scope (auto-leave / auto-unregister),
    // so nothing is half-set-up; the family's setup is only populated on full success.
    auto source_membership = source_socket_->JoinMulticastGroup(group);
    auto target_membership = target_socket_->JoinMulticastGroup(group);
    if (!source_membership.IsValid() || !target_membership.IsValid()) {
        logger_.Error("Cannot reflect mdns {}: cannot join the group on both interfaces", group);
        return false;
    }

    // source -> target: relay queries, unfiltered (any client on source may ask).
    auto source_registration = packet_dispatcher_->Register(*source_socket_,
        PacketFilter{.dest_ip = group, .dest_port = MDNS_PORT},
        CreateDelegate<&MdnsReflector::OnSourcePacket>(this));
    if (!source_registration.IsValid()) {
        logger_.Error("Cannot reflect mdns {}: registration failed (source)", group);
        return false;
    }

    // target -> source: relay responses, optionally only from the configured device's MAC.
    auto target_registration = packet_dispatcher_->Register(*target_socket_,
        PacketFilter{.dest_ip = group, .dest_port = MDNS_PORT, .source_mac = config_mac_},
        CreateDelegate<&MdnsReflector::OnTargetPacket>(this));
    if (!target_registration.IsValid()) {
        logger_.Error("Cannot reflect mdns {}: registration failed (target)", group);
        return false;
    }

    auto& setup = families_.Get(family);
    setup.memberships.push_back(std::move(source_membership));
    setup.memberships.push_back(std::move(target_membership));
    setup.registrations.push_back(std::move(source_registration));
    setup.registrations.push_back(std::move(target_registration));
    return true;
}

void MdnsReflector::OnSourcePacket(const Packet& packet) noexcept {
    if (ShouldRelay(packet, MdnsMessageKind::Query)) {
        Relay(*target_socket_, packet);
    }
}

void MdnsReflector::OnTargetPacket(const Packet& packet) noexcept {
    // The source-MAC filter is applied by the dispatcher, not here.
    if (ShouldRelay(packet, MdnsMessageKind::Response)) {
        Relay(*source_socket_, packet);
    }
}

bool MdnsReflector::ShouldRelay(const Packet& packet, MdnsMessageKind kind) noexcept {
    const auto message_kind = ClassifyMdnsMessage(packet.payload);
    if (!message_kind) {
        // The group + port 5353 should carry only mDNS, so a payload too short to be a DNS message
        // is anomalous and worth surfacing — the dedicated group means this won't spam a healthy
        // network. A message of the other kind, by contrast, is normal and dropped silently.
        logger_.Info("Ignoring non-mDNS packet on {} from {}: {}-byte payload too short for a DNS header",
            packet.header.dest, packet.header.source, packet.payload.size());
        return false;
    }
    return *message_kind == kind;
}

void MdnsReflector::Relay(LinkSocket& egress, const Packet& packet) noexcept {
    // Re-emit to the same group it was sent to (the filter guarantees dest_ip is that group), from
    // the mDNS port, with the conventional 255 hop limit.
    if (!egress.SendUdpMulticastDatagram(packet.header.dest, MDNS_PORT, packet.payload, MDNS_TTL)) {
        logger_.Error("Cannot reflect mdns packet from {} to {}", packet.header.source, packet.header.dest);
        return;
    }
    logger_.Debug("Reflected mdns packet from {} to {}", packet.header.source, packet.header.dest);
}

} // namespace reflector
