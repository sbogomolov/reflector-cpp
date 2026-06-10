#include "mdns_reflector.h"

#include "interface.h"
#include "mdns_message.h"
#include "util/delegate.h"

#include <format>
#include <string>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const MdnsConfig& config) {
    return std::format("MdnsReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
}

} // namespace

MdnsReflector::MdnsReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const MdnsConfig& config)
        : Reflector{LoggerName(config)}
        , source_socket_{source_socket}
        , target_socket_{target_socket} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(packet_dispatcher, source_socket, target_socket, config);
}

bool MdnsReflector::ValidateConfig(const MdnsConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create mdns reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void MdnsReflector::Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const MdnsConfig& config) {
    // mDNS is bidirectional, so a handled family must be sendable on BOTH interfaces: the target
    // re-emits relayed queries, the source re-emits relayed responses.
    const auto reflectable = [&](IpAddress::Family family) {
        return source_socket.GetInterface().CanSend(family)
            && target_socket.GetInterface().CanSend(family);
    };

    if (config.RequiresIPv4() && !reflectable(IpAddress::Family::V4)) {
        logger_.Error("Cannot create mdns reflector \"{}\": IPv4 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }
    if (config.RequiresIPv6() && !reflectable(IpAddress::Family::V6)) {
        logger_.Error("Cannot create mdns reflector \"{}\": IPv6 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }

    for (const auto family : {IpAddress::Family::V4, IpAddress::Family::V6}) {
        const bool uses = family == IpAddress::Family::V4 ? config.UsesIPv4() : config.UsesIPv6();
        if (!uses || !reflectable(family)) {
            continue;  // a family the config merely "uses" but can't reflect is silently skipped
        }
        if (!SetUpFamily(packet_dispatcher, source_socket, target_socket, family, config)) {
            registrations_.clear();
            return;
        }
    }

    logger_.Info("Created mdns reflector (IPv4: {}, IPv6: {})",
        config.UsesIPv4() && reflectable(IpAddress::Family::V4) ? "enabled" : "disabled",
        config.UsesIPv6() && reflectable(IpAddress::Family::V6) ? "enabled" : "disabled");
}

bool MdnsReflector::SetUpFamily(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, IpAddress::Family family, const MdnsConfig& config) {
    const auto group = IpAddress::MdnsGroupFor(family);

    // Program gate 2 so each interface actually receives the group's multicast.
    if (!source_socket.JoinMulticastGroup(group) || !target_socket.JoinMulticastGroup(group)) {
        logger_.Error("Cannot create mdns reflector \"{}\": cannot join {} on both interfaces",
            config.name, group);
        return false;
    }

    // source -> target: relay queries, unfiltered (any client on source may ask).
    auto source_registration = packet_dispatcher.Register(source_socket,
        PacketFilter{.dest_ip = group, .dest_port = MDNS_PORT},
        CreateDelegate<&MdnsReflector::OnSourcePacket>(this));
    if (!source_registration.IsValid()) {
        logger_.Error("Cannot create mdns reflector \"{}\": registration failed for {} (source)", config.name, group);
        return false;
    }
    registrations_.push_back(std::move(source_registration));

    // target -> source: relay responses, optionally only from the configured device's MAC.
    auto target_registration = packet_dispatcher.Register(target_socket,
        PacketFilter{.dest_ip = group, .dest_port = MDNS_PORT, .source_mac = config.mac},
        CreateDelegate<&MdnsReflector::OnTargetPacket>(this));
    if (!target_registration.IsValid()) {
        logger_.Error("Cannot create mdns reflector \"{}\": registration failed for {} (target)", config.name, group);
        return false;
    }
    registrations_.push_back(std::move(target_registration));

    return true;
}

void MdnsReflector::OnSourcePacket(const Packet& packet) noexcept {
    if (ShouldRelay(packet, MdnsMessageKind::Query)) {
        Relay(target_socket_, packet);
    }
}

void MdnsReflector::OnTargetPacket(const Packet& packet) noexcept {
    // The source-MAC filter is applied by the dispatcher, not here.
    if (ShouldRelay(packet, MdnsMessageKind::Response)) {
        Relay(source_socket_, packet);
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
