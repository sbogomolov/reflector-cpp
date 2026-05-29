#include "ssdp_reflector.h"

#include "ssdp_message.h"
#include "util/delegate.h"

#include <format>
#include <string>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const SsdpConfig& config) {
    return std::format("SsdpReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
}

} // namespace

SsdpReflector::SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const SsdpConfig& config)
        : Reflector{LoggerName(config)}
        , source_socket_{source_socket}
        , target_socket_{target_socket} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(packet_dispatcher, source_socket, target_socket, config);
}

bool SsdpReflector::ValidateConfig(const SsdpConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void SsdpReflector::Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const SsdpConfig& config) {
    // SSDP is bidirectional, so a handled family must be sendable on BOTH interfaces: the target
    // re-emits relayed searches, the source re-emits relayed advertisements.
    const auto reflectable = [&](IpAddress::Family family) {
        return source_socket.CanSend(family) && target_socket.CanSend(family);
    };

    if (config.RequiresIPv4() && !reflectable(IpAddress::Family::V4)) {
        logger_.Error("Cannot create ssdp reflector \"{}\": IPv4 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }
    if (config.RequiresIPv6() && !reflectable(IpAddress::Family::V6)) {
        logger_.Error("Cannot create ssdp reflector \"{}\": IPv6 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }

    for (const auto family : {IpAddress::Family::V4, IpAddress::Family::V6}) {
        const bool uses = family == IpAddress::Family::V4 ? config.UsesIPv4() : config.UsesIPv6();
        if (!uses || !reflectable(family)) {
            continue;  // a family the config merely "uses" but can't reflect is silently skipped
        }
        // SSDP has more than one group per family (IPv6: link-local + site-local); join and register
        // each one.
        for (const auto& group : IpAddress::SsdpGroupsFor(family)) {
            if (!SetUpGroup(packet_dispatcher, source_socket, target_socket, group, config)) {
                registrations_.clear();
                return;
            }
        }
    }

    logger_.Info("Created ssdp reflector (IPv4: {}, IPv6: {})",
        config.UsesIPv4() && reflectable(IpAddress::Family::V4) ? "enabled" : "disabled",
        config.UsesIPv6() && reflectable(IpAddress::Family::V6) ? "enabled" : "disabled");
}

bool SsdpReflector::SetUpGroup(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const IpAddress& group, const SsdpConfig& config) {
    // Program gate 2 so each interface actually receives the group's multicast.
    if (!source_socket.JoinMulticastGroup(group) || !target_socket.JoinMulticastGroup(group)) {
        logger_.Error("Cannot create ssdp reflector \"{}\": cannot join {} on both interfaces",
            config.name, group);
        return false;
    }

    // source -> target: relay searches, unfiltered (any client on source may search).
    auto source_registration = packet_dispatcher.Register(source_socket,
        PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT},
        CreateDelegate<&SsdpReflector::OnSourcePacket>(this));
    if (!source_registration.IsValid()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": registration failed for {} (source)", config.name, group);
        return false;
    }
    registrations_.push_back(std::move(source_registration));

    // target -> source: relay advertisements, optionally only from the configured device's MAC.
    auto target_registration = packet_dispatcher.Register(target_socket,
        PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT, .source_mac = config.mac},
        CreateDelegate<&SsdpReflector::OnTargetPacket>(this));
    if (!target_registration.IsValid()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": registration failed for {} (target)", config.name, group);
        return false;
    }
    registrations_.push_back(std::move(target_registration));

    return true;
}

void SsdpReflector::OnSourcePacket(const Packet& packet) noexcept {
    if (ShouldRelay(packet, SsdpMessageKind::Search)) {  // only searches flow source -> target
        Relay(target_socket_, packet);
    }
}

void SsdpReflector::OnTargetPacket(const Packet& packet) noexcept {
    // Only advertisements flow target -> source; the source-MAC filter is applied by the dispatcher.
    if (ShouldRelay(packet, SsdpMessageKind::Advertisement)) {
        Relay(source_socket_, packet);
    }
}

bool SsdpReflector::ShouldRelay(const Packet& packet, SsdpMessageKind kind) noexcept {
    const auto message_kind = ClassifySsdpMessage(packet.payload);
    if (!message_kind.has_value()) {
        // The group + port 1900 should carry only SSDP requests, so a payload that is neither an
        // M-SEARCH nor a NOTIFY (e.g. a stray unicast 200 OK, or junk) is anomalous and worth
        // surfacing. A message of the other kind, by contrast, is normal and dropped silently.
        logger_.Info("Ignoring non-SSDP packet on {} from {}: not an M-SEARCH or NOTIFY",
            packet.header.dest_ip, packet.header.source_ip);
        return false;
    }
    return *message_kind == kind;
}

void SsdpReflector::Relay(LinkSocket& egress, const Packet& packet) noexcept {
    // Re-emit to the same group it was sent to (the filter guarantees dest_ip is that group), from
    // the SSDP port, with a freshly reset hop limit (UDA 2.0 default).
    const auto& group = packet.header.dest_ip;
    if (!egress.SendUdpDatagram(group, SSDP_PORT, SSDP_PORT, packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect ssdp packet from {} to {}", packet.header.source_ip, group);
        return;
    }
    logger_.Debug("Reflected ssdp packet from {} to {}", packet.header.source_ip, group);
}

} // namespace reflector
