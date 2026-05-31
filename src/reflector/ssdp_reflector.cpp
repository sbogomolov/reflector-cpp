#include "ssdp_reflector.h"

#include "port_reservation.h"
#include "ssdp_message.h"
#include "util/delegate.h"

#include <algorithm>
#include <chrono>
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
        , target_socket_{target_socket}
        , packet_dispatcher_{packet_dispatcher}
        , config_mac_{config.mac}
        , eviction_timer_{packet_dispatcher.UnderlyingDispatcher()} {
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
    // re-emits reflected searches, the source re-emits reflected advertisements.
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

    // source -> target: reflect searches, unfiltered (any client on source may search).
    auto source_registration = packet_dispatcher.Register(source_socket,
        PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT},
        CreateDelegate<&SsdpReflector::OnSourcePacket>(this));
    if (!source_registration.IsValid()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": registration failed for {} (source)", config.name, group);
        return false;
    }
    registrations_.push_back(std::move(source_registration));

    // target -> source: reflect advertisements, optionally only from the configured device's MAC.
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
    if (!ShouldReflect(packet, SsdpMessageKind::Search)) {  // only searches flow source -> target
        return;
    }

    const auto family = packet.header.dest_ip.AddressFamily();
    const auto parsed_mx = ParseMSearchMx(packet.payload);
    const uint8_t mx = parsed_mx.value_or(MSEARCH_MX_DEFAULT);
    if (!parsed_mx.has_value()) {
        // A multicast M-SEARCH must carry MX (UDA 2.0); surface the non-conformant searcher at INFO.
        logger_.Info("M-SEARCH from {}:{} has no/invalid MX; using the default {}s window",
            packet.header.source_ip, packet.header.source_port, static_cast<unsigned>(mx));
    }
    const auto expiry = std::chrono::steady_clock::now() + std::chrono::seconds{mx} + SESSION_GRACE;

    // One session per client (searcher ip:port): a retransmit reuses its session, a new client gets a
    // fresh one (reserved port + response capture), built locally so a failed reflect rolls it back via
    // RAII. Either way the search is reflected once, from the session's reserved port.
    const auto existing_session = std::ranges::find_if(sessions_, [&](const Session& session) {
        return session.searcher_ip == packet.header.source_ip
            && session.searcher_port == packet.header.source_port;
    });
    std::optional<Session> new_session;
    if (existing_session == sessions_.end()) {
        new_session = MakeSession(packet, family, expiry);
        if (!new_session.has_value()) {
            return;  // MakeSession logged the cause
        }
    }

    const uint16_t port = new_session.has_value() ? new_session->reservation.Port()
                                                  : existing_session->reservation.Port();
    if (!target_socket_.SendUdpMulticastDatagram(packet.header.dest_ip, SSDP_PORT, port,
            packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect M-SEARCH from {} to {}", packet.header.source_ip, packet.header.dest_ip);
        return;  // a new session's reservation + capture RAII-drop here
    }
    logger_.Debug("Reflected M-SEARCH from {}:{} on reserved port {} (MX {}s)",
        packet.header.source_ip, packet.header.source_port, port, static_cast<unsigned>(mx));

    if (!new_session.has_value()) {
        existing_session->expiry = expiry;  // a retransmit: just refresh the client's window
        return;
    }

    sessions_.push_back(std::move(*new_session));
    // Start the eviction sweep on the first in-flight session; EvictExpired stops it once the table
    // empties, so the reactor isn't woken every interval while there's nothing to sweep.
    if (!eviction_timer_.IsRunning()) {
        eviction_timer_.Start(EVICTION_INTERVAL, CreateDelegate<&SsdpReflector::EvictExpired>(this));
    }
}

std::optional<SsdpReflector::Session> SsdpReflector::MakeSession(const Packet& packet,
    IpAddress::Family family, std::chrono::steady_clock::time_point expiry) {
    if (sessions_.size() >= MAX_SESSIONS) {
        logger_.Warning("Dropping M-SEARCH from {}: {} sessions in flight (cap reached)",
            packet.header.source_ip, sessions_.size());
        return std::nullopt;
    }
    const auto our_address = target_socket_.SourceAddress(family);
    if (!our_address.has_value()) {
        logger_.Error("Cannot reflect M-SEARCH from {}: target interface has no source address for {}",
            packet.header.source_ip, family);
        return std::nullopt;
    }
    auto reservation = PortReservation::Create(family);
    if (!reservation.has_value()) {
        return std::nullopt;  // Create logged the cause
    }
    // Register the 200-OK capture before the reflect, so a fast responder's reply can't arrive first.
    auto capture = packet_dispatcher_.Register(target_socket_,
        PacketFilter{.dest_ip = our_address, .dest_port = reservation->Port(), .source_mac = config_mac_},
        CreateDelegate<&SsdpReflector::OnUnicastResponse>(this));
    if (!capture.IsValid()) {
        logger_.Error("Cannot reflect M-SEARCH from {}: response-capture registration failed",
            packet.header.source_ip);
        return std::nullopt;  // reservation RAII-drops here, freeing the port
    }
    return Session{
        .searcher_ip = packet.header.source_ip,
        .searcher_port = packet.header.source_port,
        .searcher_mac = packet.header.source_mac,
        .expiry = expiry,
        .reservation = std::move(*reservation),
        .capture = std::move(capture),
    };
}

void SsdpReflector::OnTargetPacket(const Packet& packet) noexcept {
    // Only advertisements flow target -> source; the source-MAC filter is applied by the dispatcher.
    if (ShouldReflect(packet, SsdpMessageKind::Advertisement)) {
        Reflect(source_socket_, packet);
    }
}

void SsdpReflector::OnUnicastResponse(const Packet& packet) noexcept {
    // Find the session by the reserved port the 200 OK is addressed to (a v4 and a v6 reservation
    // could hold the same port number, so match the family too).
    const auto family = packet.header.dest_ip.AddressFamily();
    const auto it = std::ranges::find_if(sessions_, [&](const Session& session) {
        return session.reservation.Port() == packet.header.dest_port
            && session.searcher_ip.AddressFamily() == family;
    });
    if (it == sessions_.end()) {
        // Defensive: the capture is released with its session, so a 200 OK normally only reaches us
        // while the session lives. If it's gone, so is the port reservation — nothing is left to
        // suppress the kernel's ICMP unreachable, and there's no searcher to forward to. Drop it.
        return;
    }
    const Session& session = *it;
    // Inject the 200 OK to the original searcher from our own source address (no spoofing), addressed
    // to the searcher's captured frame MAC — the split's plain SendUdpDatagram takes that dst MAC.
    if (!source_socket_.SendUdpDatagram(session.searcher_mac, session.searcher_ip, session.searcher_port,
            packet.header.source_port, packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect SSDP response to searcher {}", session.searcher_ip);
        return;
    }
    logger_.Debug("Reflected SSDP response from {} to searcher {}", packet.header.source_ip,
        session.searcher_ip);
}

bool SsdpReflector::ShouldReflect(const Packet& packet, SsdpMessageKind kind) noexcept {
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

void SsdpReflector::Reflect(LinkSocket& egress, const Packet& packet) noexcept {
    // Re-emit to the same group it was sent to (the filter guarantees dest_ip is that group), from
    // the SSDP port, with a freshly reset hop limit (UDA 2.0 default).
    const auto& group = packet.header.dest_ip;
    if (!egress.SendUdpMulticastDatagram(group, SSDP_PORT, SSDP_PORT, packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect ssdp packet from {} to {}", packet.header.source_ip, group);
        return;
    }
    logger_.Debug("Reflected ssdp packet from {} to {}", packet.header.source_ip, group);
}

void SsdpReflector::EvictExpired(std::chrono::steady_clock::time_point now) noexcept {
    std::erase_if(sessions_, [now](const Session& session) { return session.expiry <= now; });
    if (sessions_.empty()) {
        // Nothing left to sweep: stop. Safe self-unregister — the dispatcher's timer merge-walk
        // tolerates a callback dropping its own timer.
        eviction_timer_.Stop();
    }
}

} // namespace reflector
