#include "ssdp_reflector.h"

#include "interface.h"
#include "port_reservation.h"
#include "protocol_constants.h"
#include "ssdp_message.h"
#include "util/delegate.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace reflector;

std::string LoggerName(const SsdpConfig& config) {
    return std::format("SsdpReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
}

} // namespace

namespace reflector {

SsdpReflector::SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const SsdpConfig& config)
        : DynamicFamilyReflector{LoggerName(config), source_socket.GetInterface(),
              target_socket.GetInterface(), FamilyCapability::PolicyOf(config)}
        , source_socket_{&source_socket}
        , target_socket_{&target_socket}
        , target_if_{target_socket.GetInterface()}
        , packet_dispatcher_{&packet_dispatcher}
        , config_mac_{config.mac}
        , eviction_timer_{packet_dispatcher.UnderlyingDispatcher()} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(config);
}

bool SsdpReflector::ValidateConfig(const SsdpConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void SsdpReflector::Initialize(const SsdpConfig& config) {
    if (config.mac && !target_socket_->LinkCarriesMacs()) {
        logger_.Error("Cannot create ssdp reflector \"{}\": mac cannot match on \"{}\" (the link carries no MAC addresses)",
            config.name, config.target_if);
        return;
    }
    // SSDP is bidirectional, so a handled family must be sendable on BOTH interfaces (capability_
    // tracks the AND): the target re-emits reflected searches, the source re-emits advertisements.
    // A required family must already be reflectable; an optional one comes up later if it ever is.
    if (config.RequiresIPv4() && !capability_.CanSend(IpAddress::Family::V4)) {
        logger_.Error("Cannot create ssdp reflector \"{}\": IPv4 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }
    if (config.RequiresIPv6() && !capability_.CanSend(IpAddress::Family::V6)) {
        logger_.Error("Cannot create ssdp reflector \"{}\": IPv6 requires a source address on both \"{}\" and \"{}\"",
            config.name, config.source_if, config.target_if);
        return;
    }

    if (!BringUpReflectableFamilies()) {
        return;
    }

    // config.Verify guarantees dial implies an IPv4 family, and the RequiresIPv4 gate above guarantees V4
    // is reflectable here, so the proxy always has a source_if V4 address to bind its listeners on. The
    // device speaks DIAL on target_if and the client reaches it on source_if (LOCATION rewrite direction).
    if (config.dial) {
        dial_proxy_.emplace(packet_dispatcher_->UnderlyingDispatcher(), source_socket_->GetInterface(),
            target_socket_->GetInterface(),
            std::format("DialProxy:{}:{}->{}", config.name, config.source_if, config.target_if));
        rewrite_scratch_.reserve(MAX_UDP_PAYLOAD_SIZE);
    }

    valid_ = true;
    logger_.Info("Created ssdp reflector (IPv4: {}, IPv6: {}, DIAL: {})",
        capability_.CanSend(IpAddress::Family::V4) ? "enabled" : "disabled",
        capability_.CanSend(IpAddress::Family::V6) ? "enabled" : "disabled",
        config.dial ? "enabled" : "disabled");
}

void SsdpReflector::OnInterfaceChanged() noexcept {
    DynamicFamilyReflector::OnInterfaceChanged();  // re-gate families: join/leave groups + (un)register captures
    EvictStaleSessions();
    if (dial_proxy_) {
        // Drops listeners bound to a now-changed source_if address; the next reflected DIAL advertisement
        // re-mints them lazily (RewriteDialLocation -> EnsureDiscoveryListener), against the fresh address.
        dial_proxy_->OnInterfaceChanged();
    }
}

bool SsdpReflector::BringUpFamily(IpAddress::Family family) {
    // SSDP has more than one group per family (IPv6: link-local + site-local); each is set up into
    // the family's setup. A failure rolls the whole family back (RAII leaves/unregisters the rest).
    auto& setup = families_.Get(family);
    for (const auto& group : IpAddress::SsdpGroupsFor(family)) {
        if (!SetUpGroup(group, setup)) {
            setup = {};
            return false;
        }
    }
    return true;
}

bool SsdpReflector::SetUpGroup(const IpAddress& group, FamilySetup& setup) {
    // Program gate 2 so each interface actually receives the group's multicast. A failed join or
    // registration drops every token taken here when it leaves scope; setup is populated only on
    // full success.
    auto source_membership = source_socket_->JoinMulticastGroup(group);
    auto target_membership = target_socket_->JoinMulticastGroup(group);
    if (!source_membership.IsValid() || !target_membership.IsValid()) {
        logger_.Error("Cannot reflect ssdp {}: cannot join the group on both interfaces", group);
        return false;
    }

    // source -> target: reflect searches, unfiltered (any client on source may search).
    auto source_registration = packet_dispatcher_->Register(*source_socket_,
        PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT},
        CreateDelegate<&SsdpReflector::OnSourcePacket>(this));
    if (!source_registration.IsValid()) {
        logger_.Error("Cannot reflect ssdp {}: registration failed (source)", group);
        return false;
    }

    // target -> source: reflect advertisements, optionally only from the configured device's MAC.
    auto target_registration = packet_dispatcher_->Register(*target_socket_,
        PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT, .source_mac = config_mac_},
        CreateDelegate<&SsdpReflector::OnTargetPacket>(this));
    if (!target_registration.IsValid()) {
        logger_.Error("Cannot reflect ssdp {}: registration failed (target)", group);
        return false;
    }

    setup.memberships.push_back(std::move(source_membership));
    setup.memberships.push_back(std::move(target_membership));
    setup.registrations.push_back(std::move(source_registration));
    setup.registrations.push_back(std::move(target_registration));
    return true;
}

void SsdpReflector::OnSourcePacket(const Packet& packet) noexcept {
    if (!ShouldReflect(packet, SsdpMessageKind::Search)) {  // only searches flow source -> target
        return;
    }

    const auto parsed_mx = ParseMSearchMx(packet.payload);
    const uint8_t mx = parsed_mx.value_or(MSEARCH_MX_DEFAULT);
    if (!parsed_mx) {
        // A multicast M-SEARCH must carry MX (UDA 2.0), but this fires on every search including
        // retransmits — one non-conformant client would flood any louder level.
        logger_.Debug("M-SEARCH from {} has no/invalid MX; using the default {}s window",
            packet.header.source, static_cast<unsigned>(mx));
    }
    const auto expiry = std::chrono::steady_clock::now() + std::chrono::seconds{mx} + SESSION_GRACE;

    // One session per (client, group): a retransmit to the same group reuses its session, a new client —
    // or the same client searching a different group (a different reply scope) — gets a fresh one
    // (reserved port + response registration), built locally so a failed reflect rolls it back via RAII.
    // Either way the search is reflected once, from the session's reserved port.
    const auto existing_session = std::ranges::find_if(sessions_, [&](const Session& session) {
        return session.searcher == packet.header.source && session.group == packet.header.dest.addr;
    });
    std::optional<Session> new_session;
    if (existing_session == sessions_.end()) {
        new_session = MakeSession(packet, expiry);
        if (!new_session) {
            return;  // MakeSession logged the cause
        }
    }

    const uint16_t port = new_session ? new_session->reservation.Port()
                                                  : existing_session->reservation.Port();
    if (!target_socket_->SendUdpMulticastDatagram(packet.header.dest, port,
            packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect M-SEARCH from {} to {}", packet.header.source, packet.header.dest);
        return;  // a new session's reservation + response registration RAII-drop here
    }
    logger_.Debug("Reflected M-SEARCH from {} on reserved port {} (MX {}s)",
        packet.header.source, port, static_cast<unsigned>(mx));

    if (!new_session) {
        existing_session->expiry = expiry;  // a retransmit: just refresh the client's window
        return;
    }

    sessions_.push_back(std::move(*new_session));
    logger_.Debug("Created session for searcher {} on reserved port {}; {} active",
        packet.header.source, port, sessions_.size());
    // Start the eviction sweep on the first in-flight session; EvictExpired stops it once the table
    // empties, so the reactor isn't woken every interval while there's nothing to sweep.
    if (!eviction_timer_.IsRunning()) {
        eviction_timer_.Start(EVICTION_INTERVAL, CreateDelegate<&SsdpReflector::EvictExpired>(this));
    }
}

std::optional<SsdpReflector::Session> SsdpReflector::MakeSession(const Packet& packet,
    std::chrono::steady_clock::time_point expiry) {
    if (sessions_.size() >= MAX_SESSIONS) {
        logger_.Warning("Dropping M-SEARCH from {}: {} sessions in flight (cap reached)",
            packet.header.source, sessions_.size());
        return std::nullopt;
    }
    const auto& target_interface = target_socket_->GetInterface();
    // Scope-matched to the group the search is re-emitted to — the same pick SendFrame makes for
    // that re-emit — so responders' unicast 200-OKs land on the reserved address.
    const auto our_address = target_interface.SourceAddressFor(packet.header.dest.addr);
    if (!our_address) {
        logger_.Error("Cannot reflect M-SEARCH from {}: target interface has no source address for {}",
            packet.header.source, packet.header.dest.addr.AddressFamily());
        return std::nullopt;
    }
    auto reservation = PortReservation::Create(*our_address, target_interface.Index());
    if (!reservation) {
        return std::nullopt;  // Create logged the cause
    }
    // Make the 200-OK response registration before the reflect, so a fast responder's reply can't arrive first.
    auto registration = packet_dispatcher_->Register(*target_socket_,
        PacketFilter{.dest_ip = our_address, .dest_port = reservation->Port(), .source_mac = config_mac_},
        CreateDelegate<&SsdpReflector::OnUnicastResponse>(this));
    if (!registration.IsValid()) {
        logger_.Error("Cannot reflect M-SEARCH from {}: response registration failed",
            packet.header.source);
        return std::nullopt;  // reservation RAII-drops here, freeing the port
    }
    return Session{
        .searcher = packet.header.source,
        .group = packet.header.dest.addr,
        .searcher_mac = packet.header.source_mac,
        .reserved_address = *our_address,
        .expiry = expiry,
        .reservation = std::move(*reservation),
        .registration = std::move(registration),
    };
}

void SsdpReflector::OnTargetPacket(const Packet& packet) noexcept {
    // Only advertisements flow target -> source; the source-MAC filter is applied by the dispatcher.
    if (!ShouldReflect(packet, SsdpMessageKind::Advertisement)) {
        return;
    }
    // A DIAL advertisement's LOCATION is first rewritten to a minted source_if listener (the string outlives
    // the send). Re-emit to the same group it was sent to (the filter guarantees dest_ip is that group), from
    // the SSDP port, with a freshly reset hop limit (UDA 2.0 default).
    const auto rewrite = RewriteDialLocation(packet.payload);
    if (rewrite.action == DialRewrite::Action::Drop) {
        return;  // RewriteDialLocation logged the cause
    }
    const auto payload = rewrite.action == DialRewrite::Action::ForwardRewritten
        ? std::as_bytes(std::span<const char>{rewrite.payload})
        : packet.payload;
    if (!source_socket_->SendUdpMulticastDatagram(packet.header.dest, SSDP_PORT, payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect ssdp packet from {} to {}", packet.header.source, packet.header.dest);
        return;
    }
    logger_.Debug("Reflected ssdp packet from {} to {}", packet.header.source, packet.header.dest);
}

void SsdpReflector::OnUnicastResponse(const Packet& packet) noexcept {
    // Find the session by the reserved port the 200 OK is addressed to (a v4 and a v6 reservation
    // could hold the same port number, so match the family too).
    const auto family = packet.header.dest.addr.AddressFamily();
    const auto it = std::ranges::find_if(sessions_, [&](const Session& session) {
        return session.reservation.Port() == packet.header.dest.port
            && session.searcher.addr.AddressFamily() == family;
    });
    if (it == sessions_.end()) {
        // Defensive: the registration is released with its session, so a 200 OK normally only reaches us
        // while the session lives. If it's gone, so is the port reservation — nothing is left to
        // suppress the kernel's ICMP unreachable, and there's no searcher to forward to. Drop it.
        return;
    }
    const Session& session = *it;
    // Inject the 200 OK to the original searcher from our own source address (no spoofing), addressed to
    // the searcher's captured frame MAC — the split's plain SendUdpDatagram takes that dst MAC. A DIAL
    // response's LOCATION is first rewritten to a minted source_if listener (the string outlives the send).
    const auto rewrite = RewriteDialLocation(packet.payload);
    if (rewrite.action == DialRewrite::Action::Drop) {
        return;  // RewriteDialLocation logged the cause
    }
    const auto payload = rewrite.action == DialRewrite::Action::ForwardRewritten
        ? std::as_bytes(std::span<const char>{rewrite.payload})
        : packet.payload;
    if (!source_socket_->SendUdpDatagram(session.searcher_mac, session.searcher,
            packet.header.source.port, payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect SSDP response to searcher {}", session.searcher);
        return;
    }
    logger_.Debug("Reflected SSDP response from {} to searcher {}", packet.header.source,
        session.searcher);
}

bool SsdpReflector::ShouldReflect(const Packet& packet, SsdpMessageKind kind) noexcept {
    const auto message_kind = ClassifySsdpMessage(packet.payload);
    if (!message_kind) {
        // The group + port 1900 should carry only SSDP requests, so a payload that is neither an
        // M-SEARCH nor a NOTIFY (e.g. a stray unicast 200 OK, or junk) is anomalous and worth
        // surfacing. A message of the other kind, by contrast, is normal and dropped silently.
        logger_.Info("Ignoring non-SSDP packet on {} from {}: not an M-SEARCH or NOTIFY",
            packet.header.dest, packet.header.source);
        return false;
    }
    return *message_kind == kind;
}

SsdpReflector::DialRewrite SsdpReflector::RewriteDialLocation(std::span<const std::byte> payload) noexcept {
    if (!dial_proxy_ || !IsDialServiceMessage(payload)) {
        return {};  // proxy disabled, or not a DIAL service message — forward unchanged
    }
    const auto location = ParseDialLocationAuthority(payload);
    if (!location) {
        return {};  // a DIAL message with no/unparseable LOCATION: nothing to rewrite
    }
    const auto max_age = ParseCacheControlMaxAge(payload);
    const auto reflector_authority = dial_proxy_->EnsureDiscoveryListener(location->endpoint,
        max_age.transform([](uint32_t seconds) { return std::chrono::seconds{seconds}; }));
    if (!reflector_authority) {
        logger_.Info("DIAL: no listener for device {} (cap/bind); forwarding its LOCATION unchanged",
            location->endpoint);
        return {};
    }
    // Wide enough for a bracketed IPv6 authority, so the format never truncates.
    std::array<char, 64> authority_text{};
    const auto formatted = std::format_to_n(authority_text.data(), authority_text.size(), "{}",
        *reflector_authority);
    const std::string_view authority{authority_text.data(),
        static_cast<size_t>(formatted.out - authority_text.data())};

    // Size the result before building: an overflow is rejected without copying, and the splice below
    // fits the reserved scratch by construction.
    const std::string_view original{reinterpret_cast<const char*>(payload.data()), payload.size()};
    const size_t rewritten_size = original.size() - location->length + authority.size();
    if (rewritten_size > MAX_UDP_PAYLOAD_SIZE) {
        logger_.Error("DIAL: rewritten LOCATION for {} overflows the {}-byte payload ceiling; dropping the datagram",
            location->endpoint, MAX_UDP_PAYLOAD_SIZE);
        return {.action = DialRewrite::Action::Drop};
    }
    // Splice the reflector authority over exactly the LOCATION's host[:port] span. The port may have been
    // omitted (defaulting to 80), in which case the span covers just the host — the inserted "addr:port"
    // still lands correctly because it replaces that exact text.
    rewrite_scratch_.clear();
    rewrite_scratch_ += original.substr(0, location->offset);
    rewrite_scratch_ += authority;
    rewrite_scratch_ += original.substr(location->offset + location->length);

    logger_.Debug("DIAL: rewrote device {} LOCATION to reflector listener {}",
        location->endpoint, *reflector_authority);
    return {.action = DialRewrite::Action::ForwardRewritten, .payload = rewrite_scratch_};
}

void SsdpReflector::EvictStaleSessions() noexcept {
    // Wholesale, since every session sits on the same target leg.
    size_t removed = sessions_.size();
    if (target_if_.TakeReplaced()) {
        sessions_.clear();
    } else {
        // The target kept its identity but may have been re-addressed under the reservations.
        // Responders reply to the address the search went out from, and the reservation is bound
        // to it, so a session whose address is gone can never be answered.
        removed = std::erase_if(sessions_, [this](const Session& session) {
            const auto current = target_if_->SourceAddressFor(session.group);
            return !current || *current != session.reserved_address;
        });
    }

    if (removed == 0) {
        return;
    }
    logger_.Info("Dropped {} search session(s) whose reserved address on the target is gone", removed);
    if (sessions_.empty()) {
        eviction_timer_.Stop();  // nothing left to sweep
    }
}

void SsdpReflector::EvictExpired(std::chrono::steady_clock::time_point now) noexcept {
    const auto removed = std::erase_if(sessions_, [this, now](const Session& session) {
        const bool expired = session.expiry <= now;
        if (expired) {
            logger_.Debug("Removing session for searcher {} on reserved port {}",
                session.searcher, session.reservation.Port());
        }
        return expired;
    });
    if (removed > 0) {
        logger_.Debug("Evicted {} session(s); {} still active", removed, sessions_.size());
    }
    if (sessions_.empty()) {
        // Nothing left to sweep: stop. Safe self-unregister — the dispatcher defers a mid-fire
        // unregister to its post-walk sweep.
        eviction_timer_.Stop();
    }
}

} // namespace reflector
