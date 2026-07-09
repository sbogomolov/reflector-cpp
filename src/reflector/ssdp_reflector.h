#pragma once

#include "config/config.h"
#include "dial_proxy.h"
#include "dynamic_family_reflector.h"
#include "ip_address.h"
#include "ip_endpoint.h"
#include "link_socket.h"
#include "mac_address.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "port_reservation.h"
#include "ssdp_message.h"
#include "timer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace reflector {

// Reflects SSDP (UPnP/DLNA discovery) between two interfaces. Captures on both source_if and
// target_if (joining each SSDP group on each — IPv4 has one group, IPv6 has two), then reflects
// directionally: M-SEARCH searches source->target, NOTIFY advertisements target->source. The
// target->source direction can be restricted to one device by its frame source MAC (config.mac).
// Both sockets must outlive this reflector. A unicast M-SEARCH 200 OK is reflected back to the
// searcher via a per-search reserved-port session. A family is reflected only while BOTH interfaces
// can send it; its group joins and captures come up / go down as addresses change
// (DynamicFamilyReflector).
class SsdpReflector : public DynamicFamilyReflector {
public:
    // Concurrent in-flight M-SEARCH sessions -- one reserved response port per search awaiting its
    // unicast 200 OK -- capped globally across all groups; a search past this is dropped before
    // reserving a port.
    static constexpr size_t MAX_SESSIONS = 64;

    SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const SsdpConfig& config);

    // Re-gate the per-family groups/captures (DynamicFamilyReflector), then let the DIAL proxy drop any
    // listener bound to a source address that has since changed — the proxy is otherwise blind to address
    // changes, so its listeners would advertise a dead authority.
    void OnInterfaceChanged() noexcept override;

private:
    static constexpr uint16_t SSDP_PORT = 1900;
    static constexpr uint8_t SSDP_TTL = 2;
    static constexpr std::chrono::seconds SESSION_GRACE{2};
    static constexpr std::chrono::seconds EVICTION_INTERVAL{1};

    // One in-flight client discovery awaiting unicast 200 OK replies; a client's retransmits reuse it.
    // Keyed by (searcher ip:port, group): one reflector spans every SSDP group, and each group's reply
    // port is bound to a scope-matched source (link-local for ff02::c, routable for ff05::c), so one
    // searcher's searches to two groups need separate sessions or the second scope's replies land on an
    // unwatched address. Sessions live in a small vector, found by linear scan. Move-only.
    struct Session {
        IpEndpoint searcher;
        IpAddress group;
        MacAddress searcher_mac;
        std::chrono::steady_clock::time_point expiry;
        PortReservation reservation;
        PacketDispatcher::Registration capture;
    };

    [[nodiscard]] bool ValidateConfig(const SsdpConfig& config);
    void Initialize(const SsdpConfig& config);
    // Joins every SSDP group of `family` (IPv4 has one, IPv6 has two) on both sockets and registers
    // both directions for each.
    [[nodiscard]] bool BringUpFamily(IpAddress::Family family) override;
    // Joins one SSDP `group` on both sockets and registers both directions, into `setup`. Returns
    // false (after logging, nothing pushed) if a join or registration fails.
    [[nodiscard]] bool SetUpGroup(const IpAddress& group, FamilySetup& setup);

    void OnSourcePacket(const Packet& packet) noexcept;  // source->target: reflect searches
    void OnTargetPacket(const Packet& packet) noexcept;  // target->source: reflect advertisements
    void OnUnicastResponse(const Packet& packet) noexcept;  // target: a captured 200 OK -> searcher
    // True if `packet` is an SSDP message of `kind` (and should be reflected). A payload that isn't an
    // SSDP request at all is logged and dropped (it shouldn't appear on the group); a message of the
    // other kind is dropped silently (normal bidirectional traffic).
    [[nodiscard]] bool ShouldReflect(const Packet& packet, SsdpMessageKind kind) noexcept;
    // When the DIAL proxy is enabled and `payload` is a DIAL advertisement/response, rewrites its LOCATION
    // authority (the device -> a minted source_if listener) so a source client reaches the device's
    // description endpoint across the boundary, returning the rewritten bytes. nullopt -> forward `payload`
    // unchanged: proxy disabled, not a DIAL message, no/invalid LOCATION, or the listener mint hit a
    // cap/bind failure (all benign — the original LOCATION still resolves for an on-subnet client).
    [[nodiscard]] std::optional<std::string> RewriteDialLocation(std::span<const std::byte> payload) noexcept;
    // Reserves a port + registers the 200-OK capture for a new client, returning the session to add
    // (not yet in the table) or nullopt (after logging) if the cap is hit or a step fails.
    [[nodiscard]] std::optional<Session> MakeSession(const Packet& packet,
        std::chrono::steady_clock::time_point expiry);
    // The eviction-timer callback (its signature is the timer's): drops sessions past their expiry.
    // `now` is the reactor's fire-cycle time, which is also the test seam — FakeDispatcher::FireTimers
    // passes it, so expiry is driven without reading the real clock.
    void EvictExpired(std::chrono::steady_clock::time_point now) noexcept;

    LinkSocket* source_socket_;
    LinkSocket* target_socket_;
    PacketDispatcher* packet_dispatcher_;  // retained so OnSourcePacket can register response captures
    std::optional<MacAddress> config_mac_;  // device-scoping filter, reused on the response capture
    std::optional<DialProxy> dial_proxy_;  // the DIAL app proxy, engaged only when config.dial (IPv4-only)
    std::vector<Session> sessions_;
    Timer eviction_timer_;  // started only while sessions are in flight (lazy); declared last ->
                            // destroyed first (stops before the sessions it sweeps drop)
};

} // namespace reflector
