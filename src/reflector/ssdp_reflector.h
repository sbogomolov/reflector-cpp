#pragma once

#include "config.h"
#include "ip_address.h"
#include "link_socket.h"
#include "mac_address.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "port_reservation.h"
#include "reflector.h"
#include "ssdp_message.h"
#include "timer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace reflector {

// Reflects SSDP (UPnP/DLNA discovery) between two interfaces. Captures on both source_if and
// target_if (joining each SSDP group on each — IPv4 has one group, IPv6 has two), then reflects
// directionally: M-SEARCH searches source->target, NOTIFY advertisements target->source. The
// target->source direction can be restricted to one device by its frame source MAC (config.mac).
// Both sockets must outlive this reflector. A unicast M-SEARCH 200 OK is reflected back to the
// searcher via a per-search reserved-port session (see the SSDP design doc).
class SsdpReflector : public Reflector {
public:
    SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const SsdpConfig& config);

private:
    static constexpr uint16_t SSDP_PORT = 1900;
    static constexpr uint8_t SSDP_TTL = 2;
    static constexpr size_t MAX_SESSIONS = 32;
    static constexpr std::chrono::seconds SESSION_GRACE{2};
    static constexpr std::chrono::seconds EVICTION_INTERVAL{1};

    // One in-flight client discovery awaiting unicast 200 OK replies; a client's retransmits reuse it.
    // The client is (searcher_ip, searcher_port) and the reserved port is reservation.Port(), so no
    // separate key is stored — sessions live in a small vector, found by linear scan. Move-only.
    struct Session {
        IpAddress searcher_ip;
        uint16_t searcher_port;
        MacAddress searcher_mac;
        std::chrono::steady_clock::time_point expiry;
        PortReservation reservation;
        PacketDispatcher::Registration capture;
    };

    [[nodiscard]] bool ValidateConfig(const SsdpConfig& config);
    void Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const SsdpConfig& config);
    // Joins one SSDP `group` on both sockets and registers both directions for it. Returns false
    // (after logging) if a join or registration fails.
    [[nodiscard]] bool SetUpGroup(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const IpAddress& group, const SsdpConfig& config);

    void OnSourcePacket(const Packet& packet) noexcept;  // source->target: reflect searches
    void OnTargetPacket(const Packet& packet) noexcept;  // target->source: reflect advertisements
    void OnUnicastResponse(const Packet& packet) noexcept;  // target: a captured 200 OK -> searcher
    // True if `packet` is an SSDP message of `kind` (and should be reflected). A payload that isn't an
    // SSDP request at all is logged and dropped (it shouldn't appear on the group); a message of the
    // other kind is dropped silently (normal bidirectional traffic).
    [[nodiscard]] bool ShouldReflect(const Packet& packet, SsdpMessageKind kind) noexcept;
    void Reflect(LinkSocket& egress, const Packet& packet) noexcept;
    // Reserves a port + registers the 200-OK capture for a new client, returning the session to add
    // (not yet in the table) or nullopt (after logging) if the cap is hit or a step fails.
    [[nodiscard]] std::optional<Session> MakeSession(const Packet& packet, IpAddress::Family family,
        std::chrono::steady_clock::time_point expiry);
    // The eviction-timer callback (its signature is the timer's): drops sessions past their expiry.
    // `now` is the reactor's fire-cycle time, which is also the test seam — FakeDispatcher::FireTimers
    // passes it, so expiry is driven without reading the real clock.
    void EvictExpired(std::chrono::steady_clock::time_point now) noexcept;

    LinkSocket& source_socket_;
    LinkSocket& target_socket_;
    PacketDispatcher& packet_dispatcher_;  // retained so OnSourcePacket can register response captures
    std::optional<MacAddress> config_mac_;  // device-scoping filter, reused on the response capture
    std::vector<Session> sessions_;
    Timer eviction_timer_;  // started only while sessions are in flight (lazy); declared last ->
                            // destroyed first (stops before the sessions it sweeps drop)
};

} // namespace reflector
