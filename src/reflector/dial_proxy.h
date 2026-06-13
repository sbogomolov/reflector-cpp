#pragma once

#include "dispatcher.h"
#include "http_message.h"
#include "ip_endpoint.h"
#include "logger.h"
#include "tcp_socket.h"
#include "timer.h"
#include "util/no_move.h"
#include "util/stream_buffer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace reflector {

class Interface;

// The DIAL (DIscovery And Launch) application proxy. A DIAL-capable device (a smart TV) restricts
// its description/REST endpoints to its own subnet; this proxy mints a per-device TCP listener on the
// source interface's subnet, so a client there can reach the device across the reflector boundary.
// SSDP-agnostic: the SSDP path classifies DIAL traffic and splices the rewritten LOCATION authority
// this hands back. Owned by SsdpReflector as std::optional<DialProxy>, gated by config.dial.
//
// NoMove: a Connection's own methods are bound into its dispatcher Registrations (so each Connection is
// a node-stable callback target in connections_, and may not move under a live Delegate). An Endpoint
// holds the listener's accept Registration, but the accept routes through DialProxy::OnAccept by fd
// (a reverse lookup, FindEndpointByListenerFd) rather than an Endpoint method; the proxy itself is the
// OnAccept target, so it may not move either.
class DialProxy : NoMove {
public:
    // The two receive StreamBuffers of a Connection are capped here. The one load-bearing invariant is
    // the static_assert below: this must exceed HttpFraming::MAX_HEADER_BYTES so the framer's own
    // over-cap refusal (Feed -> nullopt) fires before a receive buffer can fill. Otherwise the
    // always-armed reader livelocks: a full buffer yields an empty ReserveTail, Feed stalls at
    // consumed == 0, and the level-triggered reactor spins with zero progress while the send-side
    // drop-and-close never fires to break it.
    static constexpr size_t MAX_RECV_BUFFER = 4 * 1024;
    static_assert(MAX_RECV_BUFFER > HttpFraming::MAX_HEADER_BYTES,
        "the receive buffer must exceed the header cap, or the always-armed reader livelocks otherwise");

    // Concurrent proxied client<->device pairs; a new accept past this is dropped. The cap that grows with
    // concurrent fetches (source clients x devices) and the only one with per-connection memory (two recv
    // buffers, lazily allocated). Fetches are short-lived + drop-new, so a transient storm just retries.
    static constexpr size_t MAX_CONNECTIONS = 64;
    // A connect that hasn't completed within this is reaped by the eviction timer.
    static constexpr std::chrono::seconds CONNECT_TIMEOUT{10};
    // An Open connection with no forwarded byte for this long is reaped (each forwarded byte refreshes its
    // idle deadline). Covers the half-open peer that completes the handshake then goes silent.
    static constexpr std::chrono::seconds IDLE_TIMEOUT{30};
    // An unreferenced Discovery listener idle for this long is evicted. Discovery is a brief sweep then idle,
    // so its grace is short — long enough to span a client's retries, short enough to free the listener soon.
    static constexpr std::chrono::seconds DISCOVERY_ENDPOINT_GRACE{60};
    // An unreferenced Rest listener idle for this long is evicted. Rest is the longer-lived role (a launched
    // app keeps polling its REST endpoint), so its grace is longer than the discovery grace.
    static constexpr std::chrono::seconds REST_ENDPOINT_GRACE{300};
    static_assert(REST_ENDPOINT_GRACE > DISCOVERY_ENDPOINT_GRACE, "Rest is the longer-lived role");
    // The eviction sweep period — how often the reaper runs while either map is non-empty.
    static constexpr std::chrono::seconds EVICTION_INTERVAL{5};
    // Distinct devices whose REST endpoint we proxy (minted from each description's Application-URL). One per
    // device; sized to cover a device-heavy home with headroom. Past it EnsureListener returns nullopt.
    static constexpr size_t MAX_REST_LISTENERS = 24;
    // Distinct device description endpoints, minted from the rewritten LOCATION. One per device — but the
    // description port is dynamic (changes on power-cycle), so a reboot briefly doubles a device's listener
    // until the short grace reaps it; sized above REST to absorb that doubling churn.
    static constexpr size_t MAX_DISCOVERY_LISTENERS = 32;

    // Borrows the dispatcher (reached via PacketDispatcher::UnderlyingDispatcher(), as the SSDP eviction
    // timer does) and the source/target interfaces it binds/connects from. The interfaces and the
    // dispatcher must outlive this proxy. DIAL is IPv4-only.
    DialProxy(Dispatcher& dispatcher, const Interface& source_if, const Interface& target_if,
        std::string logger_name);

    // Find-or-create a Discovery listener for a device's description endpoint; returns the reflector
    // authority (source_if-addr:listener-port) to advertise in the rewritten LOCATION, or nullopt on a
    // cap/bind failure (the LOCATION is then injected unchanged — discovery still works via the router).
    // Refreshes the endpoint's last_active.
    [[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(const IpEndpoint& device);

    // React to a possible source-interface address change. Every listener is bound to source_if's V4
    // address as it was at mint time, so once that address changes (or goes away) the listener's
    // advertised authority is dead — and because each rewrite refreshes the endpoint's last_active, a
    // chatty device would keep its stale listener alive past the eviction grace forever. Drops every
    // listener whose bind address no longer matches source_if's current V4 source (and the connections
    // pinned to it) so the next rewrite re-mints against the fresh address. Called by SsdpReflector from
    // the reflector OnInterfaceChanged broadcast; runs outside any connection fd handler, so erasing
    // connections here is safe.
    void OnInterfaceChanged() noexcept;

private:
    friend class DialProxyTest;  // reaches the internal EnsureRestListener (whose only caller is the u2c rewrite)

    // A discovered device's ip:port plus the reflector listener minted for it. A plain aggregate: nothing
    // binds a Delegate to an Endpoint (the accept routes through DialProxy::OnAccept by fd, not an Endpoint
    // method), so it needs no constructor and stays node-stable in endpoints_ purely by living in the map.
    struct Endpoint {
        enum class Role { Discovery, Rest };

        IpEndpoint device;
        Role role;
        TcpSocket listener;  // bound to source_if-addr:ephemeral
        std::chrono::steady_clock::time_point last_active;
        size_t active_connections = 0;  // Connections pinned to this device; 0 = reapable, no connection scan
        Dispatcher::Registration accept_reg;  // declared LAST: dropped first on erase
    };

    // One proxied client<->device pair. NoMove and node-stable in connections_ (its own methods are bound
    // into client_reg/upstream_reg, so a move would dangle them). The client is established at accept; the
    // upstream starts a non-blocking connect (egress-pinned) and is established on completion.
    struct Connection : NoMove {
        Connection(DialProxy& proxy, Endpoint& owning_endpoint, TcpSocket client_socket,
            TcpSocket upstream_socket, std::chrono::steady_clock::time_point connect_deadline);
        ~Connection() noexcept;  // --endpoint.active_connections (the ctor ++'d it): the eviction refcount

        // Writable-edge handlers. The client is established at accept (just drain); the upstream resolves its
        // connect first, promoting the connection to Open. Both share Drain, which assumes the caller already
        // checked `closed`. Any error aborts (deferred).
        void OnClientWritable(int) noexcept;
        void OnUpstreamWritable(int) noexcept;
        void Drain(TcpSocket& sock) noexcept;

        // Read handlers: one chunk per readable edge through the shared forward helper. Client request ->
        // upstream uses c2u; device response -> client uses u2c.
        void OnClientReadable(int) noexcept { Forward(client, c2u_rx, c2u, upstream); }
        void OnUpstreamReadable(int) noexcept { Forward(upstream, u2c_rx, u2c, client); }

        // Read one chunk from `from` into `rx`, then drain whole framed messages out of `rx` into `to`.
        // Read is the authoritative error sink (peer EOF/error -> Abort); a malformed frame or a send that
        // overflows `to`'s buffer is drop-and-close. One read per edge; the level-triggered reactor re-fires
        // while more is pending.
        void Forward(TcpSocket& from, StreamBuffer& rx, HttpFraming& framer, TcpSocket& to) noexcept;

        // c2u Host rewrite: the client reached the reflector listener, so its request Host is the reflector
        // authority; always rewrite it to the pinned `device` so the upstream sees itself as Host. The parsed
        // `found` authority is irrelevant — the request always targets the device.
        std::optional<IpEndpoint> RewriteHost(const IpEndpoint&) noexcept { return endpoint.device; }

        // u2c Application-URL/Location rewrite: the device names its OWN Rest authority, unroutable across the
        // reflector boundary, so mint (re-entrantly) a reflector Rest listener for it and rewrite to that. A
        // mint failure (Rest cap/bind) Aborts the connection (deferred teardown — safe even mid-Feed; see the
        // definition) and returns nullopt; the framer then leaves the header unchanged, but the now-closed
        // connection makes Forward bail before that header (the device's real authority) reaches the client.
        // Asymmetric with SSDP's benign fallback: there is no router on the TCP path.
        std::optional<IpEndpoint> RewriteRestAuthority(const IpEndpoint& found) noexcept;

        // Forward write interest to the reactor (the only write toggle). A false return means the fd isn't
        // watched — the connection can no longer flush or be serviced, so tear it down, like every other
        // I/O failure on this path.
        void Sync(TcpSocket& sock) noexcept;

        // Deferred teardown from inside a handler: drop both Registrations now (kills any level-triggered
        // spin) and half-close both sockets so the FIN reaches the peers immediately, but do NOT erase the
        // node — erasing the node whose handler is on the stack is a UAF. The node lingers inert (closed,
        // fds shut down but still open) until the eviction timer reaps it and RAII closes the fds.
        void Abort() noexcept;

        DialProxy& owner;  // reaches owner.dispatcher_ for Sync and owner.EnsureRestListener for the u2c rewrite
        Endpoint& endpoint;  // the device's endpoint; ctor ++active_connections, dtor -- (eviction refcount)
        TcpSocket client, upstream;
        HttpFraming c2u, u2c;
        StreamBuffer c2u_rx{MAX_RECV_BUFFER}, u2c_rx{MAX_RECV_BUFFER};
        bool closed = false;
        std::chrono::steady_clock::time_point deadline;
        Dispatcher::Registration client_reg, upstream_reg;  // declared LAST: dropped first on erase
    };

    // The u2c Application-URL/Location rewrite promotes a Discovery device to Rest the first time it
    // mints a REST listener; both roles funnel through EnsureListener.
    [[nodiscard]] std::optional<IpEndpoint> EnsureRestListener(const IpEndpoint& device);

    // Find-or-create the Endpoint for `device`: refresh last_active, promote Discovery -> Rest if `role`
    // asks, and return its reflector authority. At first sight: Listen on source_if-addr:ephemeral, read
    // the port, emplace the (node-stable) Endpoint, register its accept handler, return the authority.
    // Enforces the role's cap (over cap -> nullopt, no listener leaked) and source_if SourceAddress(V4)
    // (nullopt -> nullopt).
    [[nodiscard]] std::optional<IpEndpoint> EnsureListener(const IpEndpoint& device, Endpoint::Role role);

    // The listener accept handler (registered by-fd, so it reverse-looks-up the Endpoint): accept the
    // client, egress-pinned-connect to the device, emplace the Connection, register both fds. Drops the
    // new accept at MAX_CONNECTIONS and rolls back a half-registered pair.
    void OnAccept(int listener_fd) noexcept;

    // The Endpoint whose listener owns `fd` (nullptr if none). A linear scan over endpoints_ (capped at a
    // couple dozen) — the accept callback is by-fd, so it has no Endpoint handle to start from.
    [[nodiscard]] Endpoint* FindEndpointByListenerFd(int fd) noexcept;

    // Count of endpoints currently in `role` — checked against the role's cap before a new mint.
    [[nodiscard]] size_t CountInRole(Endpoint::Role role) const noexcept;

    // The eviction-timer callback (its signature is the timer's). Reaps, in one pass: deferred-teardown
    // `closed` Connections and Connections past their `deadline` (connect timeout while Connecting, idle
    // timeout while Open), then unreferenced Endpoints idle past their role grace. Connections are swept
    // first so the endpoint "unreferenced" check sees the post-reap connection set. Self-stops the timer
    // once both maps are empty. `now` is the reactor's fire-cycle time, also the test seam.
    void EvictExpired(std::chrono::steady_clock::time_point now) noexcept;

    Logger logger_;  // "DialProxy:{name}:{src}->{tgt}" — passed in by SsdpReflector
    Dispatcher& dispatcher_;
    const Interface& source_if_;
    const Interface& target_if_;

    // Keyed by the device endpoint via std::hash<IpEndpoint>. Node-stable so a FindEndpointByListenerFd
    // result stays valid across an unrelated mint, and so OnAccept can re-enter EnsureRestListener (which
    // inserts here) while holding an Endpoint* — a vector realloc would dangle it.
    std::unordered_map<IpEndpoint, Endpoint> endpoints_;

    // Node-stable, id-keyed (never a vector — a realloc dangles each Connection's bound Registrations).
    // A monotonic id so a reaped-and-reused fd never collides with a live connection's key.
    std::unordered_map<uint64_t, Connection> connections_;
    uint64_t next_connection_id_ = 1;

    // Started lazily on the first Endpoint mint, self-stopped by EvictExpired once both maps empty.
    // Declared LAST so RAII stops it before the maps it sweeps are destroyed.
    Timer eviction_timer_;
};

} // namespace reflector
