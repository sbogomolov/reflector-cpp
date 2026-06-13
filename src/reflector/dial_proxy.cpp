#include "dial_proxy.h"

#include "interface.h"
#include "ip_address.h"
#include "logger.h"
#include "util/delegate.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace reflector {

DialProxy::DialProxy(Dispatcher& dispatcher, const Interface& source_if, const Interface& target_if,
    std::string logger_name)
        : logger_{std::move(logger_name)}
        , dispatcher_{dispatcher}
        , source_if_{source_if}
        , target_if_{target_if}
        , eviction_timer_{dispatcher} {}

std::optional<IpEndpoint> DialProxy::EnsureDiscoveryListener(const IpEndpoint& device) {
    return EnsureListener(device, Endpoint::Role::Discovery);
}

void DialProxy::OnInterfaceChanged() noexcept {
    const auto current = source_if_.SourceAddress(IpAddress::Family::V4);

    // A listener is stale when its bind address no longer matches source_if's current V4 source — the
    // address changed under it, or vanished (current == nullopt makes every listener stale). Drop the
    // connections pinned to a stale endpoint FIRST: a Connection borrows Endpoint& and its dtor
    // decrements that endpoint's active_connections, so erasing the endpoint with a live connection
    // still pinned would dangle the reference. The predicate is the same on both sweeps, so a dropped
    // connection's endpoint is always among the endpoints dropped below.
    const auto is_stale = [&current](const Endpoint& endpoint) {
        return current != endpoint.listener.LocalEndpoint().addr;
    };
    std::erase_if(connections_, [&](const auto& entry) { return is_stale(entry.second.endpoint); });
    const auto dropped = std::erase_if(endpoints_, [&](const auto& entry) { return is_stale(entry.second); });

    if (dropped > 0) {
        logger_.Info("source_if V4 source is now {}; dropped {} stale DIAL listener(s) for re-mint",
            current ? current->ToString() : "none", dropped);
    }
    if (connections_.empty() && endpoints_.empty()) {
        // Nothing left to sweep — stop the reaper (it otherwise self-stops on its next fire).
        eviction_timer_.Stop();
    }
}

std::optional<IpEndpoint> DialProxy::EnsureRestListener(const IpEndpoint& device) {
    return EnsureListener(device, Endpoint::Role::Rest);
}

std::optional<IpEndpoint> DialProxy::EnsureListener(const IpEndpoint& device, Endpoint::Role role) {
    const auto now = std::chrono::steady_clock::now();

    // Reuse an existing listener for this device: refresh it, promote Discovery -> Rest if asked (a
    // device referenced as both roles is pinned to Rest, the longer-lived grace), and hand back its
    // authority. The listener's bind address is the source_if address it was minted on.
    if (const auto it = endpoints_.find(device); it != endpoints_.end()) {
        auto& endpoint = it->second;
        endpoint.last_active = now;
        // Promoting Discovery -> Rest moves the device into the Rest tally (it isn't counted there yet), so
        // the Rest cap must gate it here too — otherwise a promotion silently overruns MAX_REST_LISTENERS.
        // Over cap: refuse without demoting (close-don't-forward, as a fresh over-cap mint does).
        if (role == Endpoint::Role::Rest && endpoint.role == Endpoint::Role::Discovery) {
            if (CountInRole(Endpoint::Role::Rest) >= MAX_REST_LISTENERS) {
                logger_.Error("Cannot promote {} to rest: rest listener cap reached", device);
                return std::nullopt;
            }
            endpoint.role = Endpoint::Role::Rest;
        }
        return endpoint.listener.LocalEndpoint();
    }

    size_t role_cap = role == Endpoint::Role::Discovery
        ? MAX_DISCOVERY_LISTENERS
        : MAX_REST_LISTENERS;
    if (CountInRole(role) >= role_cap) {
        logger_.Error("Cannot proxy {}: {} listener cap reached", device,
            role == Endpoint::Role::Rest ? "rest" : "discovery");
        return std::nullopt;
    }

    auto listener = TcpSocket::Listen(source_if_, IpAddress::Family::V4);
    if (!listener) {
        logger_.Error("Cannot proxy {}: failed to open a listener", device);  // Listen logged the cause
        return std::nullopt;
    }
    const auto authority = listener->LocalEndpoint();
    const int listener_fd = listener->Fd();

    // Construct the node in place (Endpoint is NoMove): try_emplace builds it once in the final map node
    // — no move follows, so the accept handler we register next binds a stable address.
    const auto [it, inserted] = endpoints_.try_emplace(device, device, role, std::move(*listener), now);
    auto& endpoint = it->second;

    auto registration = dispatcher_.Register(listener_fd, CreateDelegate<&DialProxy::OnAccept>(this));
    if (!registration.IsValid()) {
        logger_.Error("Cannot proxy {}: failed to register the listener", device);
        endpoints_.erase(it);  // drops the listener (registration was never valid)
        return std::nullopt;
    }
    endpoint.accept_reg = std::move(registration);

    // Start the eviction sweep on the first entry in either map; an Endpoint always precedes a Connection
    // (every Connection needs a listener first), so this mint is the earliest hook. EvictExpired stops it
    // once both maps empty, so the reactor isn't woken every interval while there's nothing to sweep. The
    // guard keeps a later mint from restarting the interval.
    if (!eviction_timer_.IsRunning()) {
        eviction_timer_.Start(EVICTION_INTERVAL, CreateDelegate<&DialProxy::EvictExpired>(this));
    }

    logger_.Debug("Created {} listener {} for {}", role == Endpoint::Role::Rest ? "rest" : "discovery",
        authority, device);
    return authority;
}

DialProxy::Connection::Connection(DialProxy& proxy, Endpoint& owning_endpoint, TcpSocket client_socket,
    TcpSocket upstream_socket, std::chrono::steady_clock::time_point connect_deadline)
        : owner{proxy}
        , endpoint{owning_endpoint}
        , client{std::move(client_socket)}
        , upstream{std::move(upstream_socket)}
        // `this` in a ctor init-list is the object's FINAL address — valid because try_emplace constructs the
        // node in place. c2u rewrites the client request's Host to the pinned device; u2c rewrites the device
        // response's Application-URL/Location to a freshly-minted reflector Rest listener (dropping the
        // connection if the mint fails).
        , c2u{CreateDelegate<&Connection::RewriteHost>(this)}
        , u2c{CreateDelegate<&Connection::RewriteRestAuthority>(this)}
        , deadline{connect_deadline} {
    ++endpoint.active_connections;  // refcount against the endpoint; the dtor decrements (RAII eviction count)
}

DialProxy::Connection::~Connection() noexcept {
    --endpoint.active_connections;
}

void DialProxy::Connection::Abort() noexcept {
    closed = true;
    client_reg = {};       // unwatch both fds FIRST (kills any level-triggered read-spin); shutting down a
    upstream_reg = {};     // still-watched fd would re-fire its EOF edge into a handler that only re-checks closed
    client.Shutdown();     // then FIN both peers now, so a client is not blocked until eviction reaps the node
    upstream.Shutdown();
}

void DialProxy::Connection::Sync(TcpSocket& sock) noexcept {
    if (!owner.dispatcher_.SetWriteInterest(sock.Fd(), sock.WantsWrite())) {
        owner.logger_.Error("Cannot set write interest for fd {} (device {}); aborting connection",
            sock.Fd(), endpoint.device);
        Abort();
    }
}

void DialProxy::Connection::OnClientWritable(int) noexcept {
    if (closed) {
        return;
    }
    Drain(client);  // the client is established at accept; nothing to connect
}

void DialProxy::Connection::OnUpstreamWritable(int) noexcept {
    if (closed) {
        return;
    }
    if (upstream.IsConnecting()) {  // the upstream is the only socket that connects; resolve it
        if (!upstream.FinishConnect()) {
            Abort();
            return;
        }
    }
    Drain(upstream);  // refreshes the deadline — including the connect-timeout -> idle-deadline transition
}

// Handle a writable edge: flush `sock`'s buffered tail and refresh the idle deadline. The edge is forward
// progress — an outbound drain, or the upstream's connect completing (a no-op flush only in that case, when
// nothing was queued). A write error drops the connection; the two callers check `closed` first.
void DialProxy::Connection::Drain(TcpSocket& sock) noexcept {
    if (!sock.Flush()) {  // write error -> drop-and-close
        Abort();
        return;
    }
    deadline = std::chrono::steady_clock::now() + IDLE_TIMEOUT;
    Sync(sock);
}

void DialProxy::Connection::Forward(
    TcpSocket& from, StreamBuffer& rx, HttpFraming& framer, TcpSocket& to) noexcept {
    if (closed) {
        return;
    }

    // One read per edge into rx's tail (empty when rx is full — Read of an empty span is fine). Read is the
    // authoritative error sink: a peer EOF/error tears the connection down here, not on the write side.
    const auto tail = rx.ReserveTail();
    const auto r = from.Read(tail);
    if (r.status == IoStatus::Closed || r.status == IoStatus::Error) {
        Abort();
        return;
    }
    rx.Commit(r.bytes);  // WouldBlock -> bytes == 0, Commit(0) is a no-op
    // Forward progress refreshes the idle deadline — but only once the upstream is connected: while it is
    // connecting, `deadline` is the connect timeout, and a client that speaks first (it is established at
    // accept) must not push it out to the longer idle grace. OnUpstreamWritable sets the idle deadline the
    // instant the connect completes.
    if (r.bytes > 0 && !upstream.IsConnecting()) {
        deadline = std::chrono::steady_clock::now() + IDLE_TIMEOUT;
    }

    // Drain whole framed messages out of rx into `to`. No ReserveTail in this loop: it Compacts and would
    // invalidate the live `body` slice the framer hands back.
    while (true) {
        const auto live = rx.View();
        const std::string_view input{reinterpret_cast<const char*>(live.data()), live.size()};
        const auto out = framer.Feed(input);
        if (!out) {  // malformed / over-cap
            Abort();
            return;
        }
        if (out->consumed == 0) {  // incomplete header: keep the bytes, wait for the next edge
            break;
        }
        // Close-don't-forward: a u2c Rest-listener mint failed inside Feed and Aborted us, so the header
        // still carries the device's unroutable authority. Bail BEFORE the Sends rather than leak it to the
        // client. Only the u2c rewrite ever closes us here; on c2u this check is a uniform no-op.
        if (closed) {
            return;
        }
        // Forward one framed message, Consuming only after it's fully handed to `to`: `header` is framer
        // scratch (clobbered by the next Feed) and `body` is an rx slice (invalidated by Consume). A header
        // rides out with its body in a single sendmsg (zero-copy, via the scatter-gather Send); a header-less
        // body continuation (a streamed body) takes the plain single-span Send. Overflow/Error -> drop-and-
        // close, the sole backpressure: read stays armed, so a persistently slow `to` ends at the 8KB send cap
        // here, not by throttling this reader.
        const auto header_bytes = std::as_bytes(std::span{out->header.data(), out->header.size()});
        const auto body_bytes = std::as_bytes(std::span{out->body.data(), out->body.size()});
        auto status = SendStatus::Ok;
        if (!out->header.empty()) {
            const std::array parts{header_bytes, body_bytes};
            status = to.Send(parts);
        } else {
            status = to.Send(body_bytes);  // body-only continuation: nothing to coalesce
        }
        if (status != SendStatus::Ok) {
            Abort();
            return;
        }
        rx.Consume(out->consumed);
    }

    Sync(to);  // `to` may have buffered a tail; arm/disarm its write interest (`from`'s is unchanged)
}

std::optional<IpEndpoint> DialProxy::Connection::RewriteRestAuthority(const IpEndpoint& found) noexcept {
    if (closed) {
        return std::nullopt;  // a prior REST header in this message already Aborted the connection; don't
                              // re-enter EnsureRestListener (Listen+Register) to mint a listener the dropped
                              // message will never deliver.
    }
    const auto authority = owner.EnsureRestListener(found);
    if (!authority) {
        // Close-don't-forward: the device's authority can't be made routable, so drop the connection now.
        // Safe from inside Feed — Abort only drops the dispatcher Registrations (PollOnce copied the firing
        // read delegate) and leaves this node, its framer, and rx alive for Feed to finish on.
        Abort();
    }
    return authority;
}

DialProxy::Endpoint* DialProxy::FindEndpointByListenerFd(int fd) noexcept {
    const auto it = std::ranges::find_if(
        endpoints_, [fd](const auto& entry) { return entry.second.listener.Fd() == fd; });
    return it != endpoints_.end() ? &it->second : nullptr;
}

void DialProxy::OnAccept(int listener_fd) noexcept {
    const auto now = std::chrono::steady_clock::now();

    auto* ep = FindEndpointByListenerFd(listener_fd);
    if (ep == nullptr) {
        logger_.Error("Accept on fd {} has no owning endpoint; ignoring", listener_fd);
        return;
    }
    ep->last_active = now;

    auto client = ep->listener.Accept();
    if (!client) {
        return;  // EAGAIN (nothing pending) or a real accept error already logged inside Accept()
    }

    if (connections_.size() >= MAX_CONNECTIONS) {
        logger_.Warning("Dropping accept for {}: connection cap reached", ep->device);
        return;  // the accepted client TcpSocket drops here -> RAII close
    }

    auto upstream = TcpSocket::Connect(ep->device, &target_if_);
    if (!upstream) {
        logger_.Error("Dropping accept for {}: failed to start the upstream connect", ep->device);
        return;
    }

    const int client_fd = client->Fd();
    const int upstream_fd = upstream->Fd();
    const auto id = next_connection_id_++;
    const auto deadline = now + CONNECT_TIMEOUT;

    const auto [it, inserted] =
        connections_.try_emplace(id, *this, *ep, std::move(*client), std::move(*upstream), deadline);
    auto& conn = it->second;

    // Register both fds into LOCAL Registrations first; only on a clean pair do they move into the
    // Connection. The client is established at accept (WantsWrite() false); the upstream is connecting
    // (WantsWrite() true), so its writable edge is armed to learn of connect-completion.
    auto client_reg = dispatcher_.Register(client_fd, Dispatcher::FdCallbacks{
        .read = CreateDelegate<&Connection::OnClientReadable>(&conn),
        .write = CreateDelegate<&Connection::OnClientWritable>(&conn),
        .write_armed = conn.client.WantsWrite()});
    auto upstream_reg = dispatcher_.Register(upstream_fd, Dispatcher::FdCallbacks{
        .read = CreateDelegate<&Connection::OnUpstreamReadable>(&conn),
        .write = CreateDelegate<&Connection::OnUpstreamWritable>(&conn),
        .write_armed = conn.upstream.WantsWrite()});

    if (!client_reg.IsValid() || !upstream_reg.IsValid()) {
        // Reset the locals FIRST so any valid half unregisters while its fd is still open, THEN erase to
        // close the sockets.
        client_reg = {};
        upstream_reg = {};
        connections_.erase(it);
        logger_.Error("Dropping accept for {}: failed to register the connection fds", ep->device);
        return;
    }

    conn.client_reg = std::move(client_reg);
    conn.upstream_reg = std::move(upstream_reg);
    logger_.Debug("Opened connection {} (client fd {}, upstream fd {}) for {}", id, client_fd, upstream_fd,
        ep->device);
}

size_t DialProxy::CountInRole(Endpoint::Role role) const noexcept {
    return static_cast<size_t>(std::ranges::count_if(
        endpoints_, [role](const auto& entry) { return entry.second.role == role; }));
}

void DialProxy::EvictExpired(std::chrono::steady_clock::time_point now) noexcept {
    // Reap connections first: a deferred-teardown `closed` node (its sockets/regs already dropped at Abort,
    // erased here so RAII frees the rest) or one past its `deadline` (connect timeout while Connecting, idle
    // timeout while Open). Erasing immediately is safe: the timer runs outside any fd handler, so no
    // Connection method is on the stack. Sweeping connections before endpoints means each reaped Connection's
    // dtor decrements its endpoint's active_connections, so the endpoint pass below sees current counts.
    const auto connections_reaped = std::erase_if(connections_, [now](const auto& entry) {
        const auto& conn = entry.second;
        return conn.closed || now >= conn.deadline;
    });

    // Reap unreferenced endpoints idle past their role grace. An endpoint is referenced while a Connection is
    // pinned to it: each Connection ++active_connections in its ctor and -- in its dtor, and the connection
    // reap above already ran the dtors of everything it erased, so the count is current here.
    const auto endpoints_reaped = std::erase_if(endpoints_, [now](const auto& entry) {
        const auto& endpoint = entry.second;
        const auto grace = endpoint.role == Endpoint::Role::Rest ? REST_ENDPOINT_GRACE : DISCOVERY_ENDPOINT_GRACE;
        if (now < endpoint.last_active + grace) {
            return false;
        }
        return endpoint.active_connections == 0;  // reap only if no Connection is still pinned to it
    });

    if (connections_reaped > 0 || endpoints_reaped > 0) {
        logger_.Debug("Evicted {} connection(s) and {} listener(s); {} connection(s), {} listener(s) remain",
            connections_reaped, endpoints_reaped, connections_.size(), endpoints_.size());
    }

    if (connections_.empty() && endpoints_.empty()) {
        // Nothing left to sweep: stop. Safe self-unregister — the dispatcher defers a mid-fire
        // unregister to its post-walk sweep.
        eviction_timer_.Stop();
    }
}

} // namespace reflector
