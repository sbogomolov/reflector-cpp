# SSDP reflection — step 3 (DIAL application proxy)

**Status:** design draft, pending user review
**Date:** 2026-06-01
**Scope:** Step 3 of the 3-step SSDP roadmap (multicast forwarding → unicast proxy → **DIAL proxy**).
Builds on step 2's `SsdpReflector` (on `main`); see `2026-05-30-ssdp-unicast-proxy-design.md`.

## 1. Goal and scope

Steps 1–2 make SSDP *discovery* work cross-segment: a source-side client's `M-SEARCH` reaches
target-side devices and their unicast `200 OK` (and multicast `NOTIFY`) replies come back, so the
client now sees the device's `LOCATION` URL. But for **DIAL** (UPnP "Discovery And Launch", how a
phone's YouTube app launches YouTube on a TV) discovery is only the first hop. After it, the client
opens a **TCP/HTTP** connection to the device to fetch its description and drive the DIAL REST API —
and that connection cannot cross the segments today.

The driving case: the user's **LG webOS TV accepts DIAL connections only from its own subnet.** Today
a router NAT masquerades the client's connection onto the TV's subnet so the TV accepts it. Step 3's
goal is to make the **reflector self-contained** — DIAL works through the reflector alone, with no
router NAT rule — so the deployment is one config and portable to any host. Once step 3 lands, the
two segments need no IP route between them for DIAL.

**Opt-in, default off.** DIAL is a `dial = true` flag on an existing SSDP entry (§9). It opens
listening TCP sockets and does L7 HTTP rewriting — more invasive than UDP reflection — so it is off
unless explicitly enabled. It reuses the entry's `source_if` (client side), `target_if` (device
side), `address_family`, and `mac` filter.

This design is grounded in a packet capture of the user's actual LG TV (a YouTube cast: discovery →
description → launch → stop). The empirical facts that shaped it are in §2.2.

## 2. The core problem and why this mechanism

### 2.1 Why terminate TCP (and why not raw-socket packet proxying)

The reflector today is pure L2/UDP: `RawSocket` captures and injects Ethernet frames over
AF_PACKET / BPF; there are no kernel TCP sockets in the data path. The tempting reuse is to proxy
DIAL's TCP at the packet level with the same raw sockets — no kernel TCP, no per-connection
machinery. **That path is not viable, and it is harder, not easier.** The decisive reason:

> **The kernel RST cannot be defeated without a real listening socket — and a listening socket _is_
> TCP termination.** When the client connects to the reflector's own `source_if` IP (the only address
> it can reach once the router NAT is gone), the host kernel sees a `SYN` to a local address with no
> listener and replies `RST`, killing the connection. This is the TCP analog of the ICMP
> port-unreachable step 2 suppressed — but fatal, and step 2's `PortReservation` trick has no TCP
> equivalent: UDP is connectionless, so a bound-but-unread socket satisfies the kernel's lookup; TCP
> needs a real state machine to complete the handshake. The only in-model way to stop the RST and
> handle the connection is `listen()`/`accept()`, which is termination.

It compounds: the entire datapath is UDP-shaped (the BPF/AF_PACKET filters are UDP-only;
`Packet` carries no TCP sequence/ack/flags), so raw-socket DIAL would mean a *second* protocol stack
plus a hand-rolled single-threaded conntrack plus a **bidirectional sequence-rewriting ALG** (every
in-stream byte rewrite shifts all subsequent TCP sequence numbers in both directions). Terminating
TCP instead hands reassembly, retransmission, sequencing, and checksums to the kernel and leaves us
two independent connections with separate sequence spaces — so a header rewrite never perturbs
framing. **Terminating is the light path; the kernel does the hard parts.** (This verdict came from a
4-architect design panel that steelmanned the raw-socket approach and rejected it on the above.)

### 2.2 What the LG TV actually does (the capture)

A `tshark` follow of a real YouTube cast to the TV established the shape of the traffic. The facts
that drive the design:

| Fact | Evidence | Consequence |
|---|---|---|
| Two device endpoints on **different ports** | description `GET /` on `TV:1461`; REST on `TV:36866` | one reflector listener per endpoint |
| Description port is **dynamic** | `:1637` in one capture, `:1461` in another | ports are never hardcoded; learned from discovery / headers |
| `Application-URL` is **absolute**, a response **header**, on the REST port | `Application-URL: http://10.1.3.80:36866/apps` | rewrite this header → reflector authority |
| Launch `POST /apps/YouTube` → **`201`** with absolute **`LOCATION`** header | `LOCATION: http://10.1.3.80:36866/apps/YouTube/run` | rewrite this header too (same REST listener); header name case varies → case-insensitive |
| Device-description and REST bodies are **relative-only** | `SCPDURL=/WebOS_Dial/...`, `<link href="run"/>` | **no body rewriting** — relative URLs resolve against the reflector authority for free |
| Responses use **both** `Content-Length` (description) and `Transfer-Encoding: chunked` (REST) | streams 0 vs 1 | framing must handle both, but only to find message *boundaries* |
| Requests carry bodies | launch `POST` `Content-Length: 74` | handle Content-Length on the request leg |
| Client requests `Connection: keep-alive` | every request | support multiple messages per connection |
| TV accepts a **its-subnet source** for the full GET/POST round trip | client appears as `10.1.3.1` (router's TV-subnet address) | binding the upstream `connect()` to `target_if`'s address reproduces exactly what the NAT does today |

**The key simplification the capture buys:** every absolute URL the TV emits points at one of the two
endpoints we already hold a listener for, and every URL *inside a body* is relative. So the proxy
**rewrites only four headers** (all authority swaps `TV:port → reflector:listener`) and **never
touches a body byte** — no de-chunking, no body rewriting, no `Content-Length` recompute. The HTTP
layer is "parse the start line + headers, find the body framing, rewrite a tiny header set, stream
the rest through verbatim, loop for keep-alive." This is the right altitude: lighter than a general
HTTP/1.1 reverse proxy (no chunked re-framing, no body mutation), heavier than the strictest "reject
chunked / assume close" cut (which the capture disproves).

### 2.3 What the DIAL spec says (read from the v1.6.4 spec text)

The spec (§5.4) defines the REST endpoint as its own absolute URL advertised in the device-description
response, independent of the `LOCATION`:

> "the HTTP response SHALL contain an additional header field, `Application-URL`, the value of which
> SHALL be an absolute HTTP URL. This URL, minus any trailing … '/' character, identifies the DIAL
> REST Service … `Application-URL = "Application-URL" ":" absoluteURI`"

Because it is a full `absoluteURI` advertised separately, the REST service is an **independent endpoint
by design** — it MAY share a host:port with the device description or differ, and the spec mandates
neither. Both are conformant and both occur in the wild:
- Netflix's DIAL **reference server** serves the device description *and* the REST service on **one
  fixed port** (`#define DIAL_PORT (56789)`, a single mongoose server).
- The user's **LG webOS TV** uses **different** ports — a *dynamic* device-description port (`:1461`,
  was `:1637`) and a *stable* REST port (`:36866`).

So the proxy keys listeners by `ip:port` and handles both, collapsing to one listener when a device
shares a port. Three further spec facts pin design choices here:
- **Header-name matching is case-insensitive** ("matching of HTTP header names is case-insensitive") —
  the TV sends `LOCATION` upper-case and `Application-URL` mixed, so §4.3's rewrite is case-insensitive.
- The host portion **"SHALL either resolve to an IPv4 address or be an IPv4 address"** — DIAL is **IPv4
  by spec**; the rewritten authority uses the reflector's `source_if` IPv4 address (§12).
- The device-description and M-SEARCH responses **"SHALL NOT be redirected"** — so we must
  reverse-proxy transparently (rewrite + forward), never answer a `3xx`; our design does exactly that.

The spec sets **no** port-stability or lifetime requirement; its model is that a client re-fetches the
device description to obtain the `Application-URL`, not that it caches a port indefinitely. In the
capture the client re-fetches the description only *periodically* (every few seconds) and makes
*several* REST calls in between — e.g. `GET /apps/YouTube` then `POST /apps/YouTube` (launch)
back-to-back on the REST endpoint with **no** description fetch between them, each on its own
short-lived connection. So a listener is kept warm by **its own connection activity** (§5), not by
description fetches. Lifetime is therefore an engineering choice, so we give the two listener roles
**different lifetimes and caps** (§5). Sources: DIAL protocol spec v1.6.4 §5.4/§6; Netflix
`dial-reference` `server/dial_server.c`.

## 3. End-to-end data flow

With `dial = true`, for one cast:

```
DISCOVERY (UDP, existing SSDP paths + a LOCATION rewrite hook)
  client --M-SEARCH(dial)--> [reflector relays] --> dev
  dev --200 OK, LOCATION: http://dev:Pdesc/ --> [reflector captures on target_if]
      [DIAL] SsdpReflector: EnsureDiscoveryListener(dev:Pdesc) -> listener L1 on source_if;
      RewriteAuthority: LOCATION -> http://<source_if-addr>:L1/
  [reflector injects rewritten 200 OK to client]            (NOTIFY rewritten the same way)

DESCRIPTION FETCH (TCP, new)
  client --GET / --> reflector:L1
      DialProxy accepts on L1; connect() to dev:Pdesc bound to target_if's address
      forward request (rewrite Host -> dev:Pdesc); read response
      rewrite Application-URL: http://dev:Prest/apps -> http://<source_if-addr>:L2/apps
         (ensuring listener L2 -> dev:Prest); forward response (Content-Length body verbatim)

DIAL REST (TCP, new) -- query / launch / stop
  client --GET|POST|DELETE /apps/YouTube[/run] --> reflector:L2
      accept on L2; connect() to dev:Prest bound to target_if's address
      forward request (rewrite Host); read response
      rewrite LOCATION (on 201) -> http://<source_if-addr>:L2/apps/YouTube/run
      forward response (chunked body streamed verbatim)
```

(`dev` is the DIAL device — a TV, streaming stick, speaker, etc.) After launch the device streams
media via its own direct internet connection — **not** through the reflector. The proxy only carries
the small DIAL control HTTP.

## 4. Components

### 4.1 Reactor: write-interest control + always-armed read (`dispatcher.h`, `event_loop_dispatcher.{h,cpp}`) — new capability

The reactor is readability-only today (`Register(fd, on_readable)`), with read interest permanently on.
TCP adds **one** new control:
- **Writability** — a non-blocking `connect()` signals completion by becoming writable, and a
  partially-drained send buffer is flushed on the next writable. Write interest is *flippable*: armed
  when there is something to write (connect-in-progress, or a backed-up send buffer), disarmed when
  idle — on a *level-triggered* reactor an armed-but-idle writable socket re-fires forever (busy-spin).

**Read interest is NOT toggleable — read is always armed.** We considered a `SetReadInterest` pause for
backpressure, then removed it: DIAL is request/response with tiny payloads, so we use *drop-and-close*
backpressure (§4.4 — a bounded send buffer that aborts the connection on overflow) rather than lossless
read-pausing. Always-armed read buys two simplifications:
- An error/hangup surfaces as readability (`recv()` reveals it; the write path reads `SO_ERROR`), so the
  **always-armed read handler is the uniform home for teardown** — no error routing that depends on
  which direction happens to be armed.
- A registration's interest mask always includes read, so it can never collapse to "nothing armed": an
  errored fd can never busy-spin with no handler to consume the unmaskable `EPOLLERR`/`EPOLLHUP`. (An
  earlier `SetReadInterest`-based design needed an explicit guard to drop a both-directions-disarmed fd
  from the epoll set; always-armed read makes that guard unnecessary.)

This is the one genuinely new reactor capability — landed and tested **in isolation, exactly like the
step-2 timer commit**, before any DIAL code.

`Dispatcher` gains a write callback and dynamic arm/disarm of the **write** direction only:

```cpp
using OnWritableCallback = Delegate<void(int)>;  // fd became writable

// Read (required, ALWAYS armed) + optional write handler + write's initial arm state. A connecting
// socket sets {.write_armed = true} to learn of connect-completion; a backed-up send buffer arms it.
struct FdCallbacks {
    OnReadableCallback read{};   // required; {} DMI keeps a designated init that omits `write` clean
    OnWritableCallback write{};  // under GCC's -Wmissing-field-initializers. Bool last: no padding.
    bool write_armed = false;
};
// Register fd per `callbacks`; fails if `read` is unset (read is required). A non-virtual 2-arg
// convenience Register(fd, on_readable) forwards FdCallbacks{.read = on_readable}, so every existing
// readability-only consumer is unchanged.
[[nodiscard]] virtual Registration Register(int fd, FdCallbacks callbacks) = 0;

// Toggle writability notification for an already-registered fd (epoll EPOLL_CTL_MOD +/- EPOLLOUT;
// kqueue EVFILT_WRITE EV_ENABLE/EV_DISABLE). Disarm once the send buffer drains to avoid a
// writable-spin. Idempotent; false on an unknown fd.
virtual bool SetWriteInterest(int fd, bool enabled) noexcept = 0;
```

`EventLoopDispatcher::callbacks_` changes from `unordered_map<int, OnReadableCallback>` to
`unordered_map<int, Dispatcher::FdCallbacks>`. The poll loop folds `EPOLLERR`/`EPOLLHUP` into both
directions and dispatches: a readable event always invokes `read` (read is always armed and always
present); a writable event invokes `write` only when `write_armed`. The kqueue `EVFILT_WRITE` filter is
added only when write is armed, so a BPF capture fd (which rejects `EVFILT_WRITE` with `EINVAL`) is never
broken. Everything else (the fd key, RAII `Registration`, the copy-callback-before-invoke discipline) is
unchanged.

**Edge- vs level-triggered.** We keep the reactor level-triggered. Edge-triggered (`EPOLLET` / kqueue
`EV_CLEAR`) was evaluated as a way to leave write always armed without spinning, and rejected: it would
impose a drain-to-`EAGAIN` contract on *every* consumer — breaking the UDP-multicast/capture path's
bounded `MAX_PACKETS_PER_READ_EVENT` yield and the `maxevents=1` round-robin fairness — and replace LT's
self-healing re-fire with a silent-permanent-stall failure mode, the worst outcome for a months-uptime
embedded daemon. Flip condition: if this reactor ever sheds its UDP consumers and goes TCP-only,
edge-triggered becomes the better choice.

This commit ships with the **fake**: `FakeDispatcher` records the write callback + arm state and gains
`FireWritable(fd)` (mirroring `FireReadable`) so the proxy's connect/flush logic is driven
deterministically with no real sockets.

### 4.2 `ip_endpoint.h` + `tcp_socket.{h,cpp}` — value type + non-blocking TCP RAII (new)

**`IpEndpoint`** — a value type `{ IpAddress addr; uint16_t port; }` that owns the family-aware sockaddr
conversion, so `TcpSocket` (and DIAL) never branch on address family:
- `ToSockaddr(sockaddr_storage&, unsigned scope_id = 0) → socklen_t` — fills a `sockaddr_in` or
  `sockaddr_in6` (with `sin6_scope_id` for a link-scoped v6 connect); returns the length.
- `FromSockaddr(const sockaddr*) → optional<IpEndpoint>` — for `accept`/`getsockname` readback (reusing
  the existing `IpAddress::FromSockaddr`).

The only family-aware code lives here — which is what makes v4/v6 "almost free": `TcpSocket` just hands
the kernel a filled `sockaddr_storage` and reads one back.

**`TcpSocket`** — a **move-only** fd owner wrapping the non-blocking-TCP syscalls. It captures **nothing**
of the dispatcher: it holds only `{ fd, StreamBuffer, connecting }`. That inertness is the boundary
decision (§11 D12): `Accept()` returns a `TcpSocket` by value and a `Connection` (§4.4) stores two by
value, so the socket must move freely without dangling a callback — a self-registering socket would
dangle its own write `Delegate` on move (the `RawSocket` `NoMove` hazard). So the dispatcher
`Registration` and the one `SetWriteInterest` call live in the owning `Connection` (the stable callback
target); `TcpSocket` owns the **buffer and the truth** (`WantsWrite()`), the owner owns the toggle.

- `Listen(IpEndpoint bind) → optional<TcpSocket>` — `socket`/`SO_REUSEADDR`/`bind`/`listen` on the given
  endpoint (port 0 = ephemeral, read back via `LocalEndpoint`); `SO_REUSEADDR` lets a reused/fixed port
  rebind across a restart. Bound to the interface address (not `0.0.0.0`/`::`) so only the client subnet
  can reach it. `nullopt` on any syscall failure.
- `Accept() → optional<TcpSocket>` — accept the next client non-blocking (`accept4(SOCK_NONBLOCK)` /
  `accept`+`fcntl`) → an established `TcpSocket` (or `nullopt`/EAGAIN).
- `Connect(IpEndpoint dst, IpEndpoint bind, unsigned ifindex = 0) → optional<TcpSocket>` — non-blocking
  `socket`; bind to `bind` (`target_if`'s address) and, when `ifindex != 0`, pin egress to that interface
  (`SO_BINDTODEVICE` / `IP_BOUND_IF` — so a host with a route toward the client subnet still egresses out
  `target_if`); `ifindex` also scopes a link-local IPv6 destination. `connect` → `EINPROGRESS` leaves the
  socket **connecting**; `nullopt` if the connect can't be initiated.
- `IsConnecting()` / `FinishConnect()` — on the writable edge `FinishConnect` reads `SO_ERROR` and clears
  the connecting flag on success (logging a failed connect at `Error`); once established it is a no-op
  `Ok`, so it is safe on any writable edge and never read-and-clears a pending `Read` error. A connect
  *failure* also surfaces on the always-armed read as a `recv()` error, so either edge reaches teardown.
- `Read(span) → IoResult{status, bytes}` — bytes moved (`Ok`), `WouldBlock` (EAGAIN), `Closed` (orderly
  EOF — read-only), or `Error`. `Read` and the internal `WriteSome` share this `IoResult`.
- `Send(span) → SendStatus` — write what the kernel takes now, copy any unsent tail into the **bounded
  outbound `StreamBuffer`** (capped at the fixed `MAX_SEND_BUFFER`, 8 KB); `Flush()` drains it on a later
  writable. Returns `Ok` / `Overflow` / `Error`; on `Overflow` the owner aborts (drop-and-close, §4.4).
  `Send` does **not** toggle write interest — it exposes `WantsWrite()` (`connecting || !buffer.empty()`)
  and the owner forwards that to the dispatcher via one `Sync` helper (§4.4).
- `LocalEndpoint()` / `PeerEndpoint()` → `optional<IpEndpoint>` — `getsockname` / `getpeername` read-back.
- **SIGPIPE-safe**: `SO_NOSIGPIPE` (macOS) at creation + `MSG_NOSIGNAL` (Linux) per send — none exists in
  `src/reflector/` today, and omitting it would crash the single-threaded daemon on a mid-write peer
  disconnect.
- Destructor closes the fd.

Tested in isolation over real loopback, **parameterized over v4 (`127.0.0.1`) and v6 (`::1`)**, so
accept/connect/partial-write/EAGAIN/`SO_ERROR` run against the kernel for both families — no `DialProxy`,
just the dispatcher and a tiny test driver standing in for the owner (holding the `Registration` and
calling `Sync`). `IpEndpoint` gets its own `ToSockaddr`/`FromSockaddr` round-trip tests.

### 4.3 `http_message.{h,cpp}` — incremental HTTP/1.1 framing + header rewrite (new)

A small incremental parser — not a general HTTP engine. The owner reads into its receive `StreamBuffer`
(§4.2) and feeds `HttpFraming` a contiguous view of the buffered bytes; `HttpFraming` reports what to
forward and how much of the input it consumed:

`std::optional<Output> Feed(std::string_view input)`, with `Output { string_view header; string_view body;
size_t consumed; }`. `header` is the **rewritten** header block — a view into HttpFraming's own scratch,
because rewriting changes it — and is empty while a body streams across feeds. `body` is a **zero-copy
slice of `input`** (the receive buffer), possibly empty. The owner forwards `header` and `body` together in
one `sendmsg` (the scatter-gather `Send`) and drops `consumed` bytes from its buffer. `nullopt` = a malformed or over-cap message →
the owner closes; `consumed == 0` = nothing forwardable yet (an incomplete header) → read more and feed
again. Each `Feed` yields at most one message's worth — a complete header plus the body bytes that have
arrived — so the owner loops `Feed` over its buffer until `consumed == 0`. **Only the header is copied**
(to rewrite it); the body, and any incomplete header or chunk-size line, stay in the owner's buffer — the
framer keeps no carry buffer of its own.

In one pass over a completed header it determines body framing (`Content-Length` / `Transfer-Encoding:
chunked` / bodyless) and rewrites a fixed, case-insensitive header set by authority substitution — on
requests `Host`, on responses `Application-URL` and `Location` — splicing the replacement directly at the
parsed authority's offset (no second search). A header is rewritten only if its authority matches a known
DIAL endpoint; everything else, including all body bytes and the chunked chunk-data, passes through
verbatim (for chunked, only the chunk-size lines are parsed, to find the terminating `0`-chunk, whose
close must be a bare CRLF — chunked trailers are unsupported, so a trailer-bearing close is refused). Because
only header authorities change, **`Content-Length` is never recomputed** and chunked framing is never
rebuilt. The shared `RewriteAuthority(text, from, to)` primitive (a one-shot authority substitution over a
string) backs the SSDP `LOCATION` path (§4.5); `HttpFraming` splices inline rather than calling it.

Bounds: the header scratch is the only thing the framer holds, capped at the fixed `MAX_HEADER_BYTES`
(2 KB); a header reaching that cap — or a chunk-size line reaching the separate `MAX_CHUNK_LINE_BYTES`
(256 B) cap — without its terminator is refused and the connection closed. The body is never buffered by the framer, so a large body is bounded only by the
owner's receive `StreamBuffer`, not here.

### 4.4 `dial_proxy.{h,cpp}` — the orchestrator (new)

Owned by `SsdpReflector` as `std::optional<DialProxy>`, constructed only when `config.dial`. It owns
all TCP/HTTP state and drives it through the reactor it reaches via
`PacketDispatcher::UnderlyingDispatcher()` (the same handle step 2's eviction `Timer` uses).

State:

```cpp
struct Endpoint : NoMove {     // discovered DIAL-device ip:port + its reflector listener; a callback target
    enum class Role { Discovery, Rest };  // Discovery = from SSDP LOCATION; Rest = from Application-URL/201
    IpEndpoint   device;       // the device's endpoint, e.g. 10.1.3.80:1461 (description) or :36866 (REST)
    Role         role;         // sets the idle lifetime (§5) and which cap it counts against
    TcpSocket    listener;     // bound to source_if-addr:ephemeral (move-only, inert)
    std::chrono::steady_clock::time_point last_active;  // refreshed on each accept + rewrite naming it
    Dispatcher::Registration accept_reg;  // LAST: destroyed first, so Unregister precedes ~listener close()
};

struct Connection : NoMove {   // one client<->device proxied TCP pair; the stable callback target
    TcpSocket client;          // accepted on a listener (move-only, inert — owns its send StreamBuffer, §4.2)
    TcpSocket upstream;        // connect() to the device endpoint, bound to target_if
    HttpFraming c2u, u2c;      // per-direction framing + rewrite state
    StreamBuffer c2u_rx, u2c_rx;  // per-direction receive buffers: read into the tail, feed HttpFraming,
                                  // retain the unconsumed carry (partial header / mid-body) — the framer
                                  // holds no buffer of its own
    enum { Connecting, Open } phase;
    bool closed = false;       // set by a handler that tears itself down; the sweep erases after dispatch
    std::chrono::steady_clock::time_point deadline;  // connect deadline, then idle deadline
    Dispatcher::Registration client_reg, upstream_reg;  // LAST: destroyed first, so Unregister precedes
                                                        // ~TcpSocket close() (no closed-but-watched fd)
};
```

- `endpoints_` keyed by `device`, role-tagged, with **two separate caps** (the roles scale differently —
  §5): `MAX_REST_LISTENERS` (≈ max DIAL devices) and `MAX_DISCOVERY_LISTENERS` (transient). An `Endpoint`
  referenced as both roles (a device serving description + REST on one port, like the reference server)
  is tagged `Rest` — the longer-lived role — and counts against the REST cap.
- `connections_` keyed by a `ConnId`; `MAX_CONNECTIONS = 64` drop-new (mirrors SSDP's `MAX_SESSIONS`).
- **Both `Endpoint` and `Connection` are the dispatcher's callback targets** — their handler methods are
  bound into the `Registration`s — so both are `NoMove` and live in **node-stable, id-keyed containers**
  (`std::unordered_map`), **never `std::vector`**: a vector reallocation relocates an element and dangles
  every `Delegate` capturing its address (the rule `RawSocket` already documents). The id-keyed map also
  serves the eviction sweep (erase-by-id), so the address stability is already paid for — and is why
  binding callbacks straight to the pinned object beats routing every event through `DialProxy` by fd.
- Eviction `Timer` (lazy-start/self-stop, like SSDP) sweeping: connections past their **connect**
  deadline (a `Connecting` pair never fires a read/write event, so it needs an explicit deadline,
  distinct from idle) or **idle** deadline; and `Endpoint`s idle (no connections referencing them and
  `last_active` older than the role's grace). Erasing either is RAII — registrations drop, then sockets
  close.

`DialProxy` is **owned by `SsdpReflector`** and has **no external consumers**. Its only cross-boundary
method is the listener primitive the owner needs while rewriting a discovered `LOCATION`; everything
else (accepting clients, the upstream connect, the HTTP header rewrites, the REST listener it spins up
internally when it rewrites a description response's `Application-URL`, eviction) is reactor-driven
internals that nothing outside calls:

```cpp
// Find or create a Discovery-role listener for a device's description endpoint, returning the
// reflector authority (source_if-addr:listener-port) to advertise in the rewritten LOCATION. Called
// only by the owning SsdpReflector, from its SSDP dispatch callback; refreshes the endpoint's
// last_active. nullopt if the listener cap is hit or listen/bind fails (then the LOCATION is injected
// unchanged — discovery still works via the router until DIAL is reachable).
[[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(IpEndpoint device);
```

`DialProxy` never sees an SSDP message: the DIAL-service classification, `LOCATION` parse, and authority
splice live in the SSDP path (§4.5), using the shared `RewriteAuthority` helper (§4.3) that the TCP
header rewrites also use.

Connection mechanics (all non-blocking, reactor-driven, single-threaded). The handlers are `Connection`
methods bound to the pinned `Connection`; each ends by **`Sync(reg, socket)`** —
`disp_.SetWriteInterest(socket.Fd(), socket.WantsWrite())` — the *only* place write interest is toggled.
The `Connection` never computes a write boolean; it forwards `TcpSocket::WantsWrite()` (`connecting ||
!buffer.empty()`) through that one funnel (the "honest Point B", §11 D12).

1. **Accept** (listener readable): `Accept()` → if at `MAX_CONNECTIONS`, close immediately (drop-new);
   else emplace a `Connection` into its final map node, move the accepted client + a fresh `Connect()`'d
   upstream (`EINPROGRESS`) into it, **then** `Register` both fds with handlers bound to that pinned
   `Connection`: client `{read, write, write_armed = false}` (already established), upstream `{read,
   write, write_armed = true}` (watching connect-completion). Read is always armed. Set the connect
   deadline; the upstream is `Connecting` (tracked by `TcpSocket::IsConnecting()`, no phase enum). (No edge
   can fire before the next `PollOnce` — single-threaded — so
   there is no window between emplace and `Register`.)
2. **Connect completes** (upstream writable): `upstream.FinishConnect()` reads `SO_ERROR`; on success go
   `Open` and `Sync` (which disarms the now-idle upstream write); on error tear down. A connect *failure*
   also folds into the always-armed read (`recv()` error → teardown), so either edge converges — DIAL
   upstreams are client-speaks-first, so in practice only the writable edge fires.
3. **Forward** (either side readable): `Read` straight into that side's receive `StreamBuffer` (its
   writable tail) → loop `HttpFraming.Feed` over the buffered bytes, forwarding each `{header, body}` to
   `peer` (the rewritten header then the zero-copy body) and dropping the consumed bytes →
   `Sync(peer_reg, peer)` (arms peer write iff a tail was buffered). On the peer's writable edge:
   `peer.Flush()` → `Sync`. Because `Send`
   attempts an immediate drain, the steady state never arms `EPOLLOUT`, so the level-triggered reactor
   never writable-spins. **Backpressure is drop-and-close, not read-pausing:** read stays armed; if a
   `Send` tail would exceed the `MAX_SEND_BUFFER` cap, abort the connection — a cheap, retryable failed
   attempt that hard-bounds per-connection memory and guards a stalled peer. Read is never paused, so the
   both-directions-disarmed reactor state never arises.
4. **Close**: peer EOF / error → tear the pair down. A teardown triggered from *inside* a handler is
   **deferred** (set `closed`, sweep after the dispatch pass) — freeing the `Connection` whose handler is
   on the stack would be a use-after-free. RAII then drops the registrations (first) and closes the fds.

Each accept (step 1) refreshes the listener `Endpoint`'s `last_active`, and each forwarded byte
(step 3) refreshes the `Connection`'s idle deadline — so an active flow is never reaped, independent
of how often the client re-fetches the description.

`EnsureDiscoveryListener` (called from the SSDP path) and the description-response's `Application-URL`
rewrite (internal, on the TCP path) are what *create* endpoints and their listeners on first sight; the
launch `LOCATION` reuses the REST endpoint's existing listener.

**Bounded buffering.** Each `TcpSocket`'s send `StreamBuffer` is capped at the fixed `MAX_SEND_BUFFER`
(8 KB — a few DIAL control messages) and exceeding it aborts the connection (drop-and-close), so a
connection's memory is bounded no matter how slow or stalled a peer is — which also keeps the long-running
daemon's RSS flat (no unbounded proxy buffer). `StreamBuffer` is a fixed-capacity FIFO byte buffer over a
lazily allocated, never-zeroed block (`make_unique_for_overwrite`): an **unused buffer holds no
allocation** — most connections never backpressure, so their send buffer stays zero bytes — and the
consumed prefix is reclaimed by a compacting memmove on the next write (negligible and rare at these
sizes). The same type backs the **receive** side: the owner reads straight into the writable tail
(`ReserveTail`/`Commit`) and `HttpFraming` (§4.3) feeds from `View`, so ingress is copy-free apart from
the header rewrite. Header accumulation in `HttpFraming` is separately bounded by `MAX_HEADER_BYTES`
(§4.3).

### 4.5 `ssdp_reflector.{h,cpp}` integration

`SsdpReflector` gains `std::optional<DialProxy> dial_proxy_`, constructed in `Initialize` on the
success path when `config.dial` (and torn down before the dispatcher, via member-order, same contract
as the eviction `Timer`). Both injection sites gain the same hook, applied to the payload **before**
the existing injection — and the hook lives in `SsdpReflector` (which already classifies SSDP), so
`DialProxy` stays SSDP-agnostic:

- `OnUnicastResponse` (the `M-SEARCH` `200 OK`) and `OnTargetPacket` (`NOTIFY`): if the message
  advertises the DIAL service type (`urn:dial-multiscreen-org:...` in `ST`/`NT`/`USN`) and carries a
  `LOCATION`, parse the device's description endpoint, call `dial_proxy_->EnsureDiscoveryListener(device)`,
  and splice the returned reflector authority into the `LOCATION` via the shared `RewriteAuthority`
  helper (§4.3) — yielding the payload to inject. A resized payload is fine: the datagram is built from
  a payload span and UDP has no sequence numbers (unlike TCP). On `nullopt` (cap/bind failure) the
  `LOCATION` is injected unchanged.

If the entry has a `mac` filter it already scopes which device's responses are seen, so only that
device is rewritten. Non-DIAL SSDP is untouched, and `DialProxy` never receives an SSDP message.

## 5. Lifecycle, caps, and teardown

- **Connections:** `MAX_CONNECTIONS = 64`, drop-new at capacity (RFC 6888 posture, as SSDP). A
  separate **connect deadline** reaps a pair stuck in `EINPROGRESS` (no I/O event ever fires for it);
  an **idle deadline** reaps an open-but-quiet pair. Both swept by the eviction `Timer`.
- **Listeners — two roles, different lifetimes** (the DIAL spec mandates no port stability, §2.3):
  - *Discovery* (from an SSDP `LOCATION`): the device-description port is **dynamic** (changes across
    reboots) and clients re-discover constantly, so a stale one is replaced fast — **short** idle reap
    (`DISCOVERY_IDLE`, ~90s).
  - *REST* (from `Application-URL` / a `201 Location`): the port is **stable** in practice (the
    reference server fixes it; the LG TV holds it across a session) and a client may keep the
    `Application-URL` across a pause, so it gets a **long** idle cooldown (`REST_IDLE`, default
    ~1h) — but **not forever**: a reboot can change the REST port, leaving the old listener dead, so a
    multi-hour (not multi-day) grace frees it promptly while surviving any realistic pause/resume.
  A listener's `last_active` is refreshed on **any activity on it** — each accepted connection *and*
  each rewrite naming its endpoint — so an in-use listener never idles regardless of how often the
  client re-fetches the description. (This matters: the client makes *several* REST calls per
  description fetch — in the capture it issues `GET /apps/YouTube` then `POST /apps/YouTube`
  back-to-back on the REST endpoint with no description fetch between — so the REST listener is kept
  warm by its own connections, not by description-fetch rewrites.) Reaping happens only after use
  stops; a reaped listener whose URL a client reuses gets a connection-refused and re-discovers.
- **Separate caps, fd-bounded.** Each listener is one bound socket = one fd, and a router's
  `RLIMIT_NOFILE` is often ~1024, so `MAX_REST_LISTENERS + MAX_DISCOVERY_LISTENERS + 2·MAX_CONNECTIONS
  + the raw capture sockets` must stay well under it. Defaults **32 / 32 / 32** (≈ 128 fds, matching
  the SSDP `MAX_SESSIONS` convention) are generous — real DIAL devices number in the single digits —
  while clear of exhaustion. A four-figure
  REST cap alone would approach the fd ceiling for no practical gain; raise the configurable cap only
  if a deployment truly needs it. `MAX_REST_LISTENERS` is effectively the cap on DIAL devices served.
- **RAII throughout:** erasing a `Connection`/`Endpoint` closes its sockets and drops its reactor
  registrations; `~DialProxy` (before the dispatcher) clears everything. Mirrors the SSDP
  `Session`/`Timer` teardown order verbatim.
- **Single-threaded:** every socket is non-blocking and reactor-driven; no threads, locks, or blocking
  calls — the invariant holds. Listener registration happens inside a dispatch callback (the SSDP
  rewrite hook), which is already an established safe pattern (step 2 registers response captures
  mid-dispatch).

## 6. Correctness and security

- **No SSRF / no open relay.** A client connecting to listener `Ln` reaches a **fixed** upstream (the
  device endpoint bound to that listener at creation). The client cannot influence the upstream
  destination — it is set by discovery, not by the request. The reflector never connects anywhere a
  DIAL device didn't advertise.
- **Listeners bind to `source_if`'s address only**, so they are reachable solely from the client
  subnet, not the whole host. Caps (`MAX_CONNECTIONS`, the two listener caps, `MAX_HEADER_BYTES`) bound
  resource use; default-off means zero new surface unless asked for.
- **Loop safety:** the proxy uses kernel TCP sockets, distinct from the raw L2 capture path — a
  proxied connection is never re-captured as SSDP (different protocol, different sockets). The SSDP
  `LOCATION` rewrite changes only the injected payload, not what is captured.
- **Header-only rewrite** avoids the request-smuggling surface of body/`Content-Length` rewriting
  entirely; chunked bodies are forwarded as opaque bytes, never re-framed.

## 7. Testing

**Unit (fakes / pure data):**
- `http_message_test`: request/response start-line + header parse; `Content-Length` vs `chunked` vs
  none framing and boundary detection; header rewrite by authority substitution (`Application-URL`,
  `Location`/`LOCATION` case-insensitive, `Host`); non-DIAL headers untouched; oversized header block
  refused. Assert the rewritten bytes, not log text.
- `dial_proxy_test` (with `FakeDispatcher` + `FakeLinkSocket` + the loopback `TcpSocket`):
  `EnsureDiscoveryListener` allocates/reuses a listener and returns the reflector authority (cap hit →
  `nullopt`); accept → connect (driven by `FireWritable`) → forward with `Application-URL` rewrite
  (spinning up the REST listener) and the launch `201 LOCATION` rewrite reusing it; `MAX_CONNECTIONS`
  drop-new; connect-deadline and idle-deadline eviction via firing the fake timer; backpressure
  drop-and-close (a short write buffers + arms write-interest; `FireWritable` flushes and disarms; a
  write past the `MAX_SEND_BUFFER` cap aborts the connection). The SSDP `LOCATION` parse + splice is tested on the `SsdpReflector` side.
- `event_loop_dispatcher_test`: extended for write-interest — `SetWriteInterest` arms/disarms,
  writable fires the write callback, a completed loopback `connect` surfaces as writable, a failed
  connect surfaces to an armed handler, the readability tests stay green.

**Application (`application_test`):** an SSDP entry with `dial = true` wires a reflector that owns a
`DialProxy`; `dial = false`/absent does not. Existing SSDP cases stay green.

**e2e (`e2e/`):** a small **DIAL device emulator** container on `target_if` serving the two endpoints
(a description endpoint with a dynamic port + `Application-URL` header; a REST endpoint answering
`GET`/`POST`/`DELETE /apps/<App>` with `chunked` + a `201 LOCATION`), modeled on the captured LG TV.
A client container on `source_if` runs discovery → `GET` description → `POST` launch → `DELETE` stop
through the reflector, asserting: the `200 OK` `LOCATION` and the response `Application-URL`/`LOCATION`
are rewritten to reflector authorities; the upstream connections arrive at the emulator from
`target_if`'s address; the launch round-trip completes. Mirrors the step-2 round-trip harness.

## 8. Empirical follow-ups (low risk, do not block the design)

- The spec defines DIAL over IPv4 (§2.3: the `Application-URL` host must be/resolve to an IPv4
  address), matching the IPv4 capture; IPv6 is out of scope (§12).
- The `DELETE /apps/YouTube/run` stop was not isolated in the capture; it targets the rewritten run
  URL on the REST listener, so it routes through `L2` with no new mechanism.
- If a future device emits **absolute** body URLs (this LG TV does not), body rewriting would be
  needed — explicitly out of scope (§11), and the parser is structured so it could be added without
  reworking the framing.

## 9. Configuration

No new section — reuse the SSDP `[name]` entry. Add a single opt-in boolean to `SsdpConfig`
(+ `Verify` + the `std::formatter`):

```toml
[livingroom-tv]
ssdp = true
dial = true              # default false; opt in to the DIAL proxy
source_if = "lan"
target_if = "iot"
mac = "..."              # optional; scopes discovery AND the DIAL device
```

`dial = true` is the **only** DIAL config knob. The caps and timeouts — max connections, listener
counts, idle reaps, the connect deadline, the header and send-buffer caps — are **fixed constants**
beside the code that enforces them, matching the rest of the codebase (`SsdpReflector`'s `MAX_SESSIONS` /
`SESSION_GRACE` / `EVICTION_INTERVAL` are constants, not config). A user has no reason to tune an
internal stall/DoS valve; expose config later only if a concrete need appears.

`dial` inherits the entry's `source_if` (listener bind + rewritten authority), `target_if` (upstream
connect bind + egress pin), `address_family`, and `mac`. Listener ports are **ephemeral** (kernel-
assigned, carried in the rewritten URLs) — nothing to configure. `Verify` rejects `dial = true`:
- when `ssdp` is not enabled (DIAL requires SSDP discovery); and
- when the entry has no IPv4 — i.e. `address_family = ipv6` (`!UsesIPv4()`). DIAL is IPv4-only (§2.3),
  so an IPv6-only entry has no IPv4 address to bind a listener or upstream to; rather than silently
  doing nothing, startup fails with a clear error. (`default`/`dual`/`ipv4` all have IPv4 and are fine.)

## 10. Commit breakdown

Each data-path commit runs the full gate (native unit + docker debug/release + e2e) before commit.

1. `dispatcher`: write-interest control (`Register` FdCallbacks overload + `SetWriteInterest`; read is
   always armed; epoll/kqueue write arm-disarm) + `FakeDispatcher` `FireWritable` + tests. Landed alone,
   like the timer commit.
2. `ip_endpoint` + `tcp_socket`: `IpEndpoint` value type with family-aware sockaddr conversion;
   move-only, dispatcher-inert `TcpSocket` (non-blocking listen/accept/connect(bound+pinned)/read/
   `Send`+bounded`StreamBuffer`/`Flush`/`WantsWrite`, SIGPIPE-safe, RAII) + loopback tests parameterized
   over v4/v6.
3. `http_message`: incremental framing (CL/chunked/none) + case-insensitive header rewrite via the
   shared `RewriteAuthority` helper + tests.
4. `dial_proxy`: endpoint/listener map, connection pump + bounded `StreamBuffer` (drop-and-close on
   overflow), cap + connect/idle eviction `Timer`, `EnsureDiscoveryListener` + tests.
5. `ssdp_reflector` + `config`: the `dial` flag (+ tunables, `Verify`, formatter) and the DIAL
   `LOCATION` parse + `RewriteAuthority` splice (calling `EnsureDiscoveryListener`) in the
   `200 OK`/`NOTIFY` paths + tests.
6. `e2e`: the DIAL device emulator + launch round-trip.
7. `docs`: README DIAL section.

## 11. Decisions

- **D1 — Terminate TCP with kernel sockets; reject raw-socket packet proxying.** The kernel RST on a
  `SYN` to the reflector's own IP is unsolvable in-model without a real listener, and a listener is
  termination; termination also dissolves the sequence-rewriting ALG (independent kernel sequence
  spaces). (§2.1; rejected after a design panel steelmanned the raw-socket path.)
- **D2 — Header-only rewrite; bodies streamed verbatim.** The capture shows every body URL is
  relative and every absolute URL is a header on a known endpoint, so we never de-chunk, rewrite a
  body, or recompute `Content-Length`. Lands between a strict "reject chunked" cut (disproved by the
  capture) and a general HTTP/1.1 reverse proxy (more than one device needs).
- **D3 — Dynamic per-endpoint listeners.** Device ports are dynamic and discovered (description from
  `LOCATION`, REST from `Application-URL`); a listener is allocated per device endpoint and the URL is
  rewritten to it. No fixed `dial_port`.
- **D4 — Upstream bound to `target_if`'s address + egress-pinned.** Reproduces exactly what the
  router NAT does today (the device accepts any its-subnet source, validated in the capture); pinning
  (`SO_BINDTODEVICE`/`IP_BOUND_IF`) guards against a host route toward the client subnet.
- **D5 — Reactor gains write-interest control; read stays always armed.** Write-interest for
  non-blocking connect-completion + send-buffer flush. Read is *not* toggleable: DIAL uses drop-and-close
  backpressure (§4.4), not read-pausing, so read stays armed — which makes the always-armed read handler
  the uniform home for error teardown and keeps the interest mask from ever collapsing to nothing-armed
  (no busy-spin guard needed). Level-triggered is kept; edge-triggered was evaluated and rejected (§4.1).
  The one capability the readability-only reactor lacks; shipped and tested in isolation first, like the
  timer commit.
- **D6 — `DialProxy` owned by `SsdpReflector`, default off.** DIAL is meaningless without SSDP
  discovery and must hook its `LOCATION` rewrite; making it a member keeps the coupling explicit and
  the SSDP class focused on UDP. Opt-in because it opens listeners and does L7 work.
- **D7 — SIGPIPE-safe sockets.** `SO_NOSIGPIPE`/`MSG_NOSIGNAL` (none exists today) — a peer
  disconnecting mid-write must not signal-kill the single-threaded daemon.
- **D8 — Fixed upstream per listener (no SSRF).** The client cannot steer where the proxy connects;
  the upstream is set by discovery, not the request.
- **D9 — Two listener roles, different lifetimes and caps.** The DIAL spec mandates no port stability
  (§2.3): the device-description port is dynamic (short reap, ~90s), the REST port stable-but-not-
  permanent (long-but-finite cooldown, ~1h — a reboot changes it, so not multi-day). Separate caps
  because REST listeners ≈ device count while discovery is transient; both fd-bounded (defaults 32/32,
  matching `MAX_SESSIONS`/`MAX_CONNECTIONS` — a four-figure cap would risk fd exhaustion for no gain).
- **D10 — Drop-and-close backpressure bounds proxy memory (no read-pausing).** DIAL is request/response
  with tiny payloads, so instead of lossless flow control (pause the source at a high-water mark) we cap
  each `TcpSocket`'s `StreamBuffer` and **abort the connection if it would overflow** — a failed attempt,
  cheap and retryable, that hard-bounds per-connection memory, keeps the daemon's RSS flat, and doubles
  as a DoS guard. Read is never paused (so the reactor never sees a both-disarmed fd). The buffer is a
  simple bounded byte queue — not `std::deque<std::byte>` (small fixed block → alloc/cache churn); a
  chunk-chain is the documented upgrade behind the same interface if high-throughput streaming is ever
  needed. (§4.4)
- **D11 — `DialProxy` exposes only `EnsureDiscoveryListener`; SSDP stays in `SsdpReflector`.** The
  proxy is owned by `SsdpReflector` with no external callers, so its sole cross-boundary method is the
  listener primitive; DIAL-classification + `LOCATION` parse/splice live in the SSDP path via the
  shared `RewriteAuthority` helper, keeping `DialProxy` free of SSDP-message knowledge. (§4.4/§4.5)
- **D12 — `TcpSocket` is dispatcher-inert; the `Connection`/`Endpoint` owns the `Registration` + the one
  `SetWriteInterest` ("honest Point B").** A `TcpSocket` captures nothing of the dispatcher (just `{fd,
  StreamBuffer, connecting}`) so it moves freely — `Accept()` returns one by value, a `Connection` holds
  two by value. The dispatcher callback target is the owning `Connection`/`Endpoint`, which is `NoMove`
  in a node-stable, id-keyed map (it must be address-stable anyway, for eviction). Write interest is
  toggled in exactly one place — `Sync(reg, s)` forwarding `s.WantsWrite()` — so `TcpSocket` owns the
  buffer and the truth while the proxy owns only the toggle. Rejected the alternative (a self-registering
  `TcpSocket` "so the proxy never touches write interest"): it would dangle its own write `Delegate` on
  move, forcing `unique_ptr` heap-pinning per socket plus an internal state machine, and it doesn't even
  remove the connect-completion callback coupling. (§4.2/§4.4; settled via a design panel + lifetime
  adversary; mirrors the shipping `SsdpReflector::Session` + `RawSocket` `NoMove` patterns.)

## 12. Out of scope

- **Body URL rewriting / de-chunking** — unneeded for this device (relative bodies); the parser leaves
  room to add it if a future device forces it.
- **General multi-device / path-mux on a shared listener** — one listener per endpoint is enough for
  the single-device case; revisit only when a second `dial` device per `source_if` exists.
- **The post-launch media / second-screen channel** — the device streams directly from the internet,
  not through the reflector.
- **TLS / Google Cast (port 8009)** — DIAL here is confirmed plain HTTP; an encrypted control channel
  can't be rewritten without MITM and is a separate problem.
- **IPv6 DIAL** — the spec's `Application-URL` host "SHALL either resolve to an IPv4 address or be an
  IPv4 address" (§2.3), so DIAL is **IPv4 by spec**; the rewritten authority uses the `source_if` IPv4
  address and the proxy only stands up IPv4 listeners even on a dual entry. An `ipv6`-only entry with
  `dial = true` is rejected at config time (§9). (An IPv6 link-local listener would also need a scoped
  `[fe80::…%if]` authority that not all clients accept.)
