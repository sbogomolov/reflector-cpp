# SSDP reflection — step 2 (unicast M-SEARCH response proxy)

**Status:** design approved, pending implementation plan
**Date:** 2026-05-30
**Scope:** Step 2 of the 3-step SSDP roadmap (multicast forwarding → **unicast proxy** → DIAL proxy).
Builds directly on the step-1 multicast `SsdpReflector` (on `main`); see
`2026-05-29-ssdp-reflection-design.md` for step 1.

## 1. Goal and scope

Step 1 relays SSDP multicast both directions: `M-SEARCH` source→target, `NOTIFY` target→source. That
makes **passive** discovery work (target devices' advertisements reach source-side clients), but
leaves **active** discovery incomplete: a device's reply to an `M-SEARCH` is a **unicast**
`HTTP/1.1 200 OK` sent to the searcher's source IP:port (UPnP Device Architecture 1.0 §1.2.3), which
cannot cross segments today.

Step 2 closes that gap. It captures those unicast `200 OK` responses on `target_if` and forwards
each back to the original searcher on `source_if`, via a short-lived per-search mapping (a UDP-NAT
of sorts). The result: a source-side client's `M-SEARCH` gets answered by target-side devices as if
they were local.

The `NOTIFY` (reverse) path is unchanged — it is one-way multicast with no source-IP-dependent
reply. Step 2 modifies only the `M-SEARCH` forward path and adds the return path.

**Always on.** The proxy activates whenever `ssdp` is enabled for an entry; there is no separate
toggle. No config schema change (see §8).

## 2. The core problem and why this mechanism

When the reflector re-emits an `M-SEARCH` so that responses come back to *itself*, target devices
unicast their `200 OK` to the reflector's interface IP on some port. Two things must happen:

1. **We must see the response with its source MAC**, so the optional per-device `mac` filter applies
   to responses just as it does to `NOTIFY` (parity). A normal `recvfrom` on a UDP socket yields the
   sender's IP:port but **not** the L2 source MAC. Only L2 capture (our existing AF_PACKET / BPF raw
   socket) carries the frame's source MAC.
2. **The kernel must not answer the response with an ICMP port-unreachable.** A UDP datagram
   arriving at a local port with no bound socket triggers ICMP port-unreachable. Capturing the frame
   via the raw socket does **not** prevent this — raw capture is a tap; the IP stack still processes
   the packet independently and NAKs it.

### Field precedent

- **`nberlee/bonjour-reflector`** (Go, the closest analog — a full SSDP cross-segment reflector):
  pure pcap, no UDP sockets. It captures the `200 OK` at L2 and simply **tolerates** the kernel's
  ICMP port-unreachable. Functional, but it leaves ICMP NAK noise on the wire for every response.
- **`udpbroadcastrelay`** (C, DIAL-capable): binds a real UDP socket per search and **reads** it.
  Binding claims the port (suppresses ICMP); reading it is how it gets the response — but a read
  socket loses the source MAC.

We want **both** properties (MAC-filtered responses *and* no ICMP noise), which neither field
project achieves together.

### Chosen mechanism: a port-reservation socket + raw capture

Bind a UDP socket to the port the relayed `M-SEARCH` originates from, **but never read it**. The
bind makes the kernel's socket lookup succeed → no ICMP. The actual response (with its source MAC)
is captured by the raw socket, exactly as multicast SSDP already is. The bound socket is a pure
*port reservation*; we never call `recv` on it.

This was confirmed empirically on Linux (glibc):

| Scenario | ICMP port-unreachable? |
|---|---|
| no socket bound *(control)* | **sent** (`ECONNREFUSED` on a connected sender) |
| bound, never read | **not sent** |
| bound + drop-all `SO_ATTACH_FILTER` | **not sent**, and nothing is enqueued |

A bound-but-unread socket suppresses the ICMP (the kernel still delivers into its buffer; we let it
overflow and drop — harmless). On Linux a drop-all `SO_ATTACH_FILTER` additionally prevents any
enqueue, so the socket buffers literally nothing. macOS (test-only) uses the plain bind-and-never-
read form. See §3.1.

## 3. Components

### 3.1 `port_reservation.{h,cpp}` — ephemeral-port allocator + ICMP suppressor (new)

A small RAII type that both **allocates** a unique ephemeral port and **reserves** it:

- `socket(AF_INET | AF_INET6, SOCK_DGRAM, 0)`, `bind` to `(in*addr_any, port 0)` → the kernel
  assigns a free port; `getsockname` reads it back. Binding to `any` reserves the port across the
  family's interfaces (it only ever receives on `target_if`), so no interface-IP accessor is needed.
- Linux: attach a drop-all classic BPF filter (`SO_ATTACH_FILTER`, program `BPF_RET|BPF_K, 0`) so
  nothing is enqueued. macOS: set a minimal `SO_RCVBUF` and never read.
- Closes the fd on destruction (RAII), freeing the port.

```cpp
// Move-only (an fd owner): Create returns it by value and Session holds it by value.
class PortReservation {
public:
    // Allocates and reserves a free ephemeral UDP port of `family`. nullopt on failure.
    [[nodiscard]] static std::optional<PortReservation> Create(IpAddress::Family family) noexcept;
    PortReservation(PortReservation&&) noexcept;
    PortReservation& operator=(PortReservation&&) noexcept;
    ~PortReservation() noexcept;  // closes the fd
    [[nodiscard]] uint16_t Port() const noexcept { return port_; }
private:
    PortReservation(int fd, uint16_t port) noexcept : fd_{fd}, port_{port} {}
    int fd_ = -1;
    uint16_t port_ = 0;
};
```

The reservation socket is never registered with the dispatcher — it is held, not watched.

### 3.2 `link_socket.h` / `raw_socket.cpp` — unicast injection + source-address getter (new methods)

Two additions to the `LinkSocket` interface.

**Unicast injection.** The existing `SendUdpDatagram` derives the dest MAC from a *multicast* dst and
originates from the interface's own source address. The return path needs a **unicast** datagram to
an explicit MAC (the searcher's), still originating from our own interface address:

```cpp
// Injects a unicast UDP datagram to an explicit L2 destination (the searcher's MAC), to deliver a
// proxied SSDP 200 OK back across segments. Like SendUdpDatagram it originates from this
// interface's own source address and MAC; it differs only in taking an explicit unicast dst_mac
// instead of deriving a multicast MAC from dst_ip. Returns false (after logging) on failure. Gate
// with CanSend(dst_ip.AddressFamily()).
[[nodiscard]] virtual bool SendUnicastUdpDatagram(MacAddress dst_mac, IpAddress dst_ip,
    uint16_t dst_port, uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;
```

`RawSocket` implements it via the existing `BuildUdpFrame` (which already takes dst/src MAC, src/dst
IP, ports, ttl), supplying its own source IP/MAC just as `SendUdpDatagram` does. The test fake
records the call. (`SendUdpDatagram` keeps its multicast-oriented contract unchanged.) We do **not**
spoof the device's source IP — see D3.

**Source-address getter.** The response capture filter needs the dest IP of the `200 OK`, which is
the source IP the relayed M-SEARCH carried — i.e. the same per-family source address `RawSocket`
puts on outgoing frames:

```cpp
// The interface's source address for `family` — the address SendUdpDatagram originates from, and
// the one a unicast reply to a relayed datagram of that family is destined to. nullopt if the
// interface has none (then CanSend(family) is also false). IPv6 returns the link-local address.
[[nodiscard]] virtual std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept = 0;
```

`RawSocket` returns `addresses_.v4` / `addresses_.v6` (a single address per family; for IPv6 the
link-local, which is what `SendUdpDatagram` uses for both the `ff02::c` and `ff05::c` relays). The
reflector samples it **at relay time** and stores the result in the filter, so a later address change
(DAD/DHCP) doesn't desync the filter from the address the device actually replies to.

### 3.3 `ssdp_message.{h,cpp}` — MX parsing (new helper)

The session lifetime derives from the `M-SEARCH`'s `MX` header (the searcher's max response wait,
seconds):

```cpp
// Parses the MX header of an M-SEARCH (max wait, seconds), clamped to [1, 5] per UDA 2.0. Returns
// a default of 3 when MX is absent or unparseable (M-SEARCH should always carry it).
[[nodiscard]] uint8_t ParseMSearchMx(std::span<const std::byte> payload) noexcept;
```

Case-insensitive scan for the `MX:` header on the start-line-terminated header block; integer parse;
clamp. No other header parsing.

### 3.4 `ssdp_reflector.{h,cpp}` — the proxy

Step 1's class gains a per-search session table and a third capture handler. The `NOTIFY` path
(`OnTargetPacket`) and classification are untouched.

**Session** (RAII bundle, one per in-flight search):

```cpp
struct Session {
    IpAddress    searcher_ip;     // from the captured M-SEARCH frame
    uint16_t     searcher_port;   // its source port (where the 200 OK must land)
    MacAddress   searcher_mac;    // its frame source MAC (unicast dst for the reply)
    std::chrono::steady_clock::time_point expiry;     // created + MX + grace
    PortReservation reservation;                       // holds port P, suppresses ICMP
    PacketDispatcher::Registration capture;            // {dest_ip = our addr, dest_port = P, ...}
};
```

Keyed by `(family, P)` — IPv4 and IPv6 ephemeral port spaces are independent, so a v4 and a v6
session can share a port number. `std::unordered_map<SessionKey, Session>`; `MAX_SESSIONS = 32` per
reflector. `Session` is move-only (its `PortReservation` and `Registration` members are), so it is
inserted with `try_emplace` and never copied. Per-session captures live in the `Session`, not in the
base `Reflector::registrations_` (which holds only the multicast registrations).

**`OnSourcePacket` (M-SEARCH, source→target)** — replaces the step-1 relay-from-1900:

1. `ShouldRelay(packet, Search)` (classify; drop non-search / wrong direction, as today).
2. If `sessions_.size() >= MAX_SESSIONS`: log (rate-limited) and **drop** — no relay, no session
   (RFC 6888 "protect committed flows, reject new"). The searcher will retry. (Expired sessions are
   reaped by the eviction timer, not here — §4.)
3. `PortReservation::Create(family)` → `P`; register a raw capture on `target_socket_` with
   `{dest_ip = *target_socket_.SourceAddress(family), dest_port = P, source_mac = config.mac}` →
   `OnUnicastResponse`. The `dest_ip` pins the capture to the `200 OK` actually destined to our
   interface address, sampled now so a later address change can't desync it.
4. Relay the `M-SEARCH` to the group via `target_socket_.SendUdpDatagram(group, 1900, /*src_port=*/P,
   payload, SSDP_TTL)`. (Originating from `P` instead of `1900` is what makes responses land on a
   port we reserved — and it incidentally removes step 1's latent ICMP from its port-1900 relay.)
5. On success, store the `Session`. On any failure, RAII drops the reservation + registration.

**`OnUnicastResponse` (200 OK, captured on target)** — new:

1. Look up `(family, packet.header.dest_port)`. Miss → drop (the reservation already suppressed the
   ICMP; a late/unknown response is simply not forwarded).
2. Inject to the searcher on `source_socket_`:
   `SendUnicastUdpDatagram(s.searcher_mac, s.searcher_ip, s.searcher_port,
   packet.header.source_port, packet.payload, SSDP_TTL)` — originating from `source_if`'s own
   address (no spoofing; see §5 / D3).

No response classification: the capture filter (unique `P` + optional device MAC) is tight enough;
whatever the device unicasts to `P` is the answer.

**Eviction.** The reflector owns a `Timer` (§3.5) that fires every `EVICTION_INTERVAL` and calls
`EvictExpired(now)`, which `erase_if`s sessions past their `expiry`. Erasing a `Session` is RAII —
it unregisters the capture and closes the reservation socket. `EvictExpired` takes `now` as a
parameter (the timer passes `steady_clock::now()`) so the sweep logic is unit-testable without real
time. The timer is created only on the success path of `Initialize` (a valid reflector), held as a
`std::optional<Timer>`.

Constants: `SSDP_PORT = 1900`, `SSDP_TTL = 2` (unchanged), `MAX_SESSIONS = 32`, `SESSION_GRACE = 2s`,
`EVICTION_INTERVAL = 1s`.

### 3.5 `Dispatcher` timers + `timer.{h,cpp}` (new) + `PacketDispatcher` getter

Eviction needs a periodic callback. Rather than an OS timer fd (`timerfd` is Linux-only; the macOS
equivalent isn't an fd), **the reactor owns the timers and fires them itself** — portable, one
implementation, no `#ifdef`.

**`Dispatcher` gains a dedicated timer API** — an explicit `RegisterTimer`/`UnregisterTimer` pair,
separate from the fd `Register`/`Unregister`:

```cpp
using OnTimerCallback = Delegate<void()>;
enum class TimerId : uint64_t {};   // 0 = invalid sentinel; real ids start at 1

[[nodiscard]] virtual TimerId RegisterTimer(
    std::chrono::milliseconds interval, const OnTimerCallback& callback) = 0;
virtual void UnregisterTimer(TimerId) noexcept = 0;
```

Kept as a distinct named pair rather than overloading `Unregister(int)` or instantiating a second
`Registration<Dispatcher, TimerId>`: timers have no fd and share none of the readiness machinery, so
a separate concept reads clearer and avoids overload/`friend` entanglement. RAII lives in the small
`Timer` class below. `TimerId` is a strong `enum class`; ids start at 1 so `TimerId{}` is the invalid
sentinel (as `DefaultPacketDispatcher` already does for its ids). The strong type costs two
`static_cast`s at the `EventLoopDispatcher` boundary (mint `static_cast<TimerId>(next_timer_id_++)`,
compare via `static_cast<uint64_t>`).

> **Known inconsistency, deferred.** `TimerId` is strongly typed while the existing
> `PacketDispatcher::RegistrationId` is a bare `uint64_t` alias (and `Dispatcher` registrations are
> keyed by a raw fd `int`). New code is born correct; converging the older ids to strong `enum class`
> types is a mechanical, cross-cutting refactor (the `RegistrationId` alias, the `Registration<>`
> instantiations, the fd key) deliberately **left out of this step** to keep the SSDP diff focused —
> tracked as a follow-up after step 2 lands.

`RegisterTimer`/`UnregisterTimer` are the only **interface** additions (every `Dispatcher` consumer
needs them). The firing/scheduling helpers — `FireDueTimers(now)` and `NextTimeout(now)` (§ below)
— are **non-virtual `EventLoopDispatcher` members**, not part of the abstract `Dispatcher`: only the
production reactor's own `Run` drives them, and the `FakeDispatcher` fires via its own on-demand helper
instead. Keeping them off the ABC means the fake doesn't have to implement scheduling it never uses.

**`EventLoopDispatcher` fires them in the poll loop.** It holds `std::vector<TimerEntry>` with
`TimerEntry = {TimerId id, milliseconds interval, steady_clock::time_point next, OnTimerCallback}`.
`RegisterTimer` validates, then appends an entry (`next = now + interval`) and returns its `TimerId`;
`UnregisterTimer` erases it by id (a no-op if already gone, so a fired callback may cancel its own or
another timer safely). **`RegisterTimer` rejects `interval <= 0ms` and an invalid callback
(`!cb.IsValid()`)**, returning an invalid `TimerId{}` (mirroring `Register` returning `{}` on a bad
fd): a non-positive interval makes the entry perpetually due (`NextTimeout` clamps to 0 forever → 100%
CPU spin), and invoking a default `Delegate` is UB.

**Firing is two new public methods on the reactor; `PollOnce` is left untouched.** The seam that makes
timers testable is the `now` *parameter* — both methods take the clock value as an argument, so a test
injects time without any clock-seam member and without any `friend`:

```cpp
// Fire (and reschedule) every timer due as of `now`. Public so it is driven directly in tests.
void FireDueTimers(std::chrono::steady_clock::time_point now);
// The wait to pass to PollOnce so the loop wakes by the soonest timer deadline, capped at
// MAX_POLL_INTERVAL. Pure; public for tests (the `now` parameter is the seam).
[[nodiscard]] std::chrono::milliseconds NextTimeout(std::chrono::steady_clock::time_point now) const;
```

`MAX_POLL_INTERVAL` is a private constant (`1000ms`) — the cap is fixed policy, not a knob: it bounds
how often the loop wakes to re-check `stop_requested` (today's `Run` already hardcodes `PollOnce(1000ms)`
for exactly this), and it is the fallback wait when no timers are registered (e.g. a WoL/mDNS-only
config). `Run` composes the helpers around the **unchanged** `PollOnce`:

```
void Run(stop):
    while (!stop):
        now = steady_clock::now()
        PollOnce(NextTimeout(now))   // wake by the next timer deadline, else after MAX_POLL_INTERVAL
        FireDueTimers(now)           // then sweep — after PollOnce has fully returned
```

Why this shape:

1. **`PollOnce` is genuinely unchanged** — no split, no rename, no new early-return surgery. Its
   existing tests (`PollOnceWithoutRegistrationsReturnsFalse`, `UnregisterStopsCallback`) stay green by
   construction: `PollOnce` never touches timers.
2. **Correctness on the idle path.** `FireDueTimers` runs in `Run`, *after* `PollOnce` returns — so it
   fires regardless of which path `PollOnce` took (a timeout with no fd event is the dominant idle
   state). The `NextTimeout` clamp ensures `PollOnce` wakes by the deadline rather than sleeping the
   full `MAX_POLL_INTERVAL`.
3. **No test-only surface.** `FireDueTimers(injected_now)` and `NextTimeout(injected_now)` are public
   and the `now` parameter is the injection point, so the fire/reschedule/unregister logic and the
   clamp (incl. the negative-timeout guard) are tested deterministically with **no friend, no
   clock-seam member, no `sleep`**. `Run` stays a trivial untested composition, exactly as it is today.

- `NextTimeout(now)`: `timers_.empty() ? MAX_POLL_INTERVAL : clamp(min(MAX_POLL_INTERVAL, soonest_next
  − now), 0ms, MAX_POLL_INTERVAL)`. The `>= 0` clamp keeps a past-due timer from handing the kernel a
  negative timeout; with no timers it returns `MAX_POLL_INTERVAL`, so the existing shutdown-check
  cadence is unchanged. The cap is only an upper bound; the timer deadline drives the real cadence.
- `FireDueTimers(now)` snapshots the due `{id, callback}` into a local vector, reschedules each due
  entry to `next = now + interval` (forward from *now*, never `+= interval` — no backlog that spins
  `NextTimeout == 0`), then invokes the copied callbacks. Mutation-safe because a callback may
  `RegisterTimer` / `UnregisterTimer` (reallocating `timers_`), mirroring `PollOnce`'s existing "copy
  the callback before invoking" and `DispatchPacket`'s live-walk discipline.

**Two edge cases, decided explicitly:**
- *Dead event queue (`event_fd_ < 0`).* `PollOnce` returns immediately (logging), so `Run` would spin
  — a **pre-existing** degenerate case (a dispatcher whose queue failed to construct never runs a real
  daemon); `FireDueTimers` still runs each spin but harmlessly (no fds means no reflectors, so no
  timers). We add one guard: `Run` checks `event_fd_` once up front and bails (logging) rather than
  spinning — a small, in-scope improvement the timer work makes natural.
- *Leftover timers at teardown.* `~EventLoopDispatcher` gains a warning for a non-empty `timers_`,
  symmetric to the existing non-empty `callbacks_` warning — a live timer at dtor signals a
  teardown-order bug (a reflector outliving the dispatcher) worth surfacing.

**`Timer`** is the RAII handle the reflector holds — a small, move-only owner of a `TimerId` that
calls `UnregisterTimer` on destruction:

```cpp
class Timer {                                   // move-only RAII over RegisterTimer/UnregisterTimer
public:
    Timer() noexcept = default;
    Timer(Dispatcher& dispatcher, std::chrono::milliseconds interval, const Dispatcher::OnTimerCallback& cb)
        : dispatcher_{&dispatcher}, id_{dispatcher.RegisterTimer(interval, cb)} {}
    Timer(Timer&& o) noexcept : dispatcher_{std::exchange(o.dispatcher_, nullptr)}, id_{o.id_} {}
    Timer& operator=(Timer&& o) noexcept;       // Reset() then steal o's dispatcher_/id_
    ~Timer() noexcept { Reset(); }
    [[nodiscard]] bool IsValid() const noexcept { return dispatcher_ != nullptr; }
private:
    void Reset() noexcept { if (dispatcher_) std::exchange(dispatcher_, nullptr)->UnregisterTimer(id_); }
    Dispatcher* dispatcher_ = nullptr;
    TimerId id_{};
};
```

**The reflector reaches the reactor** through its existing `PacketDispatcher&` via a new getter:

```cpp
// The reactor this packet dispatcher is layered on — lets a consumer register a Timer on the same
// single-threaded event loop.
[[nodiscard]] virtual Dispatcher& UnderlyingDispatcher() noexcept = 0;
```

`DefaultPacketDispatcher` returns its `*dispatcher_`. **Both interface additions are
compile-breaking** until every implementer — production *and* fakes — is updated; that companion work
is part of this commit, not optional:
- `tests/mocks/fake_dispatcher.h` (`FakeDispatcher`) gains `RegisterTimer` / `UnregisterTimer`,
  recording `{id, callback}`, plus a `FireTimers()` helper (copy-before-invoke, mirroring its existing
  `FireReadable`) so reflector tests drive eviction deterministically by *firing on demand* — no clock,
  no sleeping.
- `tests/mocks/fake_packet_dispatcher.h` (`FakePacketDispatcher`) currently owns **no** `Dispatcher`;
  it gains an **owned `FakeDispatcher` value member** and returns it from `UnderlyingDispatcher()`. It
  must be a stable member (not constructed per call) so a test's timer registrations persist across
  calls. `ssdp_reflector_test.cpp` injects only a `FakePacketDispatcher` today, so without this the
  reflector's `UnderlyingDispatcher()` call would dangle.

**Teardown invariant.** A reflector's `Timer` calls `UnregisterTimer` from its destructor, so the
`Dispatcher` must outlive the reflectors. `Application`'s member order already guarantees this
(`dispatcher_` is declared before `reflectors_`, so it destroys after them); the `Timer` adds a
second consumer to that existing reverse-destruction contract, and the comment there is extended to
name it so a future reorder can't silently break timer teardown. The reflector registers the `Timer`
only on `Initialize`'s success path (mirroring the `registrations_.clear()` rollback) and resets it
in `~SsdpReflector` before dispatcher teardown.

## 4. State lifecycle and eviction

Responses to an `M-SEARCH` arrive within the searcher's `MX` window (UDA: each responder waits a
random delay in `[0, MX]`), so a session is useful for `MX + grace` and then dead. Expiry is fixed
at creation: `expiry = now + clamp(MX, 1, 5)s + SESSION_GRACE`. There is no refresh — the `MX`
contract already bounds when responses stop.

**Deterministic timer sweep.** The reflector's `Timer` (§3.5) fires every `EVICTION_INTERVAL` (1s)
and calls `EvictExpired(steady_clock::now())`, which drops every session past its `expiry`. A session
therefore outlives its usefulness by at most one interval, regardless of whether any further SSDP
traffic arrives — no reliance on packet flow to trigger cleanup. Erasing a `Session` is RAII: it
unregisters the capture and closes the reservation socket.

The timer runs on the same single-threaded event loop as packet capture, so a sweep never interleaves
with a packet dispatch (the reactor handles one event at a time). That also means `EvictExpired`
calls `PacketDispatcher::Unregister` from *outside* any `DispatchPacket` walk — no mid-dispatch
mutation to reason about (§6). The `MAX_SESSIONS` cap remains as a hard safety bound; within a tick,
an expired-but-not-yet-swept session still counts toward it (≤1s of slack on a 32 bound).

`EvictExpired(now)` touches **only** `sessions_` (erasing entries, which drops their `PortReservation`
+ capture `Registration`); it never calls `RegisterTimer`/`UnregisterTimer`, so it cannot mutate the
dispatcher's `timers_` mid-`FireDueTimers`, and it is safe to invoke re-entrantly. (A future change
that adds timer manipulation inside the sweep would have to revisit `FireDueTimers`' snapshot logic —
called out so it isn't done blindly.)

## 5. Source / MAC fields for the reply

The reply is injected on `source_if` toward the searcher:

- **L2:** `dst_mac` = searcher's stored frame MAC; `src_mac` = `source_if`'s own MAC (filled by
  `RawSocket`).
- **dst IP:port** = searcher's stored IP and source port.
- **src port** = the device's response source port (`packet.header.source_port`, typically 1900) —
  preserved.
- **src IP** = `source_if`'s own source address for the family (filled by `RawSocket`, same path as
  `SendUdpDatagram`). We do **not** spoof the device's IP (D3). The searcher matches the response by
  *its own* dest port, not the source IP, so a reply from our address is accepted; it locates the
  service from the `LOCATION` header, not the packet source.

## 6. Loop prevention and capture correctness

- The existing direction gate (Linux `PACKET_IGNORE_OUTGOING`, macOS `BIOCSSEESENT=0`) means we
  never capture our own injected frames. The relayed `M-SEARCH` (dst port 1900) and the injected
  reply (dst port = searcher port) are outbound and excluded.
- The per-session response filter (`{dest_ip = our unicast addr, dest_port = P}`) cannot collide with
  the multicast registrations (`{dest_ip = group, dest_port = 1900}`): different dest IP (our address
  vs the group) and different port (`P` is ephemeral, never 1900).
- AF_PACKET / BPF already see unicast-to-host frames, so the `200 OK` to `target_if`:P is captured
  with no socket-level change — only a new registration.

**Mid-dispatch registration is safe.** `OnSourcePacket` registers the response capture *inside* a
dispatch callback, and `DefaultPacketDispatcher::DispatchPacket` is built for it: it walks
`registrations_` live and uses a `last_dispatched_id` filter, and the new higher-id entry it reaches
for the current packet is on a different socket (`target_socket_` ≠ the `source_socket_` being
drained) with `dest_port = P` ≠ 1900, so it cannot match the M-SEARCH — no spurious dispatch.
Eviction's `Unregister` calls run from `FireDueTimers`, which `Run` invokes *after* `PollOnce` has
fully returned (never nested inside a `DispatchPacket` walk) — so there is no mid-dispatch erase to
reason about.

## 7. Testing

### Unit

- **`port_reservation_test.cpp`** (new): `Create` returns a port; two reservations get distinct
  ports; the port is bound (a second explicit bind to it fails); destruction frees it. Linux:
  assert no ICMP via the connected-sender probe used in design validation (kept as a regression
  test where the platform allows); macOS: bind-and-never-read path.
- **`timer_test.cpp`** + **`event_loop_dispatcher_test.cpp`** (extended): `Timer` over a
  `FakeDispatcher` registers one timer / `IsValid` / unregisters on destruction and after move (no
  double-unregister); `RegisterTimer` rejects `interval <= 0` and an invalid callback. On a real
  `EventLoopDispatcher`, all through **public methods with an injected `now`** (no friend, no clock
  seam, no `sleep`): `FireDueTimers(t0 + interval)` fires a due timer's callback and reschedules it to
  `now + interval` (a second call at the same `now` does not refire; one at `+2·interval` does);
  `FireDueTimers` after `UnregisterTimer` does nothing; `NextTimeout(now)` returns `MAX_POLL_INTERVAL`
  with no timers, clamps down to a pending deadline, and floors at `0ms` for a past-due timer (the
  negative-timeout guard); `PollOnce`'s own `bool` return is unchanged.
- **`ssdp_message_test.cpp`**: `ParseMSearchMx` — present (1–5 verbatim), clamp (`0`→1, `9`→5),
  absent/garbage → default 3, case-insensitivity. (Per house rule, assert parsed values, not log
  text.)
- **`ssdp_reflector_test.cpp`**: with fakes —
  - M-SEARCH relay now originates from the reservation's port and registers a response capture;
    session created. A valid reflector also registers a `Timer` (an extra fd on the dispatcher).
  - A captured `200 OK` on `P` is injected to the stored searcher coordinates (dst = searcher
    IP/port/MAC, src = our own `source_if` address, both families); device MAC filter honored.
  - Unknown/expired `P` → no injection.
  - Eviction driven by **firing the fake timer** (`FakePacketDispatcher`'s owned `FakeDispatcher`),
    not by sleeping: after firing, sessions past `expiry` are erased (releasing capture + reservation)
    and live ones remain. `EvictExpired(now)` is also called directly with a controlled `now` for the
    boundary cases.
  - Cap: the 33rd concurrent search is dropped (no relay, no session); a freed slot admits the next.
  - `NOTIFY` path and classification unchanged (regression).

### Application (`application_test.cpp`)

No new wiring (still `ConfigureReflectors<SsdpReflector>`); existing SSDP application cases must keep
passing. Add a smoke case asserting an SSDP reflector still wires on both interfaces with the proxy
present.

### e2e (`e2e/run.py`, `e2e/config.toml`, `e2e/probe.py`)

Add the active-search round trip the probe couldn't do before:
- Source-side probe sends `M-SEARCH * HTTP/1.1\r\n...MX: 2\r\n...` to the group; a target-side probe,
  on receiving it, unicasts an `HTTP/1.1 200 OK` back to the M-SEARCH's source IP:port; assert the
  source-side probe receives the `200 OK` (payload match). IPv4 + an IPv6 link-local twin.
- Negative: with no matching session (a stray unicast `200 OK` to the reflector), nothing is
  forwarded and (Linux) no crash/leak. Existing multicast cases (`reflects_ssdp_notify`, wrong-
  direction drops) must stay green.

The probe gains a "unicast reply to the sender of a received datagram" helper; the round trip
exercises capture → reserve → relay → capture-response → inject end to end.

## 8. Configuration

No schema change. `SsdpConfig` (`name`, optional `mac`, `source_if`, `target_if`, `address_family`)
is unchanged; the proxy is implied by `ssdp` being enabled. The `mac` filter, if set, now also
scopes which devices' `200 OK` responses are proxied (via the response capture's `source_mac`),
consistent with how it scopes `NOTIFY`.

## 9. Commit breakdown

1. `port_reservation`: the RAII allocator/suppressor + tests (incl. the Linux ICMP regression probe).
2. `dispatcher` timers: `RegisterTimer`/`UnregisterTimer`/`TimerId` on the `Dispatcher` interface +
   `EventLoopDispatcher`'s public `FireDueTimers(now)` / `NextTimeout(now)` (`MAX_POLL_INTERVAL` cap)
   driven by its `Run` (`PollOnce` unchanged) + the `Timer` RAII wrapper + `PacketDispatcher::UnderlyingDispatcher`.
   Companion (same commit, else the test binary won't compile): `FakeDispatcher` gains the timer API +
   on-demand fire helper; `FakePacketDispatcher` gains an owned `FakeDispatcher` + `UnderlyingDispatcher()`.
   + tests.
3. `link_socket`/`raw_socket`: `SendUnicastUdpDatagram` + `SourceAddress` getter + fake + tests.
4. `ssdp_message`: `ParseMSearchMx` + tests.
5. `ssdp_reflector`: session table, M-SEARCH-from-reserved-port relay, `OnUnicastResponse`,
   timer-driven eviction, cap + tests.
6. `e2e`: active-search round-trip cases (v4 + v6).
7. `docs`: README SSDP section — step 2 done; note the proxy is always-on and the `mac` scope.

Each data-path commit runs the full gate (native unit + docker debug/release + e2e) before commit,
per the project workflow.

## 10. Decisions

- **D1 — Port-reservation socket, never read.** Bind to claim the port (kill ICMP) while the raw
  socket captures the response (keeps the source MAC for the `mac` filter). Empirically validated.
  Beats `nberlee` (no ICMP noise) and `udpbroadcastrelay` (keeps the MAC filter).
- **D2 — Reflector-allocated unique ephemeral port `P` per search**, not the searcher's preserved
  source port. The port *is* the demux key; a unique `P` eliminates the cross-searcher collision
  `nberlee` accepts (two searchers sharing an ephemeral source port). The reservation socket doubles
  as the allocator (bind port 0 → `getsockname`).
- **D3 — The reply originates from the reflector's own `source_if` IP (both families); no spoofing.**
  IPv6 link-local must be substituted anyway (the device's `fe80::` is unroutable off its link). For
  IPv4, preserving the device's IP is cosmetic — SSDP clients locate the service via the `LOCATION`
  header, not the response's packet source — and stamping a target-subnet source IP onto a frame
  egressing `source_if` risks IP source-guard / uRPF drops. Own-address is simpler, uniform across
  families, and matches `nberlee`. (Consequently `SendUnicastUdpDatagram` has no `src_ip` parameter;
  it differs from `SendUdpDatagram` only by an explicit unicast `dst_mac`.) (§5)
- **D4 — Fixed `MX + grace` expiry, swept by a periodic `Timer`.** The `MX` contract bounds response
  arrival; a 1s reactor timer evicts deterministically rather than relying on packet flow (no lazy
  sweep). The reactor **owns and fires the timers itself** (portable — no `timerfd`/`EVFILT_TIMER`):
  `Run` composes the **unchanged** `PollOnce` with two new public reactor methods, `NextTimeout(now)`
  (clamp the wait to the soonest deadline, capped at the fixed `MAX_POLL_INTERVAL`) and
  `FireDueTimers(now)` (sweep after `PollOnce` returns), so timers fire on every iteration including the
  idle no-fd path. The `now` *parameter* on both methods is the test seam — the whole timer path is tested through public methods with an injected
  `now`, so **no clock-seam member and no `EventLoopDispatcherTest` friendship** (consistent with the
  friendship-removal sweep). The reflector reaches the reactor via
  `PacketDispatcher::UnderlyingDispatcher()` and holds a `Timer` (RAII over
  `RegisterTimer`/`UnregisterTimer`). (Rejected: an fd-backed timer — `timerfd` isn't portable and the
  macOS workaround added complexity for no benefit. Rejected: splitting/restructuring `PollOnce` or
  firing inside it — needs no early-return surgery once firing lives in `Run`, and a public
  `FireDueTimers(now)` is simpler to test. Rejected: a private `Now()` clock seam + test friend — the
  `now` parameter removes the need for both.)
- **D5 — Cap 32 per reflector, drop-new.** Reject new searches at capacity rather than evicting
  in-flight ones (RFC 6888 posture); searches are retried by clients.
- **D6 — Always-on, no toggle.** The proxy is the completion of `ssdp`, not a separate feature.

## 11. Out of scope (step 3)

- **DIAL proxy.** HTTP/TCP proxy for the DIAL REST endpoint (the LG TV accepts DIAL only from its own
  subnet). Once discovery works cross-segment via step 2, the searcher still can't fetch the device's
  `LOCATION` URL or drive DIAL across segments — that needs an L7 TCP proxy, architecturally distinct
  from this L2/UDP reflector. Its own design pass.
