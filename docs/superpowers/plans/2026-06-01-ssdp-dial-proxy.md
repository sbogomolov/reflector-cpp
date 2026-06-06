# SSDP DIAL Application Proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cross-segment DIAL (UPnP "Discovery And Launch") work through the reflector alone — a self-contained, opt-in (`dial = true`) terminating HTTP reverse proxy that lets a client on `source_if` drive a DIAL device on `target_if` with no router NAT rule.

**Architecture:** A terminating TCP reverse proxy integrated into the existing single-threaded reactor. The reactor gains write-interest control (for non-blocking `connect()` completion and send-buffer flush; read stays always armed). `DialProxy` (owned by `SsdpReflector`, gated by `dial = true`) rewrites the DIAL `LOCATION` in proxied SSDP responses to point at itself, stands up an ephemeral TCP listener per discovered device endpoint, and for each accepted client connection opens an upstream connection bound to `target_if`'s address (so the device sees an its-subnet source). It forwards HTTP, rewriting only four headers (`LOCATION`, `Application-URL`, response `Location`, request `Host`) by authority substitution — bodies stream through verbatim (Content-Length or chunked). State is bounded (drop-new caps + role-based idle eviction + drop-and-close bounded buffers), all RAII, all reactor-driven, no threads. Grounded in a packet capture of a real LG webOS TV and the DIAL v1.6.4 spec. Full design: `docs/superpowers/specs/2026-06-01-ssdp-dial-proxy-design.md`.

**Tech Stack:** C++23, GoogleTest, the project's `Delegate`/`Registration`/`Timer` reactor primitives, raw POSIX TCP sockets (epoll on Linux / kqueue on macOS), Python for the e2e harness + DIAL device emulator. Build with `./cmake_gen.sh` (Debug, ASan+UBSan); test with `ctest --test-dir build -L unit --output-on-failure`.

---

## Commit sequence (each lands green; data-path commits run the full gate first)

1. **`dispatcher`** — reactor read/write interest control (lands alone, like the timer commit; no DIAL dependency).
2. **`tcp_socket`** — the `IpEndpoint` value type + a non-blocking `TcpSocket` RAII wrapper.
3. **`http_message`** — minimal HTTP/1.1 framing + `ParseAuthority` (endpoint + authority span; pure, no sockets).
4. **`dial_proxy`** — the `DialProxy` orchestrator (listeners, connection pump, drop-and-close backpressure, eviction).
5. **`ssdp_reflector` + `config`** — the `dial` flag (the only DIAL knob) + `Verify` rules + the SSDP `LOCATION` rewrite hooks.
6. **`e2e` + `docs`** — a DIAL device emulator + launch round-trip case, and the README section.

The **full test gate** (native `ctest -L unit` + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`, with `grep REFLECTOR_SANITIZE build/CMakeCache.txt` showing `ON`) runs before each data-path commit (4, 5, 6).

---

## File structure

**New source files**
- `src/reflector/ip_endpoint.h` — `IpEndpoint { IpAddress addr; uint16_t port; }` value type (+ `operator==`, `std::formatter`, and the family-aware `ToSockaddr`/`FromSockaddr` conversion so `TcpSocket` stays family-agnostic). *(Commit 2)*
- `src/reflector/util/stream_buffer.h` — `StreamBuffer`, a fixed-capacity FIFO byte buffer over a lazily allocated, never-zeroed block; backs both the send side (`Append`, capped) and the receive side (`ReserveTail`/`Commit` — read into the writable tail). Header-only, tested standalone. *(Commit 2; generalized 9a917f2)*
- `src/reflector/tcp_socket.{h,cpp}` — move-only, **dispatcher-inert** non-blocking TCP RAII (`Listen`/`Accept`/`Connect`(bound+pinned)/`Read`/`Send`+bounded`StreamBuffer`/`Flush`/`WantsWrite`/`IsConnecting`/`FinishConnect`), SIGPIPE-safe; v4/v6. Holds no `Registration` — the owner does (B2, §11 D12). *(Commit 2)*
- `src/reflector/http_message.{h,cpp}` — `ParseAuthority` (shared, endpoint + span) + `HttpFraming` (incremental HTTP/1.1 framing + header rewrite). *(Commit 3)*
- `src/reflector/dial_proxy.{h,cpp}` — `DialProxy`, `Endpoint`/`Connection`, the connection pump, drop-and-close backpressure, eviction `Timer` (the bounded send `StreamBuffer` lives in `TcpSocket`, C2; per-direction receive `StreamBuffer`s in each `Connection`). *(Commit 4)*

**Modified source files**
- `src/reflector/dispatcher.h`, `src/reflector/event_loop_dispatcher.{h,cpp}` — `OnWritableCallback`, `FdCallbacks` `Register`, `SetWriteInterest` (read always armed; no `SetReadInterest`). *(Commit 1)*
- `src/reflector/config.{h,cpp}` — `SsdpConfig` gains the `dial` bool only (+ `Verify` rules, formatter, TOML parse). **The DIAL caps/timeouts are fixed constants** in `dial_proxy.h`/`http_message.h` (like `SsdpReflector`'s `MAX_SESSIONS`), **not** config — this supersedes the `dial_max_*`/`dial_*_idle`/`dial_connect_timeout`/`dial_max_header_bytes` `SsdpConfig` fields + their parse/Verify/tests in the Commit 5 task steps below. *(Commit 5)*
- `src/reflector/ssdp_reflector.{h,cpp}` — `std::optional<DialProxy> dial_proxy_` + the `LOCATION` rewrite hooks in `OnUnicastResponse`/`OnTargetPacket`. *(Commit 5)*
- `src/reflector/ssdp_message.{h,cpp}` — two DIAL helpers: service-type classification + `LOCATION`-authority parse. *(Commit 5)*

**Test files** (new tests are added to the `reflector_test` source list in `tests/CMakeLists.txt`)
- New: `tests/ip_endpoint_test.cpp` + `tests/tcp_socket_test.cpp` *(C2)*, `tests/http_message_test.cpp` *(C3)*, `tests/dial_proxy_test.cpp` *(C4)*.
- Extended: `tests/event_loop_dispatcher_test.cpp` *(C1)*, `tests/config_test.cpp` + `tests/ssdp_reflector_test.cpp` + `tests/application_test.cpp` *(C5)*.
- Mocks: `tests/mocks/fake_dispatcher.h` gains `FireWritable`/`SetWriteInterest`/`IsWriteArmed` *(C1)* and `WatchedFds()` *(C4)*.

**e2e / docs**
- `e2e/run.py`, `e2e/config.toml`, plus a DIAL device emulator; `README.md` DIAL section. *(Commit 6)*

---

## Interface contract (the cross-commit source of truth)

Every task uses these signatures verbatim. Types are introduced by the commit noted; later commits depend on them.

```cpp
// ---- Commit 1: reactor write-interest control + always-armed read (dispatcher.h) ----
using OnWritableCallback = Delegate<void(int)>;                 // fd became writable (connect-completion / flush)
// The FdCallbacks form is the one pure virtual; the readability-only 2-arg form is a non-virtual convenience.
struct FdCallbacks { OnReadableCallback read; OnWritableCallback write; bool write_armed = false; };  // read REQUIRED + ALWAYS armed; write the only flippable direction
[[nodiscard]] virtual Registration Register(int fd, FdCallbacks callbacks) = 0;                       // fails if read unset, or fd already watched
[[nodiscard]] Registration         Register(int fd, const OnReadableCallback& r) { return Register(fd, FdCallbacks{.read = r}); }
[[nodiscard]] virtual bool SetWriteInterest(int fd, bool enabled) noexcept = 0;  // epoll MOD +/- EPOLLOUT; kqueue EVFILT_WRITE ENABLE/DISABLE
// Read is ALWAYS armed: an error/hangup surfaces as readability (recv reveals it), so the read handler is the
// uniform teardown home and a never-zero interest mask can't busy-spin. There is NO SetReadInterest / read-
// pausing — backpressure is drop-and-close. FakeDispatcher mirrors this: FireReadable / FireWritable,
// SetWriteInterest, IsWriteArmed (no SetReadInterest / IsReadArmed / read_armed).

// ---- Commit 2: ip_endpoint.h + util/stream_buffer.h + tcp_socket.{h,cpp}  (as built: d08290c; StreamBuffer generalized 9a917f2) ----
struct IpEndpoint { IpAddress addr; uint16_t port = 0; auto operator<=>(const IpEndpoint&) const noexcept = default; };  // + std::hash + std::formatter ("127.0.0.1:80" / "[::1]:80")
//   socklen_t ToSockaddr(sockaddr_storage&, unsigned scope_id = 0) const; static optional<IpEndpoint> FromSockaddr(const sockaddr*);  // family-aware, delegates to IpAddress
class StreamBuffer {  // util/stream_buffer.h — fixed-capacity FIFO byte buffer, lazy non-zeroed alloc; both directions, move-safe
  explicit StreamBuffer(size_t capacity);  size_t Size() const; bool Empty() const; size_t Capacity() const;
  bool Append(std::span<const std::byte>);                          // send side; false (writes nothing) if it would pass the cap
  std::span<std::byte> ReserveTail(); void Commit(size_t);          // receive side: read into the writable tail, commit the count
  std::span<const std::byte> View() const; void Consume(size_t);    // drain (both directions)
};
enum class IoStatus   : uint8_t { Ok, WouldBlock, Closed, Error };  // Closed is read-only
struct IoResult { IoStatus status = IoStatus::Error; size_t bytes = 0; };  // shared by Read and the private WriteSome
enum class SendStatus : uint8_t { Ok, Overflow, Error };
class TcpSocket {  // move-only (NoCopy), dispatcher-INERT: holds no Registration; the owner drives write interest
  static std::optional<TcpSocket> Listen(const IpEndpoint& bind);                                  // SO_REUSEADDR; bind (port 0 = ephemeral, read back via LocalEndpoint); listen
  std::optional<TcpSocket>        Accept() noexcept;                                               // non-blocking + SIGPIPE-safe child; nullopt on EAGAIN/error
  static std::optional<TcpSocket> Connect(const IpEndpoint& dst, const IpEndpoint& bind, unsigned ifindex = 0);  // egress-pinned; EINPROGRESS = success (starts CONNECTING)
  bool IsConnecting() const noexcept; IoStatus FinishConnect() noexcept;                           // no-op Ok once established; Error on a failed connect
  IoResult   Read(std::span<std::byte>) noexcept;                                                  // {Ok,n}/{WouldBlock,0}/{Closed,0}/{Error,0}
  SendStatus Send(std::span<const std::byte>) noexcept;                                            // writes what it can + buffers the tail; Overflow past MAX_SEND_BUFFER (8 KB)
  SendStatus Flush() noexcept;                                                                     // drains the buffer on a writable edge
  bool WantsWrite() const noexcept;                                                                // connecting || !buffer.empty(); owner forwards to SetWriteInterest
  int Fd() const noexcept; bool IsValid() const noexcept;
  std::optional<IpEndpoint> LocalEndpoint() const noexcept; std::optional<IpEndpoint> PeerEndpoint() const noexcept;  // getsockname/getpeername
};

// ---- Commit 3: http_message.{h,cpp}  (as built) ----
[[nodiscard]] std::string RewriteAuthority(std::string_view text, const IpEndpoint& from, const IpEndpoint& to);  // shared with the SSDP LOCATION path
class HttpFraming {  // incremental HTTP/1.1 framing + header rewrite; only the header is copied (to rewrite it)
  using EndpointRewrite = Delegate<std::optional<IpEndpoint>(const IpEndpoint& found)>;  // bound per direction by the owner
  struct Output { std::string_view header; std::string_view body; size_t consumed; };  // header -> rewritten scratch; body -> zero-copy slice of input
  explicit HttpFraming(EndpointRewrite rewrite);   // side-agnostic: inspects Host (req) + Application-URL/Location (resp); MAX_HEADER_BYTES = fixed 2 KB constant
  // Owner reads into its receive StreamBuffer, feeds a View, sends header+body in one sendmsg (scatter-gather Send), drops `consumed`.
  // nullopt = malformed / over-cap -> owner closes; consumed == 0 = nothing forwardable yet (incomplete header). One message per Feed.
  [[nodiscard]] std::optional<Output> Feed(std::string_view input);
};

// ---- Commit 4: dial_proxy.{h,cpp} ----
// Connection holds two per-direction receive StreamBuffers (read into the tail, feed HttpFraming, retain the unconsumed carry); the send StreamBuffers live inside each TcpSocket.
class DialProxy {  // NoMove; owned by SsdpReflector; reaches the reactor via PacketDispatcher::UnderlyingDispatcher()
 public:
  [[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(IpEndpoint device);   // the ONLY public method
 private:
  std::optional<IpEndpoint> EnsureRestListener(IpEndpoint device);      // used by the response-side EndpointRewrite
  std::optional<IpEndpoint> EnsureListener(IpEndpoint device, /*Role*/ int role);
  // Caps (fixed constants): MAX_REST_LISTENERS, MAX_DISCOVERY_LISTENERS, MAX_CONNECTIONS (drop-new).
  // Backpressure: drop-and-close — a Send past TcpSocket's MAX_SEND_BUFFER aborts the connection; read
  //   stays always-armed (no read-pausing / flow control).
};

// ---- Commit 5: config + ssdp_reflector ----
// SsdpConfig: adds `bool dial = false` only — the sole DIAL config. Every cap/timeout (the listener caps,
//   MAX_CONNECTIONS, idle/connect timeouts, and HttpFraming's MAX_HEADER_BYTES) is a fixed constant, not config.
// SsdpConfig::Verify() rejects: dial && !ssdp-enabled; and dial && !UsesIPv4() (address_family == ipv6) — DIAL is IPv4-only.
// SsdpReflector: std::optional<DialProxy> dial_proxy_ (Initialize success when config.dial; destroyed before the dispatcher).
//   OnUnicastResponse + OnTargetPacket: if dial && DIAL-service message with a LOCATION -> parse device endpoint,
//   EnsureDiscoveryListener(device), RewriteAuthority-splice into LOCATION, then inject (unchanged on nullopt / non-DIAL).
```

---

## Commit 1: dispatcher — read/write interest control

This commit gives the readability-only reactor one new control — a write callback with dynamic write interest (read stays **always armed**) — landed and tested in isolation, exactly like the step-2 timer commit, before any DIAL code. After this commit, every existing consumer is unaffected (the 2-arg `Register` still compiles), and the proxy (Commit 4) drives connect-completion + send-buffer flush via `SetWriteInterest`. **See the read-always-armed pivot (correction 8 below) — it supersedes the `SetReadInterest`/`read_armed`/flow-control material in the task steps that follow.**

> **API change from review.** `Register` takes a single **public** `Dispatcher::FdCallbacks` struct — `{ OnReadableCallback read{}; OnWritableCallback write{}; bool read_armed = true; bool write_armed = false; }` (handlers first, the two arm flags last) — *instead of* the 3-arg `(fd, on_readable, on_writable)` form shown in the tasks below. This lets the caller pick the **initial** arm state (the connecting upstream in Commit 4 registers `{.read_armed = false, .write_armed = true}` to watch connect-completion with read off — no follow-up `SetWriteInterest`). The 2-arg `Register(fd, on_readable)` convenience is unchanged. Mapping for the task code below: `Register(fd, read, write)` → `Register(fd, {.read = ..., .write = ...})`. `FdCallbacks` lives on the `Dispatcher` base (public); `EventLoopDispatcher`/`FakeDispatcher` drop their private copies. The handler members carry `{}` DMIs so a designated init omitting one (the 2-arg convenience, or the write-only connect registration) doesn't trip GCC's `-Wmissing-field-initializers`. `Register` impls take `FdCallbacks` by value and `std::move` it into `callbacks_`; `AddEvents` honors the initial flags (and still only adds the kqueue write filter when armed — keeping the BPF fix below).
>
> **Corrections applied during implementation** (these supersede the matching code in the tasks below; the build/tests exposed each one):
> 1. **Per-direction primitives `SetReadEvent`/`SetWriteEvent`, a handler guard (review) + the BPF fix.** `Register` programs both directions directly — `SetReadEvent(fd, read_armed)` then `SetWriteEvent(fd, write_armed)`, rolling back via `RemoveEvents` if the second fails (no separate `AddEvents`; no `Direction` enum — it only selected a branch). Each primitive does NOT touch the armed flags — the caller (`Register`, or the public `SetRead/WriteInterest`) owns those. They:
>    - **Refuse to *arm* a direction whose handler is unset** (`enabled && !callback.IsValid()` ⇒ `false`): an armed-but-undrained fd would busy-spin the level-triggered loop. Disarming is always allowed.
>    - **kqueue:** `SetReadEvent` always `EV_ADD`'s `EVFILT_READ` (enable/disable). `SetWriteEvent` `EV_ADD|EV_ENABLE`'s `EVFILT_WRITE` **only when arming**; disarming uses bare `EV_DISABLE` tolerating `ENOENT`. So `EVFILT_WRITE` is never `EV_ADD`'d on a BPF capture device (which rejects it with `EINVAL` — the bug that broke *every* raw-socket registration, `DefaultPacketDispatcherRequiresRootTest`).
>    - **epoll:** both call one shared `UpdateEpollMask(fd, read_on, write_on)` (epoll has no per-direction toggle — the whole mask is rewritten); `EPOLL_CTL_MOD` returns `ENOENT` on an fd's first call (from `Register`), so it falls back to `EPOLL_CTL_ADD`.
>    `RemoveEvents` deletes both kqueue filters in a loop, tolerating `ENOENT` (an absent write filter, or a closed fd whose filters kqueue already auto-removed) and reporting only genuine errors; on epoll a single `EPOLL_CTL_DEL`. It is not `[[nodiscard]]` (it self-logs), so the `Register` rollback ignores its result without a `(void)` cast.
> 2. **`using Dispatcher::Register;`** — the 3-arg `Register` override name-hides the base 2-arg convenience, breaking every existing 2-arg call site. Add `using Dispatcher::Register;` right after the 3-arg override in BOTH `EventLoopDispatcher` (Task 1.2) and `FakeDispatcher` (Task 1.3).
> 3. **`SetReadEvent` (macOS) cast** — the runtime read-filter flags need `static_cast` under `-Wconversion`: `const auto flags = static_cast<uint16_t>(EV_ADD | (enabled ? EV_ENABLE : EV_DISABLE));` (the write-filter flags in `SetWriteEvent` are compile-time constants, so they don't).
> 4. **`override` on the fake's interest setter** — `FakeDispatcher::SetWriteInterest` must be marked `override` (Linux `-Wsuggest-override -Werror`).
> 5. **`::htonl` → `htonl`** in the test helpers (`LoopbackPair` and the connect test) — on macOS `htonl` is a macro and can't be `::`-qualified.
> 6. **`const auto registration` → `auto registration`** in `CompletedLoopbackConnectSurfacesAsWritableWithNoSoError` — it calls the non-const `registration.Reset()`.
> 7. **`PollOnce` Linux error-event dispatch (review).** Three fixes: (a) removed the leftover early-out (`(EPOLLERR|EPOLLHUP) && !EPOLLIN ⇒ return false`) — it suppressed a *failed connect* (which arrives as `EPOLLERR` with no `EPOLLIN`), so the write handler never fired; (b) fold the error bits into **both** directions (`readable |= err; writable |= err`) and let the armed-gates route to whichever direction the fd watches (read handler recv()s the EOF/error, write handler reads `SO_ERROR`); (c) **re-look-up the live entry before the write dispatch** — a read handler that tore the fd down (read EOF → close the connection) in the same poll would otherwise use-after-free / wrongly fire the write handler (`EPOLLIN|EPOLLHUP` already lets both fire in one poll). Regression test: `FailedConnectSurfacesToAnArmedHandler`.
> 8. **Late design pivot — read is always armed; `SetReadInterest`/`read_armed`/the both-disarmed "H" guard removed.** *(Supersedes the `SetReadInterest`, `read_armed`, both-directions-disarmed, and read-pausing flow-control material throughout this commit's tasks AND §4.4.)* Backpressure was settled as **drop-and-close** — a bounded per-`TcpSocket` `SendBuffer` that aborts the connection on overflow, not lossless read-pausing — so read is never paused. Read is therefore made **always armed and required**: `FdCallbacks` drops `read_armed` → `{ OnReadableCallback read; OnWritableCallback write; bool write_armed = false; }`; `SetReadInterest` and the fake's `SetReadInterest`/`IsReadArmed` are removed; `Register` rejects a missing read handler. The two per-direction primitives `SetReadEvent`/`SetWriteEvent` and the `UpdateEpollMask` epoll helper (correction 1) collapse into one `SetEvents(fd, enable_write)` — read always armed, write per flag (keeping the BPF write-filter guard) — since read is no longer independently toggled. `PollOnce` dispatches read on any `readable` (no flag) and re-resolves the entry only then for the write. An interim **"H" guard** (drop a both-directions-disarmed fd from the epoll set to stop an unmaskable `EPOLLERR` busy-spin) was added and then **removed** — always-armed read keeps `EPOLLIN` in the mask, so the both-disarmed state is unreachable and the guard is unnecessary. A connecting upstream registers `{.read = forward, .write = on_connected, .write_armed = true}` (read armed but dormant until data/error; a server-speaks-first peer reaches `Open` via the read path through a shared transition). **Edge-triggered** (`EPOLLET`/`EV_CLEAR`) was evaluated as an alternative and rejected — keep level-triggered; flip only if the reactor ever goes TCP-only. Tests: the `SetReadInterest`/both-disarmed cases are removed; `FailedConnectSurfacesToAnArmedHandler` asserts the error folds onto the always-armed read. The standalone `tests/fake_dispatcher_test.cpp` (and its task steps below) was **dropped** — unit-testing the mock in isolation is redundant (`FakeDispatcher` is already exercised by `timer_test` / `default_address_monitor_test` / `application_test`), and its new write helpers (`FireWritable` / `IsWriteArmed`) get exercised for real by the DIAL proxy tests in Commit 4.

### Task 1.1: `OnWritableCallback` + the 3-arg `Register` virtual and 2-arg convenience on the `Dispatcher` interface

**Files**
- Modify: `src/reflector/dispatcher.h`

The `Dispatcher` interface is abstract and shared by `EventLoopDispatcher` and `FakeDispatcher`. We change its pure-virtual `Register` from 2-arg to 3-arg (read + write callback) and add a non-virtual 2-arg convenience that forwards an empty writable callback, plus the two interest-toggle pure virtuals. There is no isolated unit test for the interface header itself — it has no behavior — so this task is driven by the two implementation tasks (1.2 `EventLoopDispatcher`, 1.3 `FakeDispatcher`) whose tests fail to compile until the interface exists, then fail at runtime until the implementations are written. We make the interface edit first so those tasks compile.

- [ ] **Step 1: Add the write callback alias and the new virtuals to `src/reflector/dispatcher.h`.** Insert the `OnWritableCallback` alias next to `OnReadableCallback`, and replace the single `Register` declaration with the 3-arg pure virtual + 2-arg convenience + the two interest toggles. The full edited region (the alias block above the class, and the public method block replacing the old 2-arg `Register`):

  Replace the existing readable-callback alias comment+alias:

  ```cpp
  // Invoked with the fd that became readable. EventLoopDispatcher binds one of these per watched
  // fd; subscribers (e.g. DefaultPacketDispatcher, the interface-address monitor) bind their own.
  using OnReadableCallback = Delegate<void(int)>;

  // Invoked with the fd that became writable. A non-blocking connect() signals completion by
  // becoming writable, and a partially-drained send buffer flushes on the next writable. Write
  // interest starts disarmed (see SetWriteInterest) so a readability-only consumer never sees it.
  using OnWritableCallback = Delegate<void(int)>;
  ```

  Then replace the old single `Register` declaration:

  ```cpp
    // Watches `fd` for readability and invokes `on_readable(fd)` whenever it has data; one
    // registration per fd (re-registering an already-watched fd fails). The returned registration
    // must not outlive this dispatcher.
    [[nodiscard]] virtual Registration Register(int fd, const OnReadableCallback& on_readable) = 0;
  ```

  with:

  ```cpp
    // Watches `fd` and invokes `on_readable(fd)` whenever it has data and `on_writable(fd)` whenever
    // it can accept more (write interest starts disarmed — see SetWriteInterest). One registration
    // per fd (re-registering an already-watched fd fails). The returned registration must not
    // outlive this dispatcher. Read interest starts ARMED, so the 2-arg convenience below — which
    // every existing readability-only consumer uses — is unchanged.
    [[nodiscard]] virtual Registration Register(
        int fd, const OnReadableCallback& on_readable, const OnWritableCallback& on_writable) = 0;

    // Readability-only convenience: forwards an empty write callback. Non-virtual so the one pure
    // virtual is the 3-arg form (implementations override only that).
    [[nodiscard]] Registration Register(int fd, const OnReadableCallback& on_readable) {
        return Register(fd, on_readable, OnWritableCallback{});
    }

    // Toggle writability notification for an already-registered fd (epoll EPOLL_CTL_MOD +/- EPOLLOUT;
    // kqueue EVFILT_WRITE EV_ENABLE/EV_DISABLE). Arm to learn when a non-blocking connect completes
    // or a backed-up send buffer can flush; disarm once it drains, to avoid a writable-spin on the
    // level-triggered reactor. Idempotent; returns false on an unknown fd.
    [[nodiscard]] virtual bool SetWriteInterest(int fd, bool enabled) noexcept = 0;

    // Toggle readability notification for an already-registered fd (epoll EPOLL_CTL_MOD +/- EPOLLIN;
    // kqueue EVFILT_READ EV_ENABLE/EV_DISABLE). Read interest defaults ARMED at Register, so existing
    // consumers are unaffected. Disarming MUST stop the kernel delivering readable events (not merely
    // skip a userland pump) — the reactor is level-triggered, so a still-armed undrained readable fd
    // would busy-spin. Used to apply backpressure (flow control). Idempotent; false on an unknown fd.
    [[nodiscard]] virtual bool SetReadInterest(int fd, bool enabled) noexcept = 0;
  ```

  This is interface-only; the build is broken until Tasks 1.2 and 1.3 override the new virtuals. We verify it together with Task 1.2's first build.

### Task 1.2: `EventLoopDispatcher` — write callback dispatch + epoll/kqueue arm-disarm of both directions

**Files**
- Modify: `src/reflector/event_loop_dispatcher.h`
- Modify: `src/reflector/event_loop_dispatcher.cpp`
- Modify: `tests/event_loop_dispatcher_test.cpp`

- [ ] **Step 1: Write the failing tests in `tests/event_loop_dispatcher_test.cpp`.** Add a `WritableCounter` helper and seven new `TEST_F`s exercising: `SetWriteInterest`/`SetReadInterest` arm-disarm + unwatched-fd rejection; a real loopback readable fd whose read interest is disarmed stops firing and re-arming delivers it (the busy-spin fix); a completed loopback `connect` surfaces as writable with `SO_ERROR == 0`. Insert the new `#include`s at the top and a `WritableCounter` struct after the existing `ReadableCounter` (line 58), then append the tests before the closing `} // namespace reflector`.

  Add these includes after the existing `#include <unistd.h>` (line 12):

  ```cpp
  #include "reflector/util/no_copy.h"

  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <fcntl.h>
  ```

  Add this helper right after the `ReadableCounter` struct (after line 58):

  ```cpp
  struct WritableCounter {
      void OnWritable(int fd) {
          ++count;
          last_fd = fd;
      }
      int count = 0;
      int last_fd = -1;
  };

  // A connected loopback TCP socket pair: `client` is a non-blocking fd whose readability/writability
  // the dispatcher watches; `server` is the peer used to push bytes at it. Needs no privilege —
  // 127.0.0.1 loopback TCP is unprivileged — so this stays in the plain (non-RequiresRoot) fixture.
  struct LoopbackPair : NoCopy {
      LoopbackPair() noexcept {
          const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
          if (listener < 0) {
              return;
          }
          sockaddr_in addr{};
          addr.sin_family = AF_INET;
          addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
          addr.sin_port = 0;
          socklen_t len = sizeof(addr);
          if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
              ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) != 0 ||
              ::listen(listener, 1) != 0) {
              ::close(listener);
              return;
          }
          const int c = ::socket(AF_INET, SOCK_STREAM, 0);
          if (c >= 0) {
              if (::connect(c, reinterpret_cast<sockaddr*>(&addr), len) == 0) {
                  const int s = ::accept(listener, nullptr, nullptr);
                  if (s >= 0) {
                      client = c;
                      server = s;
                  } else {
                      ::close(c);
                  }
              } else {
                  ::close(c);
              }
          }
          ::close(listener);
      }
      ~LoopbackPair() noexcept {
          if (client >= 0) {
              ::close(client);
          }
          if (server >= 0) {
              ::close(server);
          }
      }
      bool Valid() const noexcept { return client >= 0 && server >= 0; }
      bool PushByteToClient() const noexcept {
          const std::byte one{1};
          return ::send(server, &one, 1, 0) == 1;
      }
      int client = -1;
      int server = -1;
  };
  ```

  Append these tests before the closing namespace brace:

  ```cpp
  TEST_F(EventLoopDispatcherTest, SetWriteInterestRejectsUnwatchedFd) {
      EXPECT_FALSE(dispatcher.SetWriteInterest(999, true));
      EXPECT_FALSE(dispatcher.SetWriteInterest(999, false));
  }

  TEST_F(EventLoopDispatcherTest, SetReadInterestRejectsUnwatchedFd) {
      EXPECT_FALSE(dispatcher.SetReadInterest(999, true));
      EXPECT_FALSE(dispatcher.SetReadInterest(999, false));
  }

  TEST_F(EventLoopDispatcherTest, SetWriteInterestArmsAndDisarmsAWatchedFd) {
      LoopbackPair pair;
      ASSERT_TRUE(pair.Valid());
      ReadableCounter reader;
      WritableCounter writer;

      const auto registration = dispatcher.Register(
          pair.client,
          CreateDelegate<&ReadableCounter::OnReadable>(&reader),
          CreateDelegate<&WritableCounter::OnWritable>(&writer));
      ASSERT_TRUE(registration.IsValid());

      // Write interest starts disarmed: a freshly-connected, writable socket fires no write callback.
      EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
      EXPECT_EQ(writer.count, 0);

      // Armed: the writable socket now fires the write callback (idempotent re-arm is harmless).
      EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, true));
      EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, true));
      EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
      EXPECT_EQ(writer.count, 1);
      EXPECT_EQ(writer.last_fd, pair.client);

      // Disarmed: no further write events even though the socket is still writable.
      EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, false));
      EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
      EXPECT_EQ(writer.count, 1);
  }

  TEST_F(EventLoopDispatcherTest, SetReadInterestDisarmStopsADrainedReadableFdFromFiring) {
      LoopbackPair pair;
      ASSERT_TRUE(pair.Valid());
      ReadableCounter reader;
      WritableCounter writer;

      const auto registration = dispatcher.Register(
          pair.client,
          CreateDelegate<&ReadableCounter::OnReadable>(&reader),
          CreateDelegate<&WritableCounter::OnWritable>(&writer));
      ASSERT_TRUE(registration.IsValid());

      // Make the client readable, then disarm read interest WITHOUT draining the byte. On a
      // level-triggered reactor a still-armed undrained fd re-fires forever; disarming must stop the
      // kernel delivering the event — so PollOnce returns without invoking the read callback.
      ASSERT_TRUE(pair.PushByteToClient());
      EXPECT_TRUE(dispatcher.SetReadInterest(pair.client, false));
      EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
      EXPECT_EQ(reader.count, 0);

      // Re-arm: the still-pending byte is delivered naturally on the next poll (no manual re-pump).
      EXPECT_TRUE(dispatcher.SetReadInterest(pair.client, true));
      EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
      EXPECT_EQ(reader.count, 1);
      EXPECT_EQ(reader.last_fd, pair.client);
  }

  TEST_F(EventLoopDispatcherTest, ExistingReadabilityIsUnaffectedByTheNewRegisterForm) {
      // The 2-arg convenience must keep read interest armed by default (no behavior change).
      ReadablePipe pipe;
      ASSERT_GE(pipe.ReadEnd(), 0);
      ReadableCounter counter;

      const auto registration = dispatcher.Register(
          pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&counter));
      ASSERT_TRUE(registration.IsValid());

      ASSERT_TRUE(pipe.Notify());
      EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
      EXPECT_EQ(counter.count, 1);
  }

  TEST_F(EventLoopDispatcherTest, CompletedLoopbackConnectSurfacesAsWritableWithNoSoError) {
      // A non-blocking connect to a listening loopback port completes via a writable event; SO_ERROR
      // reads 0 once connected. This drives the connect-completion path the proxy (Commit 4) uses.
      const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
      ASSERT_GE(listener, 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
      addr.sin_port = 0;
      socklen_t len = sizeof(addr);
      ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), len), 0);
      ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len), 0);
      ASSERT_EQ(::listen(listener, 1), 0);

      const int client = ::socket(AF_INET, SOCK_STREAM, 0);
      ASSERT_GE(client, 0);
      ASSERT_EQ(::fcntl(client, F_SETFL, O_NONBLOCK), 0);
      const int rc = ::connect(client, reinterpret_cast<sockaddr*>(&addr), len);
      ASSERT_TRUE(rc == 0 || errno == EINPROGRESS);

      WritableCounter writer;
      const auto registration = dispatcher.Register(
          client,
          OnReadableCallback{},
          CreateDelegate<&WritableCounter::OnWritable>(&writer));
      ASSERT_TRUE(registration.IsValid());
      ASSERT_TRUE(dispatcher.SetWriteInterest(client, true));

      EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
      EXPECT_EQ(writer.count, 1);
      EXPECT_EQ(writer.last_fd, client);

      int so_error = -1;
      socklen_t err_len = sizeof(so_error);
      ASSERT_EQ(::getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error, &err_len), 0);
      EXPECT_EQ(so_error, 0);

      ASSERT_TRUE(registration.Reset());
      ::close(client);
      ::close(listener);
  }
  ```

- [ ] **Step 2: Run the new tests — expect a COMPILE failure (the new API does not exist yet on `EventLoopDispatcher`).** Until Step 3, `SetWriteInterest`/`SetReadInterest` and the 3-arg `Register` override are undeclared, and `EventLoopDispatcher` is still abstract because it does not override the new pure virtuals:

  ```sh
  cmake --build build 2>&1 | tail -30
  ```

  Expected: compile errors such as `'class reflector::EventLoopDispatcher' has no member named 'SetWriteInterest'` and `invalid new-expression of abstract class type 'reflector::EventLoopDispatcher'`.

- [ ] **Step 3: Change `callbacks_` to an `FdCallbacks` map and declare the new methods in `src/reflector/event_loop_dispatcher.h`.** Replace the old 2-arg `Register` declaration, the `AddReadEvent`/`RemoveReadEvent` helper declarations, and the `callbacks_` member.

  Replace:

  ```cpp
      [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override;
  ```

  with:

  ```cpp
      [[nodiscard]] Dispatcher::Registration Register(
          int fd, const OnReadableCallback& on_readable, const OnWritableCallback& on_writable) override;
      [[nodiscard]] bool SetWriteInterest(int fd, bool enabled) noexcept override;
      [[nodiscard]] bool SetReadInterest(int fd, bool enabled) noexcept override;
  ```

  Replace the two read-event helper declarations:

  ```cpp
      [[nodiscard]] bool AddReadEvent(int fd) noexcept;
      [[nodiscard]] bool RemoveReadEvent(int fd) noexcept;
      bool Unregister(int fd) noexcept override;
  ```

  with a generalized event-filter helper set that arms/disarms read and write, plus the unchanged `Unregister`:

  ```cpp
      // One direction of interest on a watched fd. Read maps to EPOLLIN / EVFILT_READ, Write to
      // EPOLLOUT / EVFILT_WRITE.
      enum class Direction : uint8_t { Read, Write };
      // Adds `fd` to the event queue with read armed (per FdCallbacks defaults) and write disarmed.
      [[nodiscard]] bool AddEvents(int fd) noexcept;
      // Removes `fd` from the event queue entirely (both directions).
      [[nodiscard]] bool RemoveEvents(int fd) noexcept;
      // Arms/disarms one direction's kernel interest on an already-added fd (epoll MOD; kqueue
      // ENABLE/DISABLE). The current armed state of both directions is read from `callbacks_`.
      [[nodiscard]] bool SetEventInterest(int fd, Direction direction, bool enabled) noexcept;
      bool Unregister(int fd) noexcept override;
  ```

  Replace the callbacks comment + member:

  ```cpp
      // fd -> callback. The kernel reports the ready fd (kqueue ident / epoll data.fd) and we
      // look the callback up here rather than stashing a pointer in the event's user-data: a
      // stale event for an already-unregistered fd then fails the lookup safely instead of
      // dereferencing freed state — which a batched read could otherwise deliver.
      std::unordered_map<int, OnReadableCallback> callbacks_;
  ```

  with:

  ```cpp
      // Read and write callbacks for one watched fd plus each direction's armed state. Read interest
      // starts armed (every existing consumer registers readability and is unaffected); write
      // interest starts disarmed (armed on demand for connect-completion / send-buffer flush). The
      // armed flags mirror the kernel state so SetEventInterest can rebuild the epoll mask / know
      // which kqueue filter to toggle, and so PollOnce can ignore a direction that was disarmed
      // between the kernel report and the dispatch.
      struct FdCallbacks {
          OnReadableCallback read;
          bool read_armed = true;
          OnWritableCallback write;
          bool write_armed = false;
      };
      // fd -> callbacks. The kernel reports the ready fd (kqueue ident / epoll data.fd) and we
      // look the entry up here rather than stashing a pointer in the event's user-data: a
      // stale event for an already-unregistered fd then fails the lookup safely instead of
      // dereferencing freed state — which a batched read could otherwise deliver.
      std::unordered_map<int, FdCallbacks> callbacks_;
  ```

- [ ] **Step 4: Implement the new methods in `src/reflector/event_loop_dispatcher.cpp`.** Replace `Register`, `AddReadEvent`, `RemoveReadEvent`, and the `PollOnce` dispatch tail; add `SetWriteInterest`/`SetReadInterest`/`SetEventInterest`. `Unregister` keeps its shape but calls `RemoveEvents`.

  Replace `Register` (lines 73-90):

  ```cpp
  Dispatcher::Registration EventLoopDispatcher::Register(int fd, const OnReadableCallback& on_readable) {
      if (fd < 0) {
          GetLogger().Error("Cannot register fd callback: fd is invalid");
          return {};
      }
      if (callbacks_.contains(fd)) {
          GetLogger().Error("Cannot register fd callback: a callback for fd {} is already registered", fd);
          return {};
      }
      if (!AddReadEvent(fd)) {
          GetLogger().Error("Cannot register fd callback: read event registration failed for fd {}", fd);
          return {};
      }

      callbacks_.emplace(fd, on_readable);
      GetLogger().Debug("Registered fd callback for fd {}", fd);
      return MakeRegistration(fd);
  }
  ```

  with:

  ```cpp
  Dispatcher::Registration EventLoopDispatcher::Register(
      int fd, const OnReadableCallback& on_readable, const OnWritableCallback& on_writable) {
      if (fd < 0) {
          GetLogger().Error("Cannot register fd callback: fd is invalid");
          return {};
      }
      if (callbacks_.contains(fd)) {
          GetLogger().Error("Cannot register fd callback: a callback for fd {} is already registered", fd);
          return {};
      }
      // Insert first so AddEvents reads the armed defaults (read armed, write disarmed) from the entry.
      callbacks_.emplace(fd, FdCallbacks{.read = on_readable, .write = on_writable});
      if (!AddEvents(fd)) {
          callbacks_.erase(fd);
          GetLogger().Error("Cannot register fd callback: event registration failed for fd {}", fd);
          return {};
      }

      GetLogger().Debug("Registered fd callback for fd {}", fd);
      return MakeRegistration(fd);
  }

  bool EventLoopDispatcher::SetWriteInterest(int fd, bool enabled) noexcept {
      const auto it = callbacks_.find(fd);
      if (it == callbacks_.end()) {
          GetLogger().Warning("Cannot set write interest for fd {}: not registered", fd);
          return false;
      }
      if (it->second.write_armed == enabled) {
          return true;  // idempotent
      }
      if (!SetEventInterest(fd, Direction::Write, enabled)) {
          return false;
      }
      it->second.write_armed = enabled;
      return true;
  }

  bool EventLoopDispatcher::SetReadInterest(int fd, bool enabled) noexcept {
      const auto it = callbacks_.find(fd);
      if (it == callbacks_.end()) {
          GetLogger().Warning("Cannot set read interest for fd {}: not registered", fd);
          return false;
      }
      if (it->second.read_armed == enabled) {
          return true;  // idempotent
      }
      if (!SetEventInterest(fd, Direction::Read, enabled)) {
          return false;
      }
      it->second.read_armed = enabled;
      return true;
  }
  ```

  Replace `Unregister`'s `RemoveReadEvent` call. In `Unregister` (lines 92-106), change the body so it removes both directions:

  ```cpp
  bool EventLoopDispatcher::Unregister(int fd) noexcept {
      const auto it = callbacks_.find(fd);
      if (it == callbacks_.end()) {
          GetLogger().Warning("Cannot unregister fd callback for fd {}: not found", fd);
          return false;
      }

      callbacks_.erase(it);
      if (!RemoveEvents(fd)) {
          GetLogger().Error("Cannot remove events for fd {} after unregistering its callback", fd);
      }

      GetLogger().Debug("Unregistered fd callback for fd {}", fd);
      return true;
  }
  ```

  Replace the `PollOnce` dispatch tail (lines 173-182) so it routes by direction. The platform blocks above already compute `fd`; on Linux we also have `events`. To know whether the event is read- or write-ready uniformly, read the per-platform filter into a small pair of booleans right after the per-platform `fd` is established. Replace from the `const auto it = callbacks_.find(fd);` line through `return true;`:

  ```cpp
      const auto it = callbacks_.find(fd);
      if (it == callbacks_.end()) {
          GetLogger().Warning("Dispatcher woke for unwatched fd {}", fd);
          return false;
      }

  #if defined(__APPLE__)
      const bool readable = event.filter == EVFILT_READ;
      const bool writable = event.filter == EVFILT_WRITE;
  #elif defined(__linux__)
      // EPOLLHUP/EPOLLERR can arrive without EPOLLIN/EPOLLOUT; surface them on whichever direction is
      // armed so a half-closed or failed connect still wakes its handler (e.g. connect failure shows
      // as writable with SO_ERROR set). The error-without-EPOLLIN early-out above already handled the
      // read-only error case, so here we route a HUP/ERR to the write handler when write is armed.
      const bool readable = (events & EPOLLIN) != 0;
      const bool writable = (events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) != 0;
  #endif

      // Copy the callbacks before invoking: a callback may unregister this fd (erasing the map entry)
      // or toggle the other direction's interest, which would otherwise dangle the references we call
      // through. Re-check the armed flags from the live entry: a direction disarmed between the kernel
      // report and now (e.g. read disarmed for backpressure in the same cycle) must not be dispatched.
      const auto entry = it->second;
      if (readable && entry.read_armed && entry.read.IsValid()) {
          entry.read(fd);
      }
      if (writable && entry.write_armed && entry.write.IsValid()) {
          entry.write(fd);
      }
      return true;
  ```

  Replace `AddReadEvent` (lines 252-281) and `RemoveReadEvent` (lines 283-305) with `AddEvents`, `RemoveEvents`, and `SetEventInterest`. On kqueue, write interest is a second filter we add EV_DISABLE'd up front and toggle with EV_ENABLE/EV_DISABLE; on epoll, the mask is rebuilt from the armed flags and applied with `EPOLL_CTL_MOD`:

  ```cpp
  bool EventLoopDispatcher::AddEvents(int fd) noexcept {
      if (event_fd_ < 0) {
          GetLogger().Error("Cannot add events for fd {}: event queue is invalid", fd);
          return false;
      }

  #if defined(__APPLE__)
      // Two filters: read armed, write disabled. Each is its own kqueue change; a level-triggered
      // EVFILT_WRITE left enabled on an idle-writable socket would spin, so it starts EV_DISABLE'd.
      struct kevent changes[2];
      EV_SET(&changes[0], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
      EV_SET(&changes[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, nullptr);
      if (kevent(event_fd_, changes, 2, nullptr, 0, nullptr) != 0) {
          GetLogger().Error("Cannot add events for fd {}: {}", fd, Error::FromErrno());
          return false;
      }
  #elif defined(__linux__)
      // One epoll entry; read armed, write off. SetEventInterest rebuilds this mask on a MOD.
      epoll_event event{};
      event.events = EPOLLIN;
      event.data.fd = fd;
      if (epoll_ctl(event_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
          if (errno == EEXIST) {
              GetLogger().Debug("Event already registered for fd {}", fd);
              return true;
          }
          GetLogger().Error("Cannot add events for fd {}: {}", fd, Error::FromErrno());
          return false;
      }
  #endif

      GetLogger().Debug("Registered events for fd {}", fd);
      return true;
  }

  bool EventLoopDispatcher::RemoveEvents(int fd) noexcept {
      if (event_fd_ < 0) {
          GetLogger().Error("Cannot remove events for fd {}: event queue is invalid", fd);
          return false;
      }

  #if defined(__APPLE__)
      // Deleting a filter that was never added returns ENOENT; the write filter is always added (if
      // disabled) by AddEvents, so both deletes are valid. Issue them together.
      struct kevent changes[2];
      EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
      EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
      if (kevent(event_fd_, changes, 2, nullptr, 0, nullptr) != 0) {
          GetLogger().Error("Cannot remove events for fd {}: {}", fd, Error::FromErrno());
          return false;
      }
  #elif defined(__linux__)
      if (epoll_ctl(event_fd_, EPOLL_CTL_DEL, fd, nullptr) != 0) {
          GetLogger().Error("Cannot remove events for fd {}: {}", fd, Error::FromErrno());
          return false;
      }
  #endif

      GetLogger().Debug("Removed events for fd {}", fd);
      return true;
  }

  bool EventLoopDispatcher::SetEventInterest(int fd, Direction direction, bool enabled) noexcept {
      if (event_fd_ < 0) {
          GetLogger().Error("Cannot set event interest for fd {}: event queue is invalid", fd);
          return false;
      }

  #if defined(__APPLE__)
      // kqueue toggles a single filter in place: EV_ENABLE/EV_DISABLE, no need to know the other
      // direction's state. EV_ADD is harmless (the filter already exists) and keeps the change valid
      // even if the toggle races the initial add.
      struct kevent change{};
      const int16_t filter = direction == Direction::Read ? EVFILT_READ : EVFILT_WRITE;
      const uint16_t flags = EV_ADD | (enabled ? EV_ENABLE : EV_DISABLE);
      EV_SET(&change, fd, filter, flags, 0, 0, nullptr);
      if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
          GetLogger().Error("Cannot set {} interest for fd {}: {}",
              direction == Direction::Read ? "read" : "write", fd, Error::FromErrno());
          return false;
      }
  #elif defined(__linux__)
      // epoll has no per-filter enable: rebuild the whole mask from the armed flags. The caller
      // (SetReadInterest/SetWriteInterest) has not yet written the new state, so fold `enabled` for
      // `direction` in here. The other direction's current state is read from callbacks_.
      const auto it = callbacks_.find(fd);
      if (it == callbacks_.end()) {
          return false;
      }
      const bool read_on = direction == Direction::Read ? enabled : it->second.read_armed;
      const bool write_on = direction == Direction::Write ? enabled : it->second.write_armed;
      epoll_event event{};
      event.events = (read_on ? EPOLLIN : 0u) | (write_on ? EPOLLOUT : 0u);
      event.data.fd = fd;
      if (epoll_ctl(event_fd_, EPOLL_CTL_MOD, fd, &event) != 0) {
          GetLogger().Error("Cannot set {} interest for fd {}: {}",
              direction == Direction::Read ? "read" : "write", fd, Error::FromErrno());
          return false;
      }
  #endif

      GetLogger().Debug("Set {} interest for fd {} to {}",
          direction == Direction::Read ? "read" : "write", fd, enabled);
      return true;
  }
  ```

  Note the macOS `EV_SET` flag types: `EVFILT_READ`/`EVFILT_WRITE` are `int16_t` filter constants and the flag word is `uint16_t`, matching the `kevent` struct fields — so the local `filter`/`flags` temporaries above are correctly typed for `EV_SET`.

- [ ] **Step 5: Build and run the dispatcher tests — expect PASS.**

  ```sh
  cmake --build build
  ctest --test-dir build -R 'EventLoopDispatcher' --output-on-failure
  ```

  Expected: all `EventLoopDispatcherTest` cases pass, including the seven new ones and every pre-existing readability/timer test (unchanged behavior). If `grep REFLECTOR_SANITIZE build/CMakeCache.txt` does not show `ON`, re-run `./cmake_gen.sh` before trusting the result.

### Task 1.3: `FakeDispatcher` — `FireWritable`, read/write interest toggles, `IsReadArmed`/`IsWriteArmed`, read-disarmed `FireReadable` no-op

**Files**
- Modify: `tests/mocks/fake_dispatcher.h`
- Create: `tests/fake_dispatcher_test.cpp`
- Modify: `tests/CMakeLists.txt`

The fake must model the same kernel semantics the proxy's tests rely on: read interest starts armed, write disarmed; `FireReadable` is suppressed while read-disarmed (the kernel would not deliver the event); `FireWritable` fires the write callback; and `IsReadArmed`/`IsWriteArmed` expose the toggles so the backpressure test (Commit 4) can assert `IsReadArmed(source)==false` / `IsWriteArmed(peer)==true` at high-water and the reverse after draining.

- [ ] **Step 1: Write the failing test file `tests/fake_dispatcher_test.cpp`.** It exercises the fake in isolation — no real sockets, arbitrary positive fd ints — asserting the contract the proxy will lean on.

  ```cpp
  #include "mocks/fake_dispatcher.h"

  #include "reflector/util/delegate.h"

  #include <gtest/gtest.h>

  namespace reflector {
  namespace {

  struct CallbackRecorder {
      void OnReadable(int fd) {
          ++read_count;
          last_read_fd = fd;
      }
      void OnWritable(int fd) {
          ++write_count;
          last_write_fd = fd;
      }
      int read_count = 0;
      int write_count = 0;
      int last_read_fd = -1;
      int last_write_fd = -1;
  };

  TEST(FakeDispatcherTest, RegisterStartsReadArmedAndWriteDisarmed) {
      FakeDispatcher dispatcher;
      CallbackRecorder recorder;
      const int fd = 7;

      const auto registration = dispatcher.Register(
          fd,
          CreateDelegate<&CallbackRecorder::OnReadable>(&recorder),
          CreateDelegate<&CallbackRecorder::OnWritable>(&recorder));
      ASSERT_TRUE(registration.IsValid());

      EXPECT_TRUE(dispatcher.IsReadArmed(fd));
      EXPECT_FALSE(dispatcher.IsWriteArmed(fd));
  }

  TEST(FakeDispatcherTest, TwoArgRegisterStillStartsReadArmed) {
      FakeDispatcher dispatcher;
      CallbackRecorder recorder;
      const int fd = 3;

      const auto registration =
          dispatcher.Register(fd, CreateDelegate<&CallbackRecorder::OnReadable>(&recorder));
      ASSERT_TRUE(registration.IsValid());

      EXPECT_TRUE(dispatcher.IsReadArmed(fd));
      EXPECT_FALSE(dispatcher.IsWriteArmed(fd));

      dispatcher.FireReadable(fd);
      EXPECT_EQ(recorder.read_count, 1);
      EXPECT_EQ(recorder.last_read_fd, fd);
  }

  TEST(FakeDispatcherTest, FireWritableInvokesTheWriteCallback) {
      FakeDispatcher dispatcher;
      CallbackRecorder recorder;
      const int fd = 11;

      const auto registration = dispatcher.Register(
          fd,
          CreateDelegate<&CallbackRecorder::OnReadable>(&recorder),
          CreateDelegate<&CallbackRecorder::OnWritable>(&recorder));
      ASSERT_TRUE(registration.IsValid());

      dispatcher.FireWritable(fd);
      EXPECT_EQ(recorder.write_count, 1);
      EXPECT_EQ(recorder.last_write_fd, fd);
      EXPECT_EQ(recorder.read_count, 0);
  }

  TEST(FakeDispatcherTest, FireReadableIsSuppressedWhileReadDisarmed) {
      FakeDispatcher dispatcher;
      CallbackRecorder recorder;
      const int fd = 5;

      const auto registration = dispatcher.Register(
          fd,
          CreateDelegate<&CallbackRecorder::OnReadable>(&recorder),
          CreateDelegate<&CallbackRecorder::OnWritable>(&recorder));
      ASSERT_TRUE(registration.IsValid());

      // Disarm read: the fake models the kernel no longer delivering readable events, so FireReadable
      // is a no-op (this is what stops the proxy's backpressure test from busy-spinning).
      EXPECT_TRUE(dispatcher.SetReadInterest(fd, false));
      EXPECT_FALSE(dispatcher.IsReadArmed(fd));
      dispatcher.FireReadable(fd);
      EXPECT_EQ(recorder.read_count, 0);

      // Re-arm: FireReadable delivers again.
      EXPECT_TRUE(dispatcher.SetReadInterest(fd, true));
      EXPECT_TRUE(dispatcher.IsReadArmed(fd));
      dispatcher.FireReadable(fd);
      EXPECT_EQ(recorder.read_count, 1);
  }

  TEST(FakeDispatcherTest, SetWriteInterestTogglesIsWriteArmed) {
      FakeDispatcher dispatcher;
      CallbackRecorder recorder;
      const int fd = 9;

      const auto registration = dispatcher.Register(
          fd,
          CreateDelegate<&CallbackRecorder::OnReadable>(&recorder),
          CreateDelegate<&CallbackRecorder::OnWritable>(&recorder));
      ASSERT_TRUE(registration.IsValid());

      EXPECT_FALSE(dispatcher.IsWriteArmed(fd));
      EXPECT_TRUE(dispatcher.SetWriteInterest(fd, true));
      EXPECT_TRUE(dispatcher.IsWriteArmed(fd));
      EXPECT_TRUE(dispatcher.SetWriteInterest(fd, true));  // idempotent
      EXPECT_TRUE(dispatcher.IsWriteArmed(fd));
      EXPECT_TRUE(dispatcher.SetWriteInterest(fd, false));
      EXPECT_FALSE(dispatcher.IsWriteArmed(fd));
  }

  TEST(FakeDispatcherTest, InterestTogglesRejectUnwatchedFd) {
      FakeDispatcher dispatcher;

      EXPECT_FALSE(dispatcher.SetWriteInterest(42, true));
      EXPECT_FALSE(dispatcher.SetReadInterest(42, true));
      EXPECT_FALSE(dispatcher.IsReadArmed(42));
      EXPECT_FALSE(dispatcher.IsWriteArmed(42));
  }

  } // namespace
  } // namespace reflector
  ```

- [ ] **Step 2: Add the new file to `tests/CMakeLists.txt`.** Insert it into the `reflector_test` source list (alphabetical neighborhood, after `event_loop_dispatcher_test.cpp`):

  ```cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/event_loop_dispatcher_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/fake_dispatcher_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/timer_test.cpp
  ```

- [ ] **Step 3: Run — expect a COMPILE failure (the fake lacks the new API).** `FakeDispatcher` still has the 2-arg `Register` override and no `FireWritable`/`SetWriteInterest`/`SetReadInterest`/`IsReadArmed`/`IsWriteArmed`, and because the base `Register` is now a 3-arg pure virtual, the fake is abstract:

  ```sh
  cmake --build build 2>&1 | tail -30
  ```

  Expected: errors like `cannot declare variable 'dispatcher' to be of abstract type 'reflector::FakeDispatcher'` and `'class reflector::FakeDispatcher' has no member named 'FireWritable'`.

- [ ] **Step 4: Implement the new API in `tests/mocks/fake_dispatcher.h`.** Switch the callbacks map to an `FdCallbacks` value (mirroring production), make `Register` 3-arg, gate `FireReadable` on `read_armed`, and add `FireWritable`, the two interest toggles, and the two armed-state queries.

  Replace the existing 2-arg `Register` override and the `FireReadable` method:

  ```cpp
      [[nodiscard]] Dispatcher::Registration Register(int fd, const OnReadableCallback& on_readable) override {
          if (fd < 0 || callbacks_.contains(fd)) {
              return {};
          }
          callbacks_.emplace(fd, on_readable);
          return MakeRegistration(fd);
      }
  ```

  with the 3-arg override:

  ```cpp
      [[nodiscard]] Dispatcher::Registration Register(
          int fd, const OnReadableCallback& on_readable, const OnWritableCallback& on_writable) override {
          if (fd < 0 || callbacks_.contains(fd)) {
              return {};
          }
          callbacks_.emplace(fd, FdCallbacks{.read = on_readable, .write = on_writable});
          return MakeRegistration(fd);
      }

      // Read interest starts armed, write disarmed — mirroring production. Toggles update the armed
      // flags; false on an unwatched fd. SetReadInterest's disarm is what makes FireReadable a no-op,
      // modelling the level-triggered kernel ceasing delivery (so a paused source can't busy-spin).
      [[nodiscard]] bool SetReadInterest(int fd, bool enabled) noexcept {
          const auto it = callbacks_.find(fd);
          if (it == callbacks_.end()) {
              return false;
          }
          it->second.read_armed = enabled;
          return true;
      }
      [[nodiscard]] bool SetWriteInterest(int fd, bool enabled) noexcept {
          const auto it = callbacks_.find(fd);
          if (it == callbacks_.end()) {
              return false;
          }
          it->second.write_armed = enabled;
          return true;
      }

      [[nodiscard]] bool IsReadArmed(int fd) const noexcept {
          const auto it = callbacks_.find(fd);
          return it != callbacks_.end() && it->second.read_armed;
      }
      [[nodiscard]] bool IsWriteArmed(int fd) const noexcept {
          const auto it = callbacks_.find(fd);
          return it != callbacks_.end() && it->second.write_armed;
      }
  ```

  Replace the `FireReadable` method:

  ```cpp
      // Invokes the callback registered for `fd`, as the reactor would when `fd` becomes readable.
      void FireReadable(int fd) {
          const auto it = callbacks_.find(fd);
          if (it != callbacks_.end()) {
              it->second(fd);
          }
      }
  ```

  with read-armed-gated read and a writable analog:

  ```cpp
      // Invokes the read callback for `fd`, as the reactor would when `fd` becomes readable — but
      // ONLY while read interest is armed. A disarmed fd is one the kernel has stopped delivering
      // readable events for (SetReadInterest(false)); firing it anyway would model a busy-spin the
      // production reactor specifically avoids, so it is a no-op here too. Copies the callback before
      // invoking (it may unregister the fd or toggle interest), matching production discipline.
      void FireReadable(int fd) {
          const auto it = callbacks_.find(fd);
          if (it == callbacks_.end() || !it->second.read_armed) {
              return;
          }
          const auto read = it->second.read;
          if (read.IsValid()) {
              read(fd);
          }
      }

      // Invokes the write callback for `fd`, as the reactor would when `fd` becomes writable. Unlike
      // FireReadable, write delivery is not gated on write_armed: a test fires this to model a
      // connect completing or a send buffer draining; whether write interest was armed is the proxy's
      // concern, asserted separately via IsWriteArmed.
      void FireWritable(int fd) {
          const auto it = callbacks_.find(fd);
          if (it == callbacks_.end()) {
              return;
          }
          const auto write = it->second.write;
          if (write.IsValid()) {
              write(fd);
          }
      }
  ```

  Add the `FdCallbacks` struct and switch the member. Replace the callbacks member declaration:

  ```cpp
      std::unordered_map<int, OnReadableCallback> callbacks_;
  ```

  with:

  ```cpp
      // Mirrors EventLoopDispatcher::FdCallbacks: read armed by default, write disarmed.
      struct FdCallbacks {
          OnReadableCallback read;
          bool read_armed = true;
          OnWritableCallback write;
          bool write_armed = false;
      };
      std::unordered_map<int, FdCallbacks> callbacks_;
  ```

  The `Unregister` override (`callbacks_.erase(fd) > 0`) and `IsWatching`/`RegistrationCount` are unchanged — they only key on the fd.

- [ ] **Step 5: Build and run the fake's tests — expect PASS, and confirm the existing readability consumers of the fake still build.** The fake is used by `ssdp_reflector_test`, `mdns_reflector_test`, `default_packet_dispatcher_test`, and others through the 2-arg convenience, which still resolves:

  ```sh
  cmake --build build
  ctest --test-dir build -R 'FakeDispatcher' --output-on-failure
  ctest --test-dir build -L unit --output-on-failure
  ```

  Expected: the seven `FakeDispatcherTest` cases pass, the extended `EventLoopDispatcherTest` cases pass, and the full unit suite is green (every existing fake consumer compiles via the 2-arg `Register` and is otherwise unaffected because read interest still starts armed).

- [ ] **Step 6: Commit.**

  ```sh
  git add src/reflector/dispatcher.h \
          src/reflector/event_loop_dispatcher.h \
          src/reflector/event_loop_dispatcher.cpp \
          tests/event_loop_dispatcher_test.cpp \
          tests/mocks/fake_dispatcher.h \
          tests/fake_dispatcher_test.cpp \
          tests/CMakeLists.txt
  git commit -m "dispatcher: add read/write interest control"
  ```

## Commit 2: tcp_socket — non-blocking TCP RAII over a real fd, plus the IpEndpoint value type

This commit adds the two shared building blocks the DIAL proxy needs at the socket layer:
`IpEndpoint` (an `IpAddress` + a port, used verbatim by Commits 3/4/5) and `TcpSocket`, a
move-only RAII owner over a non-blocking, SIGPIPE-safe TCP fd (listen / accept / connect-bound-
and-egress-pinned / read / write). All `TcpSocket` tests run against real loopback (`127.0.0.1`) so
accept/connect/partial-write/EAGAIN/peer-close exercise the kernel, not a mock. Only the
egress-pinned `Connect` (`SO_BINDTODEVICE` / `IP_BOUND_IF`) needs privilege, so that one case sits
behind a `RequiresRoot` fixture that `GTEST_SKIP`s when unprivileged; everything else is green on a
plain `ctest`.

> **As built (Commit 2 = `d08290c`).** Shipped after Commit 1 with the API refined during review and the `TcpSocket`↔dispatcher boundary settled as **B2** (design spec §4.2/§4.4, decision §11 D12). The authoritative API is the **interface-contract block above** plus the committed code; the original per-task TDD steps are dropped now that the code is the source of truth (they remain in this file's history at `1f99d74`). Key decisions:
> 1. **`IpEndpoint` owns the family-aware sockaddr conversion** — `ToSockaddr(sockaddr_storage&, unsigned scope_id = 0) → socklen_t` and `static FromSockaddr(const sockaddr*) → optional<IpEndpoint>` (reusing `IpAddress::FromSockaddr`). Keeps `TcpSocket` family-agnostic; v4/v6 are mostly parameterized tests.
> 2. **`TcpSocket` is move-only and DISPATCHER-INERT** — it holds only `{fd, SendBuffer, connecting}`, captures nothing of the dispatcher, holds NO `Registration`. The `Registration` + write-interest live in the *owner* (the `Connection`/`Endpoint`, Commit 4), the stable callback target (a self-registering `TcpSocket` would dangle its write `Delegate` on move; `Accept()` returns by value, `Connection` stores two by value).
> 3. **`TcpSocket` API** — factories return `optional<TcpSocket>`: `Listen(IpEndpoint)`, `Accept()`, `Connect(IpEndpoint dst, IpEndpoint bind, unsigned ifindex = 0)`. `Read` and the internal `WriteSome` share `IoResult{status, bytes}`. `Send → SendStatus` writes what it can + buffers the tail in the **bounded `SendBuffer` (move-only, self-safe; fixed `MAX_SEND_BUFFER` = 64 KB)**, `Flush()` drains it. `WantsWrite()` (`connecting || \!buffer.empty()`); `IsConnecting()`/`FinishConnect()` (no-op `Ok` once established, `Error` on a failed connect); `Fd()`/`IsValid()`/`LocalEndpoint()`/`PeerEndpoint()`. `Send` does NOT toggle write interest — the owner forwards `WantsWrite()` via one `Sync()` helper (Commit 4).

**Files**
- `src/reflector/ip_endpoint.h` — the `IpEndpoint` value type (`operator<=>`, `std::hash`, `std::formatter`, family-aware `ToSockaddr`/`FromSockaddr`).
- `src/reflector/util/send_buffer.h` — `SendBuffer`, a lazy bounded FIFO byte buffer; move-only with self-safe move ops.
- `src/reflector/tcp_socket.{h,cpp}` — the move-only, dispatcher-inert `TcpSocket`.
- `src/reflector/CMakeLists.txt` (+`tcp_socket.cpp`); `tests/CMakeLists.txt` (+ the three test files).

**Tests** (real loopback; value-parameterized over IPv4 + IPv6 unless noted)
- `tests/ip_endpoint_test.cpp` — equality, formatter, v4/v6 `ToSockaddr`/`FromSockaddr` round-trip, hash key.
- `tests/send_buffer_test.cpp` — empty state; append/view/consume; FIFO order; partial and overshoot consume; reclaim-before-grow; zero-length ops; interleaving; and **move + self-move** (the move pair caught a real move-corruption bug — a moved-from offset left `Size()` underflowing — fixed here with explicit move ops + a `this != &other` guard).
- `tests/tcp_socket_test.cpp` — Listen + ephemeral port; the connect→`FinishConnect` lifecycle; `Accept`→nullopt on no pending client; byte forwarding; `Read` WouldBlock / Closed (FIN) / Error (RST); `Send` buffers the tail + `Flush` drains it in order; `Send` overflow → drop; move ctor/assignment + self-move; `PeerEndpoint`. The egress-pinned `Connect` (`SO_BINDTODEVICE` / `IP_BOUND_IF`) is behind a `RequiresRoot` fixture.

Full gate green: native (ASan/UBSan), docker debug + release 533/533, e2e 25/25.

## Commit 3: http_message — incremental HTTP/1.1 framing and authority rewrite

> **As built.** Implemented test-first; the original per-task TDD steps are dropped now that the code is the source of truth (they remain in this file's history at `1f99d74`). The final shape — refined during review — is the **interface-contract block above** plus the committed code.

`src/reflector/http_message.{h,cpp}` is the pure (no-socket, no-reactor) HTTP layer, depending only on `reflector::IpEndpoint` (Commit 2) and `util/ascii.h`. Two pieces:

1. **`RewriteAuthority(text, from, to)`** — a one-shot authority substitution (`addr:port`, formatted via `std::formatter<IpEndpoint>`) over a string, leaving non-matching text untouched. Public because the SSDP `LOCATION` path (Commit 5) shares it; `HttpFraming` splices inline instead.
2. **`HttpFraming`** — incremental HTTP/1.1 framing + authority-header rewrite, copying **only the header**:
   - `std::optional<Output> Feed(std::string_view input)` (`Output { string_view header; string_view body; size_t consumed; }`) reports what to forward and how much input it consumed. `header` is the rewritten header block (a view into HttpFraming's own scratch), empty while a body streams; `body` is a **zero-copy slice of `input`**. The owner reads into its receive `StreamBuffer`, feeds a `View`, forwards `header` and `body` together in one `sendmsg` (the scatter-gather `Send`), and drops `consumed` bytes. `nullopt` = malformed / over-cap -> the owner closes; `consumed == 0` = nothing forwardable yet (an incomplete header). One message per feed — the owner loops `Feed` until `consumed == 0`.
   - One pass over a completed header detects framing (`Content-Length` / chunked / bodyless) **and** rewrites the target headers (Request: `Host`; Response: `Application-URL`, `Location`), splicing the replacement directly at the parsed authority offset (no second search) in the scratch copy.
   - The header scratch is the only buffer the framer holds, capped at the fixed `MAX_HEADER_BYTES` (2 KB constant); a header — or a chunk-size line at the separate `MAX_CHUNK_LINE_BYTES` (256 B) cap — reaching its cap unterminated is refused. The body, and any incomplete header/chunk-size line, stay in the owner's buffer — the framer keeps no carry buffer of its own. Bodies (including chunked chunk-data) stream verbatim; the chunked close must be a bare CRLF, so chunked trailers are refused.

**Files:** `src/reflector/http_message.{h,cpp}`, `tests/http_message_test.cpp`, `src/reflector/CMakeLists.txt` (+`http_message.cpp`), `tests/CMakeLists.txt` (+test). The `EndpointRewrite` callback is a `Delegate` (codebase convention).

**Tests** (`tests/http_message_test.cpp`): `RewriteAuthority` (swap / every-occurrence / non-matching); `HttpFraming` over the captured LG-TV messages — Content-Length response with `Application-URL` rewrite (+ case-insensitive name, split-feed reassembly, a continuing body feed that carries no header), chunked response with `LOCATION` rewrite (+ split chunk boundaries), bodyless `Host`-rewrite request, over-cap header refusal, a body larger than the header cap forwarding intact, two pipelined keep-alive messages, a message followed by a carried partial next header, an incomplete header consuming nothing, and the **two-view contract** itself (`header` is the rewritten copy while `body` points straight into the fed input). Also: chunked precedence over `Content-Length`; case-insensitive `chunked` in a coding list; chunk-extension drop (forwarded verbatim); multi-chunk and multi-rewrite messages each followed by a next message; non-target authorities left untouched (hostname, no explicit port, non-`http`, rewrite-declines); and refusals (malformed `Content-Length`, malformed or over-cap chunk-size line, chunked trailers).

Review also extracted the shared ASCII helpers into `util/ascii.h` (`AsciiToLower`, `StartsWithNoCase`), de-duplicating identical copies in `ssdp_message.cpp` and `config.cpp`, and caught a latent header-cap body-truncation bug (fixed, with a regression test).

## Commit 4: dial_proxy — the DialProxy orchestrator (drop-and-close backpressure)

Lands `src/reflector/dial_proxy.{h,cpp}`: the `Endpoint`/`Connection` state, the two listener caps + `MAX_CONNECTIONS` drop-new, the public `EnsureDiscoveryListener` + a private `EnsureListener` primitive, the non-blocking accept→connect→forward pump driven through `HttpFraming`, the connect/idle eviction `Timer`, and drop-and-close backpressure over each `TcpSocket`'s bounded send `StreamBuffer`. Depends on Commits 1–3 (reactor write-interest control + `FakeDispatcher`; `IpEndpoint`; `TcpSocket`; `HttpFraming`/`RewriteAuthority`/`EndpointRewrite`), all landed. `DialProxy` reaches the reactor through `PacketDispatcher::UnderlyingDispatcher()`, exactly as the SSDP eviction `Timer` does. Owned by `SsdpReflector` as `std::optional<DialProxy>`, gated by `config.dial`; SSDP-agnostic (the DIAL classification + LOCATION parse/splice live in the SSDP path, Commit 5).

**As-built decisions (settled by the design panels — these supersede the spec §4.4 narration where they differ):**

- **Cap hierarchy.** Each `Connection` holds two receive `StreamBuffer`s (`c2u_rx`, `u2c_rx`) capped at `MAX_RECV_BUFFER = 4 KB`. The one load-bearing invariant: `static_assert(MAX_RECV_BUFFER > HttpFraming::MAX_HEADER_BYTES)` — the framer's own over-cap refusal (`Feed → nullopt`) must fire before the receive buffer can fill, or the *always-armed* reader livelocks (full buffer → `ReserveTail` empty → `Feed` stuck at `consumed==0` → level-triggered spin with zero progress; the send-side drop-and-close never fires to break it). `TcpSocket::MAX_SEND_BUFFER` (8 KB) is an *independent* stalled-peer backstop, rarely allocated, **not** coupled to the receive cap (a single small DIAL message never fills it).
- **Node-stable callback targets.** `Endpoint` and `Connection` ARE the dispatcher callback targets (their methods are bound into the `Registration`s), so both are `NoMove` and live in **id-keyed `std::unordered_map`s — never `std::vector`** (a realloc dangles every bound `Delegate`). This is the `RawSocket` NoMove rule, NOT the `SsdpReflector::Session` pattern — `Session` is a `vector` element precisely because its capture binds to `SsdpReflector`, not the element (the opposite case).
- **Binds come from the `LinkSocket&`s.** `DialProxy` borrows the `source_if`/`target_if` `LinkSocket&`s (as the SSDP path does). A listener binds `{ source_if.SourceAddress(V4), 0 }` (ephemeral); the upstream connects `Connect(device, { target_if.SourceAddress(V4), 0 }, target_if.InterfaceIndex())`. DIAL is IPv4-only (§9). `SourceAddress()==nullopt` is treated as a listen/bind failure → `EnsureDiscoveryListener` returns `nullopt`.
- **The two rewrite delegates.** `HttpFraming` has no default ctor; each direction is built in the accept step with an `EndpointRewrite`. **c2u (request)** captures the `Connection`'s pinned upstream device endpoint: rewrite the reflector-listener authority in `Host` → the device. **u2c (response)** captures `DialProxy`: on a device `Application-URL`/`Location` authority it **find-or-creates the Rest-role `Endpoint`** (`EnsureListener` — re-entrant `Listen`+emplace+`Register` *inside* `Feed`, safe on the single-threaded path: no edge fires before the next `PollOnce`) and returns its reflector authority. **Close-don't-forward:** if the REST listener can't be minted (cap/bind fail) the connection is dropped — never forward the device's real, unroutable authority to the client (unlike the benign SSDP nullopt fallback, there is no router on the TCP path).
- **Forward loop + the Send/Consume barrier.** `Read` into this side's recv `StreamBuffer` tail (`ReserveTail`/`Commit`) → loop `Feed(View)`: per message a scatter-gather `Send({header, body})` — header and body together in one `sendmsg` (a header-less body continuation falls back to the single-span `Send`) — then `Consume(consumed)`, only after the `Send` returns, because `header` is a view into the framer scratch (reused next `Feed`) and `body` is a zero-copy slice of the recv buffer (invalidated by `Consume`/`Compact`). Loop until `Feed` returns `consumed==0` (incomplete header — stop, read more) or `nullopt` (malformed/over-cap — abort). Then `Sync(peer)`.
- **One write handler per fd; client-speaks-first.** A connection fd has exactly one write callback: on any writable edge call `FinishConnect()` (a no-op once established); on `Error` tear down; if it just went `Open`, **also `Flush()`** — the client is established at accept while the upstream is still `Connecting`, so the forward path already `Send`-buffered the request into the connecting upstream (its send buffer is non-empty at connect-completion). Read is always armed, so a readable-first completion is also handled by `FinishConnect()` at the top of the forward handler.
- **`Sync(socket)` is the only write toggle:** `disp_.SetWriteInterest(socket.Fd(), socket.WantsWrite())` (fd-keyed — no `Registration` arg). The `Connection` never computes a write bool; it forwards `TcpSocket::WantsWrite()`.
- **Teardown.** A teardown from *inside* a handler (peer EOF/error, `Send` `Overflow`, `Send`/`Flush` `Error`, `Feed` `nullopt`) is **deferred** — set `closed`, sweep after the dispatch pass (freeing the `Connection` whose handler is on the stack is the UAF this prevents); that handler returns without `Sync`. A timer-driven reap erases immediately (outside any handler). RAII drops the `Registration`s (declared last) before the `TcpSocket`s close.

**State** (`dial_proxy.h`):
```cpp
struct Endpoint : NoMove {       // discovered device ip:port + its reflector listener; the accept callback target
    enum class Role { Discovery, Rest };
    IpEndpoint device;
    Role role;
    TcpSocket listener;          // bound to source_if-addr:ephemeral
    std::chrono::steady_clock::time_point last_active;
    Dispatcher::Registration accept_reg;   // declared LAST: dropped first on erase
};
struct Connection : NoMove {     // one client<->device proxied pair; the I/O callback target
    TcpSocket client, upstream;
    HttpFraming c2u, u2c;        // per-direction framing + rewrite (built with the two delegates above)
    StreamBuffer c2u_rx{MAX_RECV_BUFFER}, u2c_rx{MAX_RECV_BUFFER};
    enum { Connecting, Open } phase;
    bool closed = false;
    std::chrono::steady_clock::time_point deadline;    // connect deadline, then idle deadline
    Dispatcher::Registration client_reg, upstream_reg; // declared LAST
};
```

**Public surface — one method** (SSDP-owned, no external callers):
```cpp
// Find-or-create a Discovery listener for a device's description endpoint; returns the reflector authority to
// advertise in the rewritten LOCATION (source_if-addr:listener-port). nullopt on cap/bind failure (LOCATION
// injected unchanged — discovery still works via the router). Refreshes last_active.
[[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(const IpEndpoint& device);
```
Both `EnsureDiscoveryListener` and the u2c `Application-URL`/`Location` rewrite funnel through a private `EnsureListener(const IpEndpoint& device, Role)` that find-or-creates the `Endpoint` (Listen + emplace + Register), enforces the role's cap, refreshes `last_active`, and returns the reflector authority (a device referenced as both roles is promoted to `Rest`). Every cap/timeout is a file-local `constexpr` (like `SsdpReflector::MAX_SESSIONS`): `MAX_CONNECTIONS = 64`, `MAX_REST_LISTENERS = 24`, `MAX_DISCOVERY_LISTENERS = 32`, `MAX_RECV_BUFFER`, the connect deadline, and the per-role idle graces. `dial = true` is the only DIAL config knob (§9) — nothing here is tunable.

Tests: `tests/dial_proxy_test.cpp`. Cap/reuse/drop-new/rewrite/eviction cases use loopback `Listen` + a `FakeDispatcher` and run unprivileged; the accept→egress-pinned-connect→forward cases use a real loopback pair behind a `*RequiresRoot*` fixture that `GTEST_SKIP`s without privilege.

### Task 4.1: skeleton + caps + `EnsureListener` (allocate/reuse, two caps, authority) — unprivileged
`dial_proxy.{h,cpp}` + CMake; the cap constants + `static_assert(MAX_RECV_BUFFER > HttpFraming::MAX_HEADER_BYTES)`; the `Endpoint` struct + `endpoints_` (id-keyed by `device`); `EnsureListener`/`EnsureDiscoveryListener`/`EnsureRestListener`. TDD: allocate→authority; reuse same device; distinct devices→distinct listeners; per-role caps; both-roles→Rest promotion; over-cap→nullopt + no listener; nullopt source address→nullopt.

### Task 4.2: accept → egress-pinned connect → the unified write handler — RequiresRoot
The accept handler (emplace→move client+`Connect`→`Register` both, set the connect deadline with the upstream `Connecting`; drop-new at `MAX_CONNECTIONS`; roll back a half-registered `Connection`). The per-socket writable handlers (`OnClientWritable` drains; `OnUpstreamWritable` `FinishConnect`s while connecting, then drains via the shared `Drain` — which flushes, refreshes the idle deadline, and `Sync`s; teardown on error). TDD: loopback accept; egress-pinned connect completes; the queued request flushes on connect-completion; connect failure tears down.

### Task 4.3: forward loop + drop-and-close + deferred teardown — RequiresRoot
The read handler (recv `StreamBuffer` → `Feed` loop → the scatter-gather `Send` (header+body in one sendmsg) + the Send/Consume barrier → `Sync`); the `consumed==0`/`nullopt` exits; drop-and-close on `Overflow`; the closed-flag deferral + post-dispatch sweep. TDD: a request/response body forwards verbatim across the pair; a slow peer past the send cap aborts; an in-handler abort defers (no UAF); a header in the 1.5–2 KB band forwards (no livelock).

### Task 4.4: the per-direction `EndpointRewrite` delegates + REST-listener side effect
c2u `Host` (reflector→device, captures the `Connection`'s upstream); u2c `Application-URL`/`Location` (device→reflector, captures `DialProxy`, find-or-create the Rest listener, close-don't-forward on failure). TDD: a description response's `Application-URL` mints a Rest endpoint + rewrites to its authority; a request `Host` rewrites reflector→device; the launch `201 Location` reuses the REST listener; a single-port device collapses both roles onto one listener; REST-cap exhaustion drops the connection (no dead authority forwarded).

### Task 4.5: eviction `Timer` (connect deadline, idle deadline, endpoint idle)
Lazy-start/self-stop `Timer` sweeping `Connection`s past their connect or idle deadline and unreferenced `Endpoint`s — tracked by a per-`Endpoint` `active_connections` refcount (ctor `++`, dtor `--`), not a connection scan — past the role grace (Rest > Discovery); each accept refreshes the endpoint `last_active`, each forwarded byte the connection idle deadline; timer-reap erases immediately. TDD: a Connecting pair past the connect deadline is reaped; an idle open pair reaped, an active one not; an unreferenced idle endpoint reaped after its role grace.

### Task 4.6: full gate + commit
`ctest -L unit`, `./docker_test.sh`, `./docker_test.sh release`, `python3 e2e/run.py` green. Commit `dial_proxy.{h,cpp}` + test + CMake. (The cap-constant hoist landed separately in f0a3505.)

## Commit 5: ssdp_reflector + config: add the `dial` flag, Verify rules, and the DIAL LOCATION rewrite

> **As-built note.** `dial = true` is the only DIAL config knob — the tunables this draft once proposed (`dial_max_*`/`dial_*_idle`/`dial_connect_timeout`/`dial_max_header_bytes`) were dropped; every cap/timeout is a file-local `constexpr` in `dial_proxy.h`/`http_message.h`. The task steps below that parse/Verify/test those fields are superseded — ignore them; the `dial` bool + two `Verify` rejections is the whole config surface.

This commit wires the (already-built, Commit 4) `DialProxy` into the SSDP path. It adds the `dial` bool to `SsdpConfig` (with two `Verify` rejections and the formatter), parses it from the `[name]` TOML table, adds two small SSDP-side DIAL helpers (service-type classification + LOCATION-authority parse, the latter reusing `ParseAuthority` for the endpoint + its byte span) to `ssdp_message.{h,cpp}`, and — in `SsdpReflector::RewriteDialLocation`, called inline from `OnTargetPacket` (NOTIFY) and `OnUnicastResponse` (200 OK) — splices a minted reflector authority over the `LOCATION`'s authority span before injection (unchanged on proxy-disabled / non-DIAL / no-LOCATION / cap-or-bind `nullopt`; a present-but-unparseable LOCATION is logged at INFO). It depends on the contract types `IpEndpoint` (Commit 2), `ParseAuthority` (Commit 3), and `DialProxy::EnsureDiscoveryListener` (Commit 4).

The full data-path gate (native unit + docker debug/release + e2e) runs before the final commit step (5.6).

### Task 5.1: `SsdpConfig` gains `dial` + tunables, two `Verify` rejections, and a formatter that prints `dial`

Files:
- Modify `src/reflector/config.h` (the `SsdpConfig` struct, lines 81-94; the `std::formatter<reflector::SsdpConfig>`, lines 211-235)
- Modify `src/reflector/config.cpp` (`SsdpConfig::Verify`, lines 328-342)
- Modify `tests/config_test.cpp` (append new tests)

- [ ] **Step 1: Write the failing struct-level Verify + formatter tests.** Append to `tests/config_test.cpp` (before the final `// --- SSDP dedup matrix ...` block is fine; put them at end of file). These assert on the `SsdpConfig` struct directly (no TOML), mirroring `AddressFamilyRuntimePolicy`/`VerifyRejectsPortZero`:

```cpp
// --- SSDP dial flag: struct-level Verify + formatter (independent of the TOML format) ---

TEST(ConfigTest, SsdpVerifyAcceptsDialWithSsdpDefaultFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv",
        .source_if = "lan",
        .target_if = "iot",
        .dial = true,
    };  // ssdp entries are SSDP by construction; default family has IPv4
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyAcceptsDialWithDualFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::Dual, .dial = true,
    };
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyAcceptsDialWithIpv4Family) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv4, .dial = true,
    };
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyRejectsDialWithIpv6OnlyFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv6, .dial = true,
    };  // DIAL is IPv4-only: an ipv6-only entry has no IPv4 address to bind
    const auto error = ssdp.Verify();
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->Message().find("dial"), std::string::npos) << error->Message();
}

TEST(ConfigTest, SsdpVerifyAcceptsDialFalseWithIpv6) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv6, .dial = false,
    };  // the ipv6 rejection is gated on dial being on
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpFormatterPrintsDial) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .source_if = "lan", .target_if = "iot", .dial = true,
    };
    const auto text = std::format("{}", ssdp);
    EXPECT_NE(text.find("dial: true"), std::string::npos) << text;
}

TEST(ConfigTest, SsdpFormatterPrintsDialFalseByDefault) {
    const auto ssdp = SsdpConfig{.name = "tv", .source_if = "lan", .target_if = "iot"};
    const auto text = std::format("{}", ssdp);
    EXPECT_NE(text.find("dial: false"), std::string::npos) << text;
}
```

- [ ] **Step 2: Run them and expect a COMPILE failure.** `SsdpConfig` has no `dial` member yet, so the designated initializer `.dial = true` and the formatter expectations don't compile.

```sh
./cmake_gen.sh
grep REFLECTOR_SANITIZE build/CMakeCache.txt   # confirm ON
cmake --build build
```

Expected: build error — `SsdpConfig` has no member named `dial`.

- [ ] **Step 3: Add the `dial` flag + tunables to `SsdpConfig` and a tunables aggregate.** In `src/reflector/config.h`, first add the standard-library include the tunables need (just under the existing includes, after line 14 `#include <utility>`):

```cpp
#include <chrono>
```

Then replace the `SsdpConfig` struct (lines 81-94) with:

```cpp
struct SsdpConfig {
    std::string name;
    std::optional<MacAddress> mac;
    std::string source_if;
    std::string target_if;
    AddressFamily address_family = AddressFamily::Default;

    // DIAL application proxy (opt-in, default off). Off unless `dial = true`; the tunables apply only
    // when it is on and otherwise carry these defaults (see the DIAL design doc §9). DIAL reuses this
    // entry's source_if/target_if/address_family/mac, so it has no fields of its own beyond these.
    bool dial = false;
    size_t dial_max_connections = 32;
    size_t dial_max_rest_listeners = 32;
    size_t dial_max_discovery_listeners = 32;
    std::chrono::seconds dial_rest_idle{3600};
    std::chrono::seconds dial_discovery_idle{90};
    std::chrono::seconds dial_connect_timeout{5};
    size_t dial_max_header_bytes = 65536;

    [[nodiscard]] constexpr bool UsesIPv4() const noexcept { return reflector::UsesIPv4(address_family); }
    [[nodiscard]] constexpr bool UsesIPv6() const noexcept { return reflector::UsesIPv6(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv4() const noexcept { return reflector::RequiresIPv4(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv6() const noexcept { return reflector::RequiresIPv6(address_family); }

    [[nodiscard]] std::optional<Error> Verify() const;
};
```

- [ ] **Step 4: Add the two `Verify` rejections.** In `src/reflector/config.cpp`, replace `SsdpConfig::Verify` (lines 328-342) — keep the existing four checks and add the two `dial` rules at the end:

```cpp
std::optional<Error> SsdpConfig::Verify() const {
    if (name.empty()) {
        return Error{"ssdp name is not configured"};
    }
    if (source_if.empty()) {
        return Error{"ssdp source_if is not configured"};
    }
    if (target_if.empty()) {
        return Error{"ssdp target_if is not configured"};
    }
    if (source_if == target_if) {
        return Error{"ssdp source_if and target_if must be different: \"{}\"", source_if};
    }
    // DIAL is IPv4-only (the spec's Application-URL host must be/resolve to IPv4); an ipv6-only entry
    // has no IPv4 address to bind a listener or the upstream connect to, so fail loudly rather than
    // silently doing nothing. (This SsdpConfig already exists only because ssdp is enabled, so the
    // "dial requires ssdp" rule is enforced at parse time — see ReadEntry.)
    if (dial && !UsesIPv4()) {
        return Error{"ssdp entry \"{}\" enables dial but is ipv6-only; DIAL is IPv4-only", name};
    }
    return std::nullopt;
}
```

(The "dial && !ssdp" rejection lives in `ReadEntry`, Task 5.2, since `SsdpConfig` only exists when `ssdp` is enabled — by the time we hold a `SsdpConfig`, ssdp is true. The `Verify`-level guard here covers the family rule, which `SsdpConfig` can check itself.)

- [ ] **Step 5: Print `dial` in the formatter.** In `src/reflector/config.h`, replace the `SsdpConfig` formatter's `format` body (lines 224-234) with one that appends `dial`:

```cpp
    template <typename FmtContext>
    FmtContext::iterator format(const reflector::SsdpConfig& c, FmtContext& ctx) const {
        std::format_to(ctx.out(), "{{name: \"{}\", mac: ", c.name);
        if (c.mac.has_value()) {
            std::format_to(ctx.out(), "\"{}\"", *c.mac);
        } else {
            std::format_to(ctx.out(), "any");
        }
        return std::format_to(ctx.out(), ", source_if: \"{}\", target_if: \"{}\", address_family: {}, dial: {}}}",
            c.source_if, c.target_if, c.address_family, c.dial);
    }
```

- [ ] **Step 6: Run the new tests and expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'ConfigTest.Ssdp(Verify|Formatter)' --output-on-failure
```

Expected: `SsdpVerifyAcceptsDialWithSsdpDefaultFamily`, `...DualFamily`, `...Ipv4Family`, `SsdpVerifyRejectsDialWithIpv6OnlyFamily`, `SsdpVerifyAcceptsDialFalseWithIpv6`, `SsdpFormatterPrintsDial`, `SsdpFormatterPrintsDialFalseByDefault` all PASS.

### Task 5.2: parse `dial` + tunables from the `[name]` TOML table

Files:
- Modify `src/reflector/config.cpp` (`ReadEntry`, lines 171-277)
- Modify `tests/config_test.cpp` (append new tests)

- [ ] **Step 1: Write the failing parse + parse-Verify tests.** Append to `tests/config_test.cpp`:

```cpp
// --- dial parsing from the [name] table ---

TEST(ConfigTest, ParsesDialFlagAndTunables) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
dial_max_connections = 8
dial_max_rest_listeners = 4
dial_max_discovery_listeners = 6
dial_rest_idle = 600
dial_discovery_idle = 30
dial_connect_timeout = 2
dial_max_header_bytes = 16384
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->SsdpConfigs().size(), 1u);
    const auto& ssdp = config->SsdpConfigs().front();
    EXPECT_TRUE(ssdp.dial);
    EXPECT_EQ(ssdp.dial_max_connections, 8u);
    EXPECT_EQ(ssdp.dial_max_rest_listeners, 4u);
    EXPECT_EQ(ssdp.dial_max_discovery_listeners, 6u);
    EXPECT_EQ(ssdp.dial_rest_idle, std::chrono::seconds{600});
    EXPECT_EQ(ssdp.dial_discovery_idle, std::chrono::seconds{30});
    EXPECT_EQ(ssdp.dial_connect_timeout, std::chrono::seconds{2});
    EXPECT_EQ(ssdp.dial_max_header_bytes, 16384u);
}

TEST(ConfigTest, DialDefaultsToFalseWhenAbsent) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    const auto& ssdp = config->SsdpConfigs().front();
    EXPECT_FALSE(ssdp.dial);
    EXPECT_EQ(ssdp.dial_max_connections, 32u);  // the documented defaults survive when unset
    EXPECT_EQ(ssdp.dial_rest_idle, std::chrono::seconds{3600});
    EXPECT_EQ(ssdp.dial_discovery_idle, std::chrono::seconds{90});
    EXPECT_EQ(ssdp.dial_connect_timeout, std::chrono::seconds{5});
    EXPECT_EQ(ssdp.dial_max_header_bytes, 65536u);
}

TEST(ConfigTest, DialOnlyNeedsTheFlag) {
    // The common case: just `dial = true`, every tunable defaulted.
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->SsdpConfigs().front().dial);
}

TEST(ConfigTest, RejectsDialWithoutSsdp) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
mdns = true
dial = true
)").has_value());  // DIAL requires SSDP discovery
}

TEST(ConfigTest, RejectsDialTunablesWithoutDial) {
    // A dial tunable set without dial enabled is a config mistake, like wol_ports without wol.
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial_max_connections = 8
)").has_value());
}

TEST(ConfigTest, RejectsDialIpv6Only) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
address_family = "ipv6"
)").has_value());  // SsdpConfig::Verify rejects dial + ipv6-only
}

TEST(ConfigTest, AcceptsDialDualFamily) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
address_family = "dual"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->SsdpConfigs().front().dial);
}

TEST(ConfigTest, RejectsNonBooleanDial) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = "yes"
)").has_value());
}

TEST(ConfigTest, RejectsNonIntegerDialTunable) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
dial_max_connections = "lots"
)").has_value());
}

TEST(ConfigTest, RejectsZeroDialConnections) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
dial_max_connections = 0
)").has_value());  // a zero cap would proxy nothing; reject it as a likely mistake
}
```

- [ ] **Step 2: Run them and expect FAIL.**

```sh
cmake --build build
ctest --test-dir build -R 'ConfigTest.(ParsesDial|DialDefaults|DialOnly|RejectsDial|AcceptsDialDual|RejectsNonBooleanDial|RejectsNonIntegerDialTunable|RejectsZeroDialConnections)' --output-on-failure
```

Expected: `ParsesDialFlagAndTunables`, `DialDefaultsToFalseWhenAbsent`, `DialOnlyNeedsTheFlag`, `AcceptsDialDualFamily` FAIL (unexpected key `dial`/`dial_*` → `Config::FromString` returns an error, so `has_value()` is false). `RejectsDialWithoutSsdp`, `RejectsDialTunablesWithoutDial`, `RejectsDialIpv6Only`, `RejectsNonBooleanDial`, `RejectsNonIntegerDialTunable`, `RejectsZeroDialConnections` happen to PASS already (they assert `false`, and the parser currently rejects the unknown key) — but they assert the wrong reason. After Step 3 they must still pass for the *right* reason; that is verified in Step 4.

- [ ] **Step 3: Parse `dial` + the tunables in `ReadEntry`.** In `src/reflector/config.cpp`, add a small seconds-reader helper in the anonymous namespace (after `ReadPorts`, around line 85):

```cpp
// Reads a positive-integer dial tunable (count or seconds) from a TOML node; rejects a non-integer,
// a negative, or (for counts/timeouts that must be non-zero) zero. Mirrors ReadPorts' shape.
std::expected<uint64_t, Error> ReadPositiveInt(const toml::node& node, std::string_view name,
        std::string_view entry) {
    const auto value = node.value<int64_t>();
    if (!value.has_value()) {
        return std::unexpected(Error{"entry \"{}\" {} must be an integer", entry, name});
    }
    if (*value <= 0) {
        return std::unexpected(Error{"entry \"{}\" {} must be a positive integer", entry, name});
    }
    return static_cast<uint64_t>(*value);
}
```

Then add the `dial` parse to `ReadEntry`. First declare the locals alongside the existing `bool ssdp = false;` (after line 180):

```cpp
    bool dial = false;
    bool dial_seen = false;             // distinguishes "dial = false" from "dial absent"
    std::optional<uint64_t> dial_max_connections;
    std::optional<uint64_t> dial_max_rest_listeners;
    std::optional<uint64_t> dial_max_discovery_listeners;
    std::optional<uint64_t> dial_rest_idle;
    std::optional<uint64_t> dial_discovery_idle;
    std::optional<uint64_t> dial_connect_timeout;
    std::optional<uint64_t> dial_max_header_bytes;
    bool any_dial_tunable = false;
```

Then extend the field-dispatch `if/else` chain. Add a `dial` boolean branch by extending the protocol-flag clause (line 213) and add a tunables clause. Replace the protocol-flag branch (lines 213-224):

```cpp
        } else if (field_name == "wol" || field_name == "mdns" || field_name == "ssdp"
                   || field_name == "dial") {
            const auto flag = field_node.value<bool>();
            if (!flag.has_value()) {
                return Error{"entry \"{}\" {} must be a boolean", name, field_name};
            }
            if (field_name == "wol") {
                wol = *flag;
            } else if (field_name == "mdns") {
                mdns = *flag;
            } else if (field_name == "ssdp") {
                ssdp = *flag;
            } else {
                dial = *flag;
                dial_seen = true;
            }
```

And add the tunables clause immediately before the final `} else {` (the `unexpected option` catch-all, line 235):

```cpp
        } else if (field_name == "dial_max_connections" || field_name == "dial_max_rest_listeners"
                   || field_name == "dial_max_discovery_listeners" || field_name == "dial_rest_idle"
                   || field_name == "dial_discovery_idle" || field_name == "dial_connect_timeout"
                   || field_name == "dial_max_header_bytes") {
            auto value = ReadPositiveInt(field_node, field_name, name);
            if (!value.has_value()) {
                return std::move(value).error();
            }
            any_dial_tunable = true;
            if (field_name == "dial_max_connections") {
                dial_max_connections = *value;
            } else if (field_name == "dial_max_rest_listeners") {
                dial_max_rest_listeners = *value;
            } else if (field_name == "dial_max_discovery_listeners") {
                dial_max_discovery_listeners = *value;
            } else if (field_name == "dial_rest_idle") {
                dial_rest_idle = *value;
            } else if (field_name == "dial_discovery_idle") {
                dial_discovery_idle = *value;
            } else if (field_name == "dial_connect_timeout") {
                dial_connect_timeout = *value;
            } else {
                dial_max_header_bytes = *value;
            }
```

Then add the cross-field checks next to the existing `wol_ports`-without-`wol` check (after line 245):

```cpp
    if ((dial || any_dial_tunable) && !ssdp) {
        return Error{"entry \"{}\" enables dial but does not enable ssdp (DIAL requires SSDP)", name};
    }
    if (any_dial_tunable && !dial) {
        return Error{"entry \"{}\" sets a dial tunable but does not enable dial", name};
    }
    (void)dial_seen;  // reserved for a future "dial = false with tunables" nuance; harmless today
```

Finally, populate the `SsdpConfig` in the `if (ssdp)` block (lines 269-275), folding the optionals onto the struct defaults:

```cpp
    if (ssdp) {
        SsdpConfig config{
            .name = std::string{name}, .mac = mac, .source_if = source_if,
            .target_if = target_if, .address_family = address_family, .dial = dial};
        if (dial_max_connections) config.dial_max_connections = static_cast<size_t>(*dial_max_connections);
        if (dial_max_rest_listeners) config.dial_max_rest_listeners = static_cast<size_t>(*dial_max_rest_listeners);
        if (dial_max_discovery_listeners) config.dial_max_discovery_listeners = static_cast<size_t>(*dial_max_discovery_listeners);
        if (dial_rest_idle) config.dial_rest_idle = std::chrono::seconds{*dial_rest_idle};
        if (dial_discovery_idle) config.dial_discovery_idle = std::chrono::seconds{*dial_discovery_idle};
        if (dial_connect_timeout) config.dial_connect_timeout = std::chrono::seconds{*dial_connect_timeout};
        if (dial_max_header_bytes) config.dial_max_header_bytes = static_cast<size_t>(*dial_max_header_bytes);
        if (auto error = AppendSsdp(ssdp_configs, std::move(config))) {
            return error;
        }
    }
```

(`<chrono>` is already included by `config.h`; `<cstdint>` is already included by `config.cpp`.)

- [ ] **Step 4: Run the parse tests and expect PASS for the right reasons.**

```sh
cmake --build build
ctest --test-dir build -R 'ConfigTest.(ParsesDial|DialDefaults|DialOnly|RejectsDial|AcceptsDialDual|RejectsNonBooleanDial|RejectsNonIntegerDialTunable|RejectsZeroDialConnections)' --output-on-failure
```

Expected: all ten PASS. `ParsesDialFlagAndTunables` now reads each tunable; `RejectsDialWithoutSsdp`/`RejectsDialTunablesWithoutDial` are rejected by the new `ReadEntry` guards; `RejectsDialIpv6Only` is rejected by `SsdpConfig::Verify` through `AppendSsdp`.

- [ ] **Step 5: Run the whole ConfigTest suite (no regressions).**

```sh
ctest --test-dir build -R 'ConfigTest\.' --output-on-failure
```

Expected: every `ConfigTest.*` passes (the existing entries are unaffected; `dial` defaults false).

### Task 5.3: SSDP-side DIAL helpers — `IsDialServiceMessage` and `ParseSsdpLocationEndpoint`

These keep the DIAL classification + LOCATION parse out of `SsdpReflector`'s body and unit-testable on their own. They live in `ssdp_message.{h,cpp}` (where SSDP HTTPU parsing already lives) and depend on `IpEndpoint` (Commit 2, `src/reflector/ip_endpoint.h`).

Files:
- Modify `src/reflector/ssdp_message.h`
- Modify `src/reflector/ssdp_message.cpp`
- Modify `tests/ssdp_message_test.cpp` (append new tests)

- [ ] **Step 1: Write the failing helper tests.** Append to `tests/ssdp_message_test.cpp` (it already includes `reflector/ssdp_message.h`; add `#include "reflector/ip_endpoint.h"` to its include block). Use the byte helper pattern the file already uses (an SSDP-message test file builds a `std::span<const std::byte>` from a string; reuse its local `Bytes` if present, else add one):

```cpp
namespace {
std::vector<std::byte> DialBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}
}  // namespace

TEST(SsdpMessageTest, IsDialServiceMessageMatchesStHeader) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n"
        "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(bytes));
}

TEST(SsdpMessageTest, IsDialServiceMessageMatchesNtAndUsn) {
    const auto nt = DialBytes(
        "NOTIFY * HTTP/1.1\r\n"
        "NT: urn:dial-multiscreen-org:device:dial:1\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(nt));
    const auto usn = DialBytes(
        "NOTIFY * HTTP/1.1\r\n"
        "USN: uuid:abc::urn:dial-multiscreen-org:service:dial:1\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(usn));
}

TEST(SsdpMessageTest, IsDialServiceMessageIsCaseInsensitiveOnTheToken) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\n"
        "ST: urn:Dial-Multiscreen-Org:service:dial:1\r\n\r\n");
    EXPECT_TRUE(IsDialServiceMessage(bytes));
}

TEST(SsdpMessageTest, IsDialServiceMessageRejectsNonDial) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\n"
        "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    EXPECT_FALSE(IsDialServiceMessage(bytes));
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointReadsHostAndPort) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n"
        "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    const auto endpoint = ParseSsdpLocationEndpoint(bytes);
    ASSERT_TRUE(endpoint.has_value());
    EXPECT_EQ(endpoint->addr, IpAddress::FromV4Bytes(10, 1, 3, 80));
    EXPECT_EQ(endpoint->port, 1461u);
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointDefaultsPort80) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\nLOCATION: http://10.1.3.80/dd.xml\r\n\r\n");
    const auto endpoint = ParseSsdpLocationEndpoint(bytes);
    ASSERT_TRUE(endpoint.has_value());
    EXPECT_EQ(endpoint->addr, IpAddress::FromV4Bytes(10, 1, 3, 80));
    EXPECT_EQ(endpoint->port, 80u);  // absent port -> default HTTP port
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointCaseInsensitiveHeaderName) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\nlocation: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    EXPECT_TRUE(ParseSsdpLocationEndpoint(bytes).has_value());
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointNulloptWhenNoLocation) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n");
    EXPECT_FALSE(ParseSsdpLocationEndpoint(bytes).has_value());
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointNulloptOnNonIpv4Host) {
    // A hostname (not an IP literal) can't be bound to; DIAL is IPv4 literal-only here.
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\nLOCATION: http://tv.local:1461/dd.xml\r\n\r\n");
    EXPECT_FALSE(ParseSsdpLocationEndpoint(bytes).has_value());
}

TEST(SsdpMessageTest, ParseSsdpLocationEndpointNulloptOnMalformedPort) {
    const auto bytes = DialBytes(
        "HTTP/1.1 200 OK\r\nLOCATION: http://10.1.3.80:notaport/dd.xml\r\n\r\n");
    EXPECT_FALSE(ParseSsdpLocationEndpoint(bytes).has_value());
}
```

- [ ] **Step 2: Run them and expect a COMPILE failure.** `IsDialServiceMessage` and `ParseSsdpLocationEndpoint` don't exist yet.

```sh
cmake --build build
```

Expected: build error — use of undeclared identifier `IsDialServiceMessage` / `ParseSsdpLocationEndpoint`.

- [ ] **Step 3: Declare the helpers in `ssdp_message.h`.** Add the include and declarations (after the existing `ParseMSearchMx` declaration, before the closing `}` at line 35):

```cpp
#include "ip_endpoint.h"
```

```cpp
// True if the SSDP message advertises the DIAL service/device type — i.e. the token
// "urn:dial-multiscreen-org:" appears in any of the ST / NT / USN header values (the headers a DIAL
// 200 OK / NOTIFY uses to name its type). Case-insensitive on the token; scans the header block only.
[[nodiscard]] bool IsDialServiceMessage(std::span<const std::byte> payload) noexcept;

// Parses the authority of the message's LOCATION header (e.g. "http://10.1.3.80:1461/dd.xml") into an
// IpEndpoint. The host must be an IPv4 literal (DIAL is IPv4-only); an absent port defaults to 80.
// Returns nullopt when LOCATION is absent, the scheme/host isn't an "http://<ipv4>" authority, or the
// port is unparseable — the caller then injects the LOCATION unchanged. Quiet (no logging).
[[nodiscard]] std::optional<IpEndpoint> ParseSsdpLocationEndpoint(std::span<const std::byte> payload) noexcept;
```

- [ ] **Step 4: Implement the helpers in `ssdp_message.cpp`.** Add `#include "ip_endpoint.h"` and `#include "ip_address.h"` to the includes, then add to the anonymous namespace a header-value finder and the DIAL token, and implement the two functions. The existing `HeaderNameMatches` matches a prefix; reuse the line-scanning shape of `ParseMSearchMx`.

Add to the anonymous namespace (after `HeaderNameMatches`, around line 42):

```cpp
constexpr std::string_view DIAL_URN = "urn:dial-multiscreen-org:";

// Lowercase-insensitive substring search of `haystack` for the ASCII `needle`.
bool ContainsCaseInsensitive(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) {
        return haystack.size() >= needle.size();
    }
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j]))
                    != std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

// Returns the trimmed value of the first header named `name` (case-insensitive on the name) in the
// header block, or nullopt if no such header. `name` includes the trailing ':'.
std::optional<std::string_view> FindHeaderValue(std::string_view text, std::string_view name) noexcept {
    size_t pos = 0;
    while (pos < text.size()) {
        const auto end = text.find("\r\n", pos);
        const auto line = text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
        if (HeaderNameMatches(line, name)) {
            auto value = line.substr(name.size());
            const auto first = value.find_first_not_of(" \t");
            return first == std::string_view::npos ? std::string_view{} : value.substr(first);
        }
        if (end == std::string_view::npos) {
            break;
        }
        pos = end + 2;
    }
    return std::nullopt;
}
```

Implement the two functions (after `ParseMSearchMx`, before the closing namespace brace):

```cpp
bool IsDialServiceMessage(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    for (const auto name : {std::string_view{"ST:"}, std::string_view{"NT:"}, std::string_view{"USN:"}}) {
        if (const auto value = FindHeaderValue(text, name)) {
            if (ContainsCaseInsensitive(*value, DIAL_URN)) {
                return true;
            }
        }
    }
    return false;
}

std::optional<IpEndpoint> ParseSsdpLocationEndpoint(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    const auto location = FindHeaderValue(text, "LOCATION:");
    if (!location.has_value()) {
        return std::nullopt;
    }
    constexpr std::string_view scheme = "http://";
    if (location->size() < scheme.size() || !HeaderNameMatches(*location, scheme)) {
        return std::nullopt;  // only plain-HTTP DIAL is in scope (TLS is out of scope)
    }
    auto authority = location->substr(scheme.size());
    // The authority ends at the first '/', '?' or '#'.
    const auto path_start = authority.find_first_of("/?#");
    if (path_start != std::string_view::npos) {
        authority = authority.substr(0, path_start);
    }
    std::string_view host = authority;
    uint16_t port = 80;  // default HTTP port when the authority omits one
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = authority.substr(0, colon);
        const auto port_text = authority.substr(colon + 1);
        unsigned parsed = 0;
        const auto* begin = port_text.data();
        const auto* stop = port_text.data() + port_text.size();
        if (port_text.empty() || std::from_chars(begin, stop, parsed).ec != std::errc{}
                || parsed == 0 || parsed > 65535) {
            return std::nullopt;
        }
        port = static_cast<uint16_t>(parsed);
    }
    // Host must be an IPv4 literal: a dotted-quad with no non-digit/dot characters (so we don't hand a
    // hostname to IpAddress::FromString, which logs on a parse miss). Reject anything else quietly.
    if (host.empty() || host.find_first_not_of("0123456789.") != std::string_view::npos) {
        return std::nullopt;
    }
    const auto addr = IpAddress::FromString(std::string{host});
    if (!addr.has_value() || !addr->IsV4()) {
        return std::nullopt;
    }
    return IpEndpoint{.addr = *addr, .port = port};
}
```

(`<charconv>`, `<cctype>`, `<optional>`, `<string_view>`, `<cstring>` are already included by `ssdp_message.cpp`; add `#include <string>` for `std::string{host}`.)

- [ ] **Step 5: Run the helper tests and expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'SsdpMessageTest.(IsDialServiceMessage|ParseSsdpLocationEndpoint)' --output-on-failure
```

Expected: all ten new `SsdpMessageTest.*` cases PASS; the existing `SsdpMessageTest.*` cases stay green (run `-R 'SsdpMessageTest\.'` to confirm).

### Task 5.4: `SsdpReflector` owns a `DialProxy` and rewrites the DIAL LOCATION on the way out

Files:
- Modify `src/reflector/ssdp_reflector.h` (includes; member; a small helper decl)
- Modify `src/reflector/ssdp_reflector.cpp` (`Initialize`, `OnUnicastResponse`, `OnTargetPacket`)
- Modify `tests/ssdp_reflector_test.cpp` (append new tests)

The integration test builds a real `DialProxy` backed by `FakePacketDispatcher` (whose `UnderlyingDispatcher()` is a `FakeDispatcher`). `EnsureDiscoveryListener` binds a real loopback `TcpSocket` listener on the source interface's IPv4 address — which `FakeLinkSocket::source_v4` defaults to `127.0.0.1` — so the listener bind needs no privilege (loopback TCP listen is unprivileged). The reflector authority returned is `127.0.0.1:<ephemeral>`, and we assert the LOCATION host was swapped to `127.0.0.1` with that port.

- [ ] **Step 1: Write the failing integration tests.** Append to `tests/ssdp_reflector_test.cpp` (inside `namespace reflector { ... }`, in the `SsdpReflectorTest` fixture region). Add a `MakeDialConfig` helper and DIAL payload builders to `SsdpReflectorTestBase` first (extend the class body, after `MakeAdvertisement`):

```cpp
    static SsdpConfig MakeDialConfig() {
        auto config = MakeConfig(AddressFamily::IPv4);
        config.dial = true;
        return config;
    }

    static std::vector<std::byte> MakeDialResponse() {
        return Bytes(
            "HTTP/1.1 200 OK\r\n"
            "ST: urn:dial-multiscreen-org:service:dial:1\r\n"
            "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    }

    static std::vector<std::byte> MakeDialNotify() {
        return Bytes(
            "NOTIFY * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "NT: urn:dial-multiscreen-org:device:dial:1\r\n"
            "NTS: ssdp:alive\r\n"
            "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    }

    // The text of `bytes`, for substring assertions on a rewritten payload.
    static std::string AsText(const std::vector<std::byte>& bytes) {
        return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }
```

Then the tests:

```cpp
// --- DIAL: the dial-enabled reflector rewrites the LOCATION of a DIAL 200 OK / NOTIFY ---

TEST_F(SsdpReflectorTest, DialRewritesLocationOfUnicastResponse) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeDialConfig()};
    ASSERT_TRUE(reflector.IsValid());

    // 1) An M-SEARCH establishes a session and reveals the reserved port P.
    const auto searcher_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:02");
    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4(), searcher_mac));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    // 2) The DIAL device unicasts a 200 OK with a DIAL ST + an absolute LOCATION at 10.1.3.80:1461.
    const auto response = MakeDialResponse();
    Packet reply{
        .header = PacketHeader{
            .source_ip = IpAddress::FromV4Bytes(10, 1, 3, 80),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = SSDP_PORT,
            .dest_port = reserved_port,
            .ttl = 4,
            .source_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:01"),
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    // 3) The injected payload's LOCATION points at the reflector authority (source_if addr = 127.0.0.1,
    //    DialProxy's listener port), not the device's 10.1.3.80:1461. The device host is gone.
    ASSERT_EQ(source.sent.size(), 1u);
    const auto injected = AsText(source.sent.back().payload);
    EXPECT_EQ(injected.find("10.1.3.80:1461"), std::string::npos) << injected;  // device authority spliced out
    EXPECT_NE(injected.find("LOCATION: http://127.0.0.1:"), std::string::npos) << injected;  // reflector addr
    // The rest of the 200 OK is intact (ST untouched, status line preserved).
    EXPECT_NE(injected.find("urn:dial-multiscreen-org:service:dial:1"), std::string::npos) << injected;
    EXPECT_NE(injected.find("HTTP/1.1 200 OK"), std::string::npos) << injected;
}

TEST_F(SsdpReflectorTest, DialRewritesLocationOfNotify) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeDialConfig()};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target, MakePacket(MakeDialNotify(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto injected = AsText(source.sent.back().payload);
    EXPECT_EQ(injected.find("10.1.3.80:1461"), std::string::npos) << injected;
    EXPECT_NE(injected.find("LOCATION: http://127.0.0.1:"), std::string::npos) << injected;
    EXPECT_NE(injected.find("NOTIFY * HTTP/1.1"), std::string::npos) << injected;
}

TEST_F(SsdpReflectorTest, DialLeavesNonDialAdvertisementUntouched) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeDialConfig()};
    ASSERT_TRUE(reflector.IsValid());

    // A plain rootdevice NOTIFY (no DIAL urn, no LOCATION) is reflected byte-for-byte.
    const auto advertisement = MakeAdvertisement();
    packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, advertisement);  // unchanged
}

TEST_F(SsdpReflectorTest, DialLeavesNonDialResponseUntouched) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeDialConfig()};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    // A non-DIAL 200 OK (a MediaRenderer): its LOCATION must survive verbatim.
    const auto response = Bytes(
        "HTTP/1.1 200 OK\r\n"
        "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        "LOCATION: http://10.1.3.80:1461/dd.xml\r\n\r\n");
    Packet reply{
        .header = PacketHeader{
            .source_ip = IpAddress::FromV4Bytes(10, 1, 3, 80),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = SSDP_PORT,
            .dest_port = reserved_port,
            .ttl = 4,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, response);  // non-DIAL LOCATION untouched
}

TEST_F(SsdpReflectorTest, NoDialProxyWhenDialDisabled) {
    // With dial off (the default), even a DIAL 200 OK is forwarded verbatim — no listener, no rewrite.
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    const auto response = MakeDialResponse();
    Packet reply{
        .header = PacketHeader{
            .source_ip = IpAddress::FromV4Bytes(10, 1, 3, 80),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = SSDP_PORT,
            .dest_port = reserved_port,
            .ttl = 4,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, response);  // verbatim: dial disabled
}
```

Add `#include "mocks/fake_packet_dispatcher.h"` is already present; the test uses `packet_dispatcher.dispatcher` (the `FakeDispatcher`) implicitly through the `DialProxy` the reflector constructs — no extra include needed.

- [ ] **Step 2: Run them and expect FAIL.**

```sh
cmake --build build
ctest --test-dir build -R 'SsdpReflectorTest.(DialRewrites|DialLeaves|NoDialProxyWhenDialDisabled)' --output-on-failure
```

Expected: the four `Dial...` cases FAIL — the injected LOCATION still contains `10.1.3.80:1461` (no rewrite happens yet). `NoDialProxyWhenDialDisabled` already PASSES (no rewrite is the current behavior); it guards against regressing the disabled path.

- [ ] **Step 3: Add the `DialProxy` member and a rewrite helper to `ssdp_reflector.h`.** Add the include (after `#include "config.h"`, line 3):

```cpp
#include "dial_proxy.h"
#include "ip_endpoint.h"
```

Add the private helper declaration (after `EvictExpired`, line 75):

```cpp
    // If dial is enabled and `payload` is a DIAL message carrying a LOCATION, ensures a discovery
    // listener for the advertised device endpoint and rewrites the LOCATION authority to the reflector
    // listener; returns the rewritten bytes. Otherwise (dial off, non-DIAL, no LOCATION, or the proxy
    // declines) returns nullopt and the caller injects `payload` unchanged. Quiet on the no-op paths.
    [[nodiscard]] std::optional<std::vector<std::byte>> MaybeRewriteDialLocation(
        std::span<const std::byte> payload);
```

Add the member as the **last** data member (after `eviction_timer_`, line 83) so it is destroyed *first* — before the dispatcher it reaches via `UnderlyingDispatcher()` and before the timer/sessions it is independent of. Per the contract, `dial_proxy_` torn down before the dispatcher; declaring it last satisfies that (members destroy in reverse declaration order, and the dispatcher is a reference, not owned here):

```cpp
    // The DIAL application proxy, present only when config.dial. Reaches the reactor via
    // packet_dispatcher_.UnderlyingDispatcher(); declared last so it is destroyed first (before
    // anything it borrowed). NoMove, so it lives in an optional.
    std::optional<DialProxy> dial_proxy_;
```

Add the needed includes to the header's include block if not already present: `<span>` and `<vector>` (`<optional>` is already included).

- [ ] **Step 4: Construct `dial_proxy_` on the `Initialize` success path.** In `ssdp_reflector.cpp`, add includes:

```cpp
#include "ip_address.h"
#include "ip_endpoint.h"
```

In `Initialize` (after the `logger_.Info("Created ssdp reflector ...")` line, line 82, i.e. only once setup succeeded and at least one registration exists), construct the proxy when enabled:

```cpp
    if (config.dial) {
        // DIAL is IPv4-only and Verify guarantees this entry has IPv4; the source_if IPv4 address is
        // the listener bind address and the rewritten authority. (reflectable(V4) held above whenever
        // a v4 group was set up; require it explicitly so a dial entry that couldn't reflect v4 logs.)
        const auto source_v4 = source_socket.SourceAddress(IpAddress::Family::V4);
        if (!source_v4.has_value()) {
            logger_.Error("Cannot enable DIAL for \"{}\": source interface \"{}\" has no IPv4 address",
                config.name, config.source_if);
            registrations_.clear();
            return;
        }
        dial_proxy_.emplace(packet_dispatcher, *source_v4, config.source_if, config.target_if, config.mac,
            DialProxy::Tunables{
                .max_connections = config.dial_max_connections,
                .max_rest_listeners = config.dial_max_rest_listeners,
                .max_discovery_listeners = config.dial_max_discovery_listeners,
                .max_header_bytes = config.dial_max_header_bytes,
                .connect_timeout = config.dial_connect_timeout,
                .discovery_idle = config.dial_discovery_idle,
                .rest_idle = config.dial_rest_idle,
            });
    }
```

Note on the `DialProxy` ctor: Commit 4 owns `dial_proxy.{h,cpp}` and defines the ctor as
`DialProxy(PacketDispatcher&, IpAddress source_if_addr, std::string source_if_name, std::string target_if_name, std::optional<MacAddress> device_mac, DialProxy::Tunables)`. This call site unpacks `config` into those params and maps the `dial_*` fields into `DialProxy::Tunables`; config's `std::chrono::seconds` widen to the struct's `std::chrono::milliseconds`, and the designated initializers follow `Tunables`' declaration order (`high_water`/`low_water`/`eviction_interval` keep their defaults). The test below depends only on `EnsureDiscoveryListener`'s contracted behavior.

- [ ] **Step 5: Implement `MaybeRewriteDialLocation` and call it at both injection sites.** Add the helper to `ssdp_reflector.cpp` (after `EvictExpired`, before the closing namespace brace):

```cpp
std::optional<std::vector<std::byte>> SsdpReflector::MaybeRewriteDialLocation(
    std::span<const std::byte> payload) {
    if (!dial_proxy_.has_value() || !IsDialServiceMessage(payload)) {
        return std::nullopt;  // dial off, or not a DIAL message: inject unchanged
    }
    const auto device = ParseSsdpLocationEndpoint(payload);
    if (!device.has_value()) {
        return std::nullopt;  // DIAL but no parseable IPv4 LOCATION: nothing to rewrite
    }
    const auto reflector_authority = dial_proxy_->EnsureDiscoveryListener(*device);
    if (!reflector_authority.has_value()) {
        // Cap hit or listen/bind failed: leave the LOCATION pointing at the device so discovery still
        // works via the router until DIAL becomes reachable. (EnsureDiscoveryListener logged the cause.)
        return std::nullopt;
    }
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    auto rewritten = RewriteAuthority(text, *device, *reflector_authority);
    logger_.Debug("DIAL: rewrote LOCATION {} -> {} for searcher discovery", *device, *reflector_authority);
    std::vector<std::byte> out(rewritten.size());
    std::memcpy(out.data(), rewritten.data(), rewritten.size());
    return out;
}
```

Add `#include "ssdp_message.h"` (already present), `#include "http_message.h"` (for `RewriteAuthority`), `#include <cstring>`, `#include <string>`, `#include <span>`, `#include <vector>` to the cpp's includes.

In `OnUnicastResponse` (the 200 OK), replace the `source_socket_.SendUdpDatagram(...)` block (lines 231-236) so the rewrite is applied to the payload before injecting:

```cpp
    // DIAL: if this 200 OK advertises a DIAL service with a LOCATION, swap the device authority for a
    // reflector listener so the searcher's later TCP fetch terminates here. Non-DIAL -> unchanged.
    const auto rewritten = MaybeRewriteDialLocation(packet.payload);
    const std::span<const std::byte> out_payload = rewritten.has_value() ? *rewritten : packet.payload;
    // Inject the 200 OK to the original searcher from our own source address (no spoofing), addressed
    // to the searcher's captured frame MAC — the split's plain SendUdpDatagram takes that dst MAC.
    if (!source_socket_.SendUdpDatagram(session.searcher_mac, session.searcher_ip, session.searcher_port,
            packet.header.source_port, out_payload, SSDP_TTL)) {
        logger_.Error("Cannot reflect SSDP response to searcher {}", session.searcher_ip);
        return;
    }
```

In `OnTargetPacket` (the NOTIFY), the reflect goes through `Reflect(source_socket_, packet)`. Apply the rewrite before reflecting by replacing the body (lines 208-213):

```cpp
void SsdpReflector::OnTargetPacket(const Packet& packet) noexcept {
    // Only advertisements flow target -> source; the source-MAC filter is applied by the dispatcher.
    if (!ShouldReflect(packet, SsdpMessageKind::Advertisement)) {
        return;
    }
    const auto rewritten = MaybeRewriteDialLocation(packet.payload);
    if (!rewritten.has_value()) {
        Reflect(source_socket_, packet);  // common path: reflect the captured payload verbatim
        return;
    }
    // A DIAL NOTIFY with a spliced LOCATION: reflect the rewritten bytes to the same group, from the
    // SSDP port, with the SSDP hop limit (mirrors Reflect, but on the rewritten payload).
    const auto& group = packet.header.dest_ip;
    if (!source_socket_.SendUdpMulticastDatagram(group, SSDP_PORT, SSDP_PORT, *rewritten, SSDP_TTL)) {
        logger_.Error("Cannot reflect DIAL NOTIFY from {} to {}", packet.header.source_ip, group);
        return;
    }
    logger_.Debug("Reflected DIAL NOTIFY (LOCATION rewritten) from {} to {}", packet.header.source_ip, group);
}
```

- [ ] **Step 6: Run the integration tests and expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'SsdpReflectorTest.(DialRewrites|DialLeaves|NoDialProxyWhenDialDisabled)' --output-on-failure
```

Expected: `DialRewritesLocationOfUnicastResponse`, `DialRewritesLocationOfNotify`, `DialLeavesNonDialAdvertisementUntouched`, `DialLeavesNonDialResponseUntouched`, `NoDialProxyWhenDialDisabled` all PASS.

- [ ] **Step 7: Run the full SsdpReflector suite (no regressions).**

```sh
ctest --test-dir build -R 'SsdpReflector' --output-on-failure
```

Expected: every `SsdpReflectorTest.*` and `SsdpReflectorPerFamilyTest.*` passes — the existing non-DIAL paths construct no `dial_proxy_` (default `dial = false`), so their byte-for-byte assertions are unchanged.

### Task 5.5: `application_test` smoke — `dial = true` wires a reflector; absent does not

Files:
- Modify `tests/application_test.cpp` (extend `MakeSsdpConfig` to accept `dial`; append two tests)

This is a smoke test: it confirms an SSDP entry with `dial = true` still wires exactly one reflector (the `DialProxy` is constructed during `SsdpReflector::Initialize` against the fake dispatcher + fake sockets, whose `source_v4` defaults to `127.0.0.1`, so the discovery listener machinery is reachable but no listener is created until a DIAL LOCATION arrives — `Configure` just builds the reflector). It does not exercise the data path (that is `ssdp_reflector_test`/`dial_proxy_test`/e2e).

- [ ] **Step 1: Write the failing smoke tests.** First extend `MakeSsdpConfig` (lines 88-97) to set `dial`:

```cpp
    static SsdpConfig MakeSsdpConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, AddressFamily family = AddressFamily::IPv4, bool dial = false) {
        return SsdpConfig{
            .name = std::string{name},
            .mac = std::nullopt,
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .address_family = family,
            .dial = dial,
        };
    }
```

Append the tests (after `ClearsEarlierReflectorsWhenSsdpFails`, around line 421):

```cpp
TEST_F(ApplicationTest, WiresDialEnabledSsdpReflector) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "src", "dst", AddressFamily::IPv4, /*dial=*/true))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // The dial-enabled SSDP reflector wires like any other: two interface sockets, one reflector,
    // both fds watched. DialProxy is constructed inside it (against the fake reactor + sockets) but
    // opens no listener until a DIAL LOCATION is seen, so the wiring counts are unchanged.
    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 1);
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("src")->fd));
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("dst")->fd));
}

TEST_F(ApplicationTest, WiresSsdpReflectorWithoutDialByDefault) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "src", "dst"))  // dial defaults to false
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // Wires identically; the absence of dial changes nothing observable at the Application level.
    EXPECT_EQ(ReflectorCount(app), 1);
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
}
```

- [ ] **Step 2: Run them and expect FAIL (compile, then behavior).**

```sh
cmake --build build
ctest --test-dir build -R 'ApplicationTest.(WiresDialEnabledSsdpReflector|WiresSsdpReflectorWithoutDialByDefault)' --output-on-failure
```

Expected before Task 5.1-5.4 are in place this would not compile; with them in place, build succeeds and both PASS immediately — the wiring is already correct because `SsdpReflector::Initialize` constructs `dial_proxy_` without changing registration counts. If `WiresDialEnabledSsdpReflector` fails (e.g. `dial_proxy_.emplace` aborted setup), that signals the `Initialize` ordering is wrong; fix `Initialize` so `dial_proxy_.emplace` runs only after registrations exist and never clears them on the happy path. (`FakeLinkSocket::source_v4` defaults to `127.0.0.1`, so the IPv4-address guard in Step 5.4.4 passes.)

- [ ] **Step 3: Confirm PASS.**

```sh
ctest --test-dir build -R 'ApplicationTest\.' --output-on-failure
```

Expected: every `ApplicationTest.*` passes (the existing SSDP wiring tests are unaffected; the two new ones pass).

### Task 5.6: full unit suite, the data-path gate, then commit

Files: none (verification + commit).

- [ ] **Step 1: Run the entire unit suite under ASan/UBSan.**

```sh
grep REFLECTOR_SANITIZE build/CMakeCache.txt   # confirm ON
ctest --test-dir build -L unit --output-on-failure
```

Expected: all `unit.*` tests pass (config, ssdp_message, ssdp_reflector, application, and the rest), zero ASan/UBSan reports.

- [ ] **Step 2: Run the data-path gate (docker debug, docker release, e2e).** This commit changes the SSDP injection path, so the full gate runs before committing (per the data-path rule). Run each in-sandbox first; if a sandbox failure is observed, rerun that one with the sandbox disabled.

```sh
./docker_test.sh
./docker_test.sh release
python3 e2e/run.py
```

Expected: docker debug + release suites green; the existing e2e (mDNS + SSDP round-trips) green. (The DIAL e2e emulator + round-trip is Commit 6, not this commit — here e2e must simply not regress.)

- [ ] **Step 3: Stage and commit.** No new files were added (every change is to existing translation units already listed in `tests/CMakeLists.txt`), so no CMake edit is needed.

```sh
git add src/reflector/config.h src/reflector/config.cpp \
        src/reflector/ssdp_message.h src/reflector/ssdp_message.cpp \
        src/reflector/ssdp_reflector.h src/reflector/ssdp_reflector.cpp \
        tests/config_test.cpp tests/ssdp_message_test.cpp \
        tests/ssdp_reflector_test.cpp tests/application_test.cpp
git commit -m "ssdp_reflector: wire the DIAL proxy into config and the LOCATION rewrite"
```

Expected: one commit on the working branch containing the `dial` config flag + tunables + Verify rules + formatter, the SSDP-side DIAL classification/LOCATION helpers, and the `SsdpReflector` `DialProxy` member with the `200 OK`/`NOTIFY` LOCATION rewrite.

## Commit 6: e2e: dial device emulator + launch round-trip

This commit adds an end-to-end DIAL test that exercises the whole proxy through real Docker containers: a self-contained DIAL device emulator on `target_if` (SSDP responder + HTTP description endpoint + HTTP REST endpoint, modeled on the captured LG TV) and a source-side client that runs discovery → GET description → POST launch → DELETE stop through the reflector. It asserts the reflector rewrote the `LOCATION`, `Application-URL`, and `201 LOCATION` to reflector authorities and that the upstream TCP connections arrived at the emulator from `target_if`'s address. The case is wired into `ALL_CASES` exactly like the SSDP round-trip, so it is selectable with `--case` and runs in the full suite. There is no native-test component here — this commit is e2e + config + README only. It depends on Commits 1–5 being merged (the reflector image must actually implement DIAL), so it lands last.

### Task 6.1: Add the `dial-device` emulator subcommand to probe.py

The emulator is one process that (a) answers the proxied `M-SEARCH` with a unicast `200 OK` whose `LOCATION` points at its own target-side address and a dynamic description port, and (b) serves two HTTP endpoints. It records the peer address of every accepted TCP connection so the client can later assert those connections came from `target_if`'s address. It prints a `dial-device ready` marker once both HTTP servers are bound and the SSDP socket is listening, so `run.py` can sequence the client after it.

**Files:**
- Modify: `/Users/sergii/code/reflector/e2e/probe.py` (add imports, the `dial_device` function, and its subparser in `main`)

- [ ] **Step 1: Add the stdlib imports the emulator needs.** At the top of `probe.py`, the existing imports are `argparse, binascii, socket, struct, sys, time`. Add the HTTP server + threading + JSON bits. Edit the import block:

```python
import argparse
import binascii
import http.server
import json
import os
import socket
import struct
import sys
import threading
import time
```

- [ ] **Step 2: Write the emulator function.** Add this `dial_device` function to `probe.py`, immediately after the `search` function (before `main`). It binds two ephemeral HTTP ports first (so the description port is dynamic, like the LG TV's `:1461`), then answers exactly one proxied M-SEARCH with a `200 OK` whose `LOCATION` is `http://<own-target-addr>:<desc-port>/dd.xml` and whose `ST` is the DIAL service type. The description endpoint serves `GET /dd.xml` → `200` with a `Content-Length` body and an `Application-URL: http://<own-target-addr>:<rest-port>/apps` header. The REST endpoint serves `GET/POST/DELETE /apps/<App>` with `Transfer-Encoding: chunked`; the launch `POST` returns `201` with an absolute `LOCATION: http://<own-target-addr>:<rest-port>/apps/<App>/run`. Every accepted connection's peer IP is recorded in a shared set, which the client reads back over a tiny side channel (`GET /__peers__` on the description server returns the JSON list).

```python
DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"


def _own_address(interface: str, family: int) -> str:
    # The address the reflector's upstream connect() will land on: this container's address on the
    # interface facing the reflector. getsockname after a dummy connect to the all-nodes/broadcast
    # address resolves it without parsing `ip addr`.
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as probe:
        if family == 6:
            scope = socket.if_nametoindex(interface)
            probe.connect(("ff02::1", 9, 0, scope))
        else:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            probe.connect(("255.255.255.255", 9))
        return probe.getsockname()[0]


def dial_device(args: argparse.Namespace) -> int:
    own = _own_address(args.interface, args.family)
    peers: set[str] = set()
    peers_lock = threading.Lock()

    def record(peer_ip: str) -> None:
        with peers_lock:
            peers.add(peer_ip)

    desc_body = (
        '<?xml version="1.0"?>\r\n'
        '<root><device><friendlyName>e2e-dial</friendlyName>'
        '<X_DIALEX_AppsListURL>/apps</X_DIALEX_AppsListURL></device></root>\r\n'
    ).encode()

    class DescHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002 - silence default stderr spam
            pass

        def do_GET(self):  # noqa: N802 - stdlib name
            record(self.client_address[0])
            if self.path == "/__peers__":
                with peers_lock:
                    body = json.dumps(sorted(peers)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            # The DIAL device description: Application-URL is an absolute header on the REST port,
            # the body is relative-only (so the proxy never rewrites a body byte).
            self.send_response(200)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Application-URL", f"http://{own}:{rest_port}/apps")
            self.send_header("Content-Length", str(len(desc_body)))
            self.end_headers()
            self.wfile.write(desc_body)

    class RestHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002
            pass

        def _drain_body(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length:
                self.rfile.read(length)

        def _chunked(self, status: int, body: bytes, extra: dict[str, str] | None = None) -> None:
            # Transfer-Encoding: chunked, matching the LG TV's REST stream. The proxy forwards the
            # chunk data verbatim and only parses chunk-size lines to find the terminating 0-chunk.
            self.send_response(status)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def do_GET(self):  # noqa: N802
            record(self.client_address[0])
            self._drain_body()
            self._chunked(200, b"<service><state>stopped</state></service>")

        def do_POST(self):  # noqa: N802 - launch
            record(self.client_address[0])
            self._drain_body()
            # 201 with an ABSOLUTE Location on the REST port — the proxy rewrites this to its authority.
            run_url = f"http://{own}:{rest_port}{self.path}/run"
            self._chunked(201, b"", {"Location": run_url})

        def do_DELETE(self):  # noqa: N802 - stop
            record(self.client_address[0])
            self._drain_body()
            self._chunked(200, b"")

    # Bind both HTTP servers on ephemeral ports first; the description port is "dynamic" by design.
    bind_host = "::" if args.family == 6 else "0.0.0.0"
    server_cls = http.server.ThreadingHTTPServer
    if args.family == 6:
        server_cls = type("V6Server", (http.server.ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    desc_server = server_cls((bind_host, 0), DescHandler)
    rest_server = server_cls((bind_host, 0), RestHandler)
    desc_port = desc_server.server_address[1]
    rest_port = rest_server.server_address[1]

    threading.Thread(target=desc_server.serve_forever, daemon=True).start()
    threading.Thread(target=rest_server.serve_forever, daemon=True).start()

    # The SSDP responder leg: answer the one proxied M-SEARCH with a 200 OK carrying our LOCATION.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((udp_bind, args.port))
        join_group(sock, family, args.join_group, args.interface)
        location = f"http://{own}:{desc_port}/dd.xml"
        ok = (
            "HTTP/1.1 200 OK\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            f"ST: {DIAL_SERVICE_TYPE}\r\n"
            f"USN: uuid:e2e-dial::{DIAL_SERVICE_TYPE}\r\n"
            f"LOCATION: {location}\r\n\r\n"
        ).encode()
        # Readiness marker after everything is bound, so run.py sequences the client after us.
        print(f"dial-device ready: desc {own}:{desc_port} rest {own}:{rest_port} ssdp :{args.port}",
              flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"dial-device: no M-SEARCH for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1
        print(f"dial-device received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
        sock.sendto(ok, peer)
        print(f"dial-device replied 200 OK (LOCATION {location}) to {peer[0]}:{peer[1]}", flush=True)

    # Stay up serving HTTP for the client's GET/POST/DELETE; exit when its deadline elapses.
    time.sleep(args.serve_seconds)
    print(f"dial-device upstream peers seen: {sorted(peers)}", flush=True)
    return 0
```

- [ ] **Step 3: Register the `dial-device` subparser.** In `main()` in `probe.py`, after the `search_parser` block (just before `args = parser.parse_args()`), add:

```python
    device_parser = subparsers.add_parser(
        "dial-device", help="emulate a DIAL device: SSDP 200 OK + description + REST HTTP endpoints")
    device_parser.add_argument("--port", required=True, type=int, help="SSDP UDP port to bind (1900)")
    device_parser.add_argument("--join-group", required=True, help="SSDP multicast group to join")
    device_parser.add_argument("--interface", required=True, help="interface facing the reflector")
    device_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    device_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the M-SEARCH")
    device_parser.add_argument("--serve-seconds", required=True, type=float,
                               help="seconds to keep the HTTP endpoints up after answering discovery")
    device_parser.set_defaults(func=dial_device)
```

- [ ] **Step 4: Smoke-check the emulator parses and binds locally.** This is not the full e2e run (that needs Docker + the reflector image), just a syntax/bind sanity check on the host. Run:

```sh
python3 -c "import ast; ast.parse(open('e2e/probe.py').read()); print('probe.py parses')"
```

Expected output: `probe.py parses`. (A real run happens in Task 6.4 under Docker.)

### Task 6.2: Add the `dial-client` subcommand (the source-side flow + assertions)

The client runs the full DIAL flow through the reflector and makes the rewrite assertions. It is a single process so the assertions can chain off the previous response (the description's `Application-URL` tells it where to POST). All assertions are about reflector *authorities* (host:port), so the client is told the reflector's source-side address and the device's true target-side address to distinguish "rewritten" from "leaked through".

**Files:**
- Modify: `/Users/sergii/code/reflector/e2e/probe.py` (add the `dial_client` function and its subparser)

- [ ] **Step 1: Write the client function.** Add `dial_client` to `probe.py` right after `dial_device`. It does: (1) M-SEARCH from a bound source port and reads the proxied `200 OK`; (2) asserts the `LOCATION` authority is the reflector's source address (not the device's target address); (3) `GET` the description through that authority and asserts the response `Application-URL` authority is also a reflector authority on source_if; (4) `POST` the launch to the `Application-URL` and asserts `201` + a rewritten `LOCATION`; (5) `DELETE` the run URL; (6) reads `/__peers__` off the device's *true* address to assert the upstream connections arrived from `target_if`'s address (the device's own address — i.e. the reflector bound its upstream connect to target_if, so the device saw the target-side address, never the source client's).

```python
def _http_request(host: str, port: int, method: str, path: str, family: int,
                  body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as sock:
        sock.settimeout(8.0)
        sock.connect((host, port) if family == 4 else (host, port, 0, 0))
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        sock.sendall(req)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, rest


def _authority(url: str) -> str:
    # Strip scheme + path: http://host:port/p -> host:port. IPv6 literals keep their brackets.
    after = url.split("://", 1)[1]
    return after.split("/", 1)[0]


def dial_client(args: argparse.Namespace) -> int:
    refl = args.reflector_authority   # e.g. "172.30.0.2" (source_if address, no port — port is dynamic)
    device = args.device_authority    # the device's TRUE target-side address, host only

    # 1. Discovery: M-SEARCH -> proxied 200 OK.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((udp_bind, args.source_port))
        if family == socket.AF_INET6:
            scope = socket.if_nametoindex(args.interface)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            ifindex = socket.if_nametoindex(args.interface)
            mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)
        sock.sendto(args.payload_hex, dest)
        print(f"dial-client sent M-SEARCH to {args.address}:{args.port}", flush=True)
        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"dial-client: no 200 OK for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

    text = payload.decode("latin-1")
    print(f"dial-client received 200 OK from {peer[0]}:{peer[1]}:\n{text}", flush=True)
    location = next((ln.split(":", 1)[1].strip() for ln in text.split("\r\n")
                     if ln.lower().startswith("location:")), None)
    if location is None:
        print("dial-client: 200 OK had no LOCATION", file=sys.stderr, flush=True)
        return 1
    loc_host = _authority(location).rsplit(":", 1)[0]
    if loc_host != refl:
        print(f"dial-client: LOCATION host {loc_host!r} is not the reflector authority {refl!r} "
              f"(rewrite missing); full LOCATION {location!r}", file=sys.stderr, flush=True)
        return 1
    if device in _authority(location):
        print(f"dial-client: LOCATION still names the device {device!r}: {location!r}",
              file=sys.stderr, flush=True)
        return 1
    desc_host, _, desc_port_s = _authority(location).rpartition(":")
    desc_port = int(desc_port_s)
    desc_path = "/" + location.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: LOCATION rewritten to reflector authority {desc_host}:{desc_port}", flush=True)

    # 2. GET the description through the reflector; assert Application-URL is a reflector authority.
    status, headers, _ = _http_request(desc_host, desc_port, "GET", desc_path, args.family)
    if status != 200:
        print(f"dial-client: GET description -> {status}", file=sys.stderr, flush=True)
        return 1
    app_url = headers.get("application-url")
    if app_url is None:
        print("dial-client: description had no Application-URL", file=sys.stderr, flush=True)
        return 1
    app_host = _authority(app_url).rsplit(":", 1)[0]
    if app_host != refl or device in _authority(app_url):
        print(f"dial-client: Application-URL {app_url!r} not rewritten to reflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    rest_host, _, rest_port_s = _authority(app_url).rpartition(":")
    rest_port = int(rest_port_s)
    apps_path = "/" + app_url.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: Application-URL rewritten to {rest_host}:{rest_port}", flush=True)

    # 3. POST the launch; assert 201 + a rewritten LOCATION on the reflector's REST authority.
    launch_path = f"{apps_path}/YouTube"
    status, headers, _ = _http_request(rest_host, rest_port, "POST", launch_path, args.family,
                                       body=b"pairingCode=e2e")
    if status != 201:
        print(f"dial-client: launch POST -> {status} (expected 201)", file=sys.stderr, flush=True)
        return 1
    run_loc = headers.get("location")
    if run_loc is None:
        print("dial-client: 201 had no LOCATION", file=sys.stderr, flush=True)
        return 1
    run_host = _authority(run_loc).rsplit(":", 1)[0]
    if run_host != refl or device in _authority(run_loc):
        print(f"dial-client: 201 LOCATION {run_loc!r} not rewritten to reflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    print(f"dial-client: 201 LOCATION rewritten to {_authority(run_loc)}", flush=True)

    # 4. DELETE the run URL (stop) through the reflector's REST listener.
    run_path = "/" + run_loc.split("://", 1)[1].split("/", 1)[1]
    status, _, _ = _http_request(rest_host, rest_port, "DELETE", run_path, args.family)
    if status not in (200, 204):
        print(f"dial-client: stop DELETE -> {status}", file=sys.stderr, flush=True)
        return 1
    print("dial-client: stop DELETE ok", flush=True)

    # 5. Assert every upstream connection reached the device from target_if's address. The device
    #    is queried on its TRUE address (the client can reach it only because the test network is
    #    flat for this side-channel — see run.py wiring), and reports the peer IPs it saw.
    status, _, body = _http_request(args.device_query_host, desc_port, "GET", "/__peers__", args.family)
    seen = json.loads(body.decode())
    print(f"dial-client: device saw upstream peers {seen}", flush=True)
    if seen != [args.expect_upstream_from]:
        print(f"dial-client: upstream peers {seen} != [{args.expect_upstream_from!r}] "
              f"(reflector did not source from target_if)", file=sys.stderr, flush=True)
        return 1
    print("dial-client: all upstream connections came from target_if's address", flush=True)
    return 0
```

- [ ] **Step 2: Register the `dial-client` subparser.** In `main()` in `probe.py`, after the `device_parser` block, add:

```python
    client_parser = subparsers.add_parser(
        "dial-client", help="run the DIAL flow through the reflector and assert the rewrites")
    client_parser.add_argument("--source-port", required=True, type=int, help="M-SEARCH source port")
    client_parser.add_argument("--port", required=True, type=int, help="SSDP destination port (1900)")
    client_parser.add_argument("--address", required=True, help="SSDP multicast group")
    client_parser.add_argument("--interface", required=True, help="egress interface for multicast")
    client_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    client_parser.add_argument("--payload-hex", required=True, type=parse_payload_hex, help="M-SEARCH")
    client_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the 200 OK")
    client_parser.add_argument("--reflector-authority", required=True,
                               help="reflector source_if address (host only; LOCATION ports are dynamic)")
    client_parser.add_argument("--device-authority", required=True,
                               help="device's true target-side host, asserted absent from rewrites")
    client_parser.add_argument("--device-query-host", required=True,
                               help="host to read /__peers__ from (the device's true address)")
    client_parser.add_argument("--expect-upstream-from", required=True,
                               help="target_if address the device must have seen the upstream from")
    client_parser.set_defaults(func=dial_client)
```

- [ ] **Step 3: Re-check probe.py parses.** Run:

```sh
python3 -c "import ast; ast.parse(open('e2e/probe.py').read()); print('probe.py parses')"
```

Expected output: `probe.py parses`.

### Task 6.3: Add the DIAL case + DockerDial runner to run.py and the config entry

The runner mirrors `DockerRoundTrip`: it reuses `DockerE2E`'s network/reflector setup via a `TestCase` shim, starts the emulator on `target_if` (the responder side), and runs the client on `source_if`. It must learn two addresses at runtime: the reflector's `source_if` address (the rewrite target) and the device emulator's `target_if` address (asserted absent from rewrites, and asserted present as the upstream source). Both are read with `docker inspect` after the containers attach to their networks.

**Files:**
- Modify: `/Users/sergii/code/reflector/e2e/run.py` (add `DIAL_SERVICE_TYPE`/`SSDP_DIAL_MSEARCH_HEX`, the `DialCase` dataclass, `DIAL_CASES`, fold into `ALL_CASES`, the `DockerDial` runner, and the `make_runner` branch)
- Modify: `/Users/sergii/code/reflector/e2e/config.toml` (add a `dial = true` entry)

- [ ] **Step 1: Add the DIAL M-SEARCH constant.** In `run.py`, after the `SSDP_OK_HEX`/`SEARCHER_SOURCE_PORT` block (around line 86), add a DIAL-targeted M-SEARCH (the `ST` is the DIAL service type, so the emulator and any future ST-filtering both match):

```python
DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"
SSDP_DIAL_MSEARCH_HEX = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    f"ST: {DIAL_SERVICE_TYPE}\r\n\r\n"
).encode().hex()
DIAL_CLIENT_SOURCE_PORT = 49153
```

- [ ] **Step 2: Add the `DialCase` dataclass.** In `run.py`, after the `ROUNDTRIP_CASES` definition (around line 366), add:

```python
@dataclasses.dataclass(frozen=True)
class DialCase:
    name: str
    family: int          # 4 (DIAL is IPv4-only by spec; kept as a field for symmetry/clarity)
    group: str
    timeout_seconds: float = 8.0
    serve_seconds: float = 6.0


DIAL_CASES = [
    DialCase(name="dial_launch_roundtrip", family=4, group=SSDP_GROUP_V4),
]
```

- [ ] **Step 3: Fold `DIAL_CASES` into `ALL_CASES`.** Replace the existing `ALL_CASES` assignment (line 370):

```python
ALL_CASES: list[TestCase | RoundTripCase | DialCase] = [*TEST_CASES, *ROUNDTRIP_CASES, *DIAL_CASES]
```

- [ ] **Step 4: Add the `DockerDial` runner.** In `run.py`, after the `DockerRoundTrip` class (after line 699), add the runner. It learns the source/target addresses via a helper that reads the container's IP on a given Docker network, then wires those into the emulator + client args. The emulator runs on `target_if`; the client on `source_if`. The client reads `/__peers__` from the device's *true* target address — reachable from the client container only because Docker attaches it to both networks for this side-channel read (added below in the `--network` flags), keeping the assertion deterministic without scraping reflector logs.

```python
class DockerDial(DockerE2E):
    def __init__(self, args: argparse.Namespace, case: DialCase) -> None:
        shim = TestCase(name=case.name, send_port=SSDP_PORT, receive_port=SSDP_PORT,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward")
        super().__init__(args, shim)
        self.dial = case
        self.device_container = f"{self.prefix}-device"
        self.client_container = f"{self.prefix}-client"
        self.containers = [self.client_container, self.device_container, self.reflector_container]

    def container_ip(self, container: str, network: str) -> str:
        fmt = "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}"
        result = docker(["inspect", "-f", fmt, container])
        ip = result.stdout.strip()
        if not ip:
            raise RuntimeError(f"no IPv4 address for {container} on {network}")
        return ip

    def reflector_source_ip(self) -> str:
        return self.container_ip(self.reflector_container, self.source_network)

    def start_device(self) -> None:
        # The emulator lives on target_if (responder side) AND is also attached to the source network
        # so the client can read its /__peers__ side channel directly. The reflector's upstream still
        # connects to its target-side address (that is the LOCATION it advertises), so the peer the
        # device records is target_if's address regardless of the extra attachment.
        docker([
            "run", "-d", "--name", self.device_container,
            "--network", f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={RECEIVER_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "dial-device",
            "--port", str(SSDP_PORT), "--join-group", self.dial.group,
            "--interface", RECEIVER_IFNAME, "--family", str(self.dial.family),
            "--timeout", str(self.dial.timeout_seconds), "--serve-seconds", str(self.dial.serve_seconds),
        ])
        # Attach the device to the source network too, for the client's /__peers__ read only.
        docker(["network", "connect", self.source_network, self.device_container])
        self.wait_for_container_log(self.device_container, "dial-device ready", "dial-device")

    def run_client(self) -> None:
        device_target_ip = self.container_ip(self.device_container, self.target_network)
        device_source_ip = self.container_ip(self.device_container, self.source_network)
        refl_source_ip = self.reflector_source_ip()
        docker([
            "run", "-d", "--name", self.client_container,
            "--network", f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "dial-client",
            "--source-port", str(DIAL_CLIENT_SOURCE_PORT), "--port", str(SSDP_PORT),
            "--address", self.dial.group, "--interface", REFLECTOR_SOURCE_IFNAME,
            "--family", str(self.dial.family), "--payload-hex", SSDP_DIAL_MSEARCH_HEX,
            "--timeout", str(self.dial.timeout_seconds),
            "--reflector-authority", refl_source_ip,
            "--device-authority", device_target_ip,
            "--device-query-host", device_source_ip,
            "--expect-upstream-from", device_target_ip,
        ])

    def wait_for_client(self) -> None:
        exit_code = docker(["wait", self.client_container]).stdout.strip()
        logs = docker(["logs", self.client_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)
        if exit_code != "0":
            raise RuntimeError(f"dial-client failed with exit code {exit_code}")

    def run(self) -> None:
        print(f"\n=== {self.dial.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        self.start_device()      # must be serving before the client searches
        self.run_client()
        self.wait_for_client()
        print(f"PASS {self.dial.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()
```

- [ ] **Step 5: Wire `DockerDial` into `make_runner`.** Replace `make_runner` (line 702):

```python
def make_runner(args: argparse.Namespace, case: TestCase | RoundTripCase | DialCase) -> DockerE2E:
    if isinstance(case, DialCase):
        return DockerDial(args, case)
    if isinstance(case, RoundTripCase):
        return DockerRoundTrip(args, case)
    return DockerE2E(args, case)
```

- [ ] **Step 6: Widen the two `list[TestCase | RoundTripCase]` annotations.** `select_cases` (line 710) is annotated `-> list[TestCase | RoundTripCase]`; update it to include `DialCase`:

```python
def select_cases(case_names: list[str]) -> list[TestCase | RoundTripCase | DialCase]:
```

(The `cases_by_name`/`--case`/`choices` machinery already iterates `ALL_CASES` generically, so adding `DIAL_CASES` to `ALL_CASES` in Step 3 makes `dial_launch_roundtrip` selectable with no further change.)

- [ ] **Step 7: Add the `dial = true` entry to `e2e/config.toml`.** The emulator and client both use the `wol_src`/`wol_dst` interface pair the e2e networks pin. Append a DIAL entry to `e2e/config.toml`:

```toml
[dial-tv]
source_if = "wol_src"
target_if = "wol_dst"
ssdp = true
dial = true
```

(Keep the existing `[discovery]` entry as-is — it already enables `ssdp`/`mdns` on the same interface pair for the non-DIAL SSDP/mDNS cases. The duplicate-detection rules in §"Duplicate detection" reject two entries that reflect the same packet twice: `[dial-tv]` and `[discovery]` share `source_if`/`target_if`, both omit `mac` (any device), and both enable `ssdp` — so they WOULD collide. To avoid the startup rejection, scope `[dial-tv]` to the emulator's MAC instead so they no longer overlap on MAC selection.) Use this entry instead:

```toml
[dial-tv]
source_if = "wol_src"
target_if = "wol_dst"
mac = "02:42:ac:11:00:09"
ssdp = true
dial = true
```

- [ ] **Step 8: Verify run.py parses and lists the new case.** Run:

```sh
python3 -c "import ast; ast.parse(open('e2e/run.py').read()); print('run.py parses')"
python3 e2e/run.py --help
```

Expected: `run.py parses`, and the `--case` `choices` in the help text now includes `dial_launch_roundtrip`.

### Task 6.4: Run the DIAL e2e case against the built reflector image

This is the failing-then-passing gate for the whole DIAL feature end to end. Before Commits 1–5 are present in the image the case fails (the reflector leaves `LOCATION` unrewritten, so the client's first assertion trips); with them it passes.

**Files:** none (execution only)

- [ ] **Step 1: Run only the DIAL case (it builds the reflector image first).** Run:

```sh
python3 e2e/run.py --case dial_launch_roundtrip
```

Expected FAIL **before** the DIAL implementation is in the image: the client prints `dial-client: LOCATION host ... is not the reflector authority ... (rewrite missing)` and `run.py` reports `dial-client failed with exit code 1`. Expected PASS **with** the full DIAL implementation: the client prints the four rewrite confirmations (`LOCATION rewritten`, `Application-URL rewritten`, `201 LOCATION rewritten`, `all upstream connections came from target_if's address`) and `run.py` prints `PASS dial_launch_roundtrip`.

- [ ] **Step 2: Run the full e2e suite to confirm no regression.** Run:

```sh
python3 e2e/run.py
```

Expected: every existing case still passes and the run ends with `PASS <N> e2e case(s)` where `<N>` is the prior count plus one (the new `dial_launch_roundtrip`).

- [ ] **Step 3: Commit.** Run:

```sh
git add e2e/probe.py e2e/run.py e2e/config.toml
git commit -m "e2e: add dial device emulator and launch round-trip"
```

---

## Follow-ups (deferred — surfaced while building/gating the proxy, intentionally NOT bundled into Commits 4–6)

- **Stricter GCC warning flags.** Add `-Wuseless-cast`, `-Wformat-signedness`, `-Wmissing-declarations` (GCC) and the Clang twin `-Wmissing-prototypes` to `reflector_configure_project_target` in the root `CMakeLists.txt`. They were left out of the warning-flag tidy-up because they surface *pre-existing* warnings the code doesn't fix yet — a useless cast in `raw_socket.cpp`, plus warnings on the Linux-only epoll / `AF_PACKET` paths that only the docker (Linux/GCC) build compiles. Do it as a focused commit run under `./docker_test.sh`, fixing each surfaced warning. A matching `NOTE` marks the spot in `CMakeLists.txt`. Use the local `g++-15` `-fsyntax-only` sweep to catch the platform-agnostic ones fast; the docker gate is authoritative for the Linux paths.

- **Three DialProxy test/cleanup nits** the verification panels flagged as deferrable (none are correctness holes):
  - Pin that a client request arriving while the upstream is still `Connecting` does **not** extend the connect deadline (the `phase == Open` guard on `Forward`'s idle-deadline refresh).
  - The dispatcher single-`PollOnce` read-then-write re-resolve (`event_loop_dispatcher.cpp` line ~229) is exercised coincident-edge only under epoll; the unit test pins it portably but the exact ordering is epoll-only.
  - Review the log level on the u2c REST-mint-failure (close-don't-forward) path: a cap-reached drop is an expected capacity limit, arguably `Warning`/`Debug` rather than `Error`.
