# SSDP DIAL Application Proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cross-segment DIAL (UPnP "Discovery And Launch") work through the reflector alone — a self-contained, opt-in (`dial = true`) terminating HTTP reverse proxy that lets a client on `source_if` drive a DIAL device on `target_if` with no router NAT rule.

**Architecture:** A terminating TCP reverse proxy integrated into the existing single-threaded reactor. The reactor gains write-interest control (for non-blocking `connect()` completion and send-buffer flush; read stays always armed). `DialProxy` (owned by `SsdpReflector`, gated by `dial = true`) rewrites the DIAL `LOCATION` in proxied SSDP responses to point at itself, stands up an ephemeral TCP listener per discovered device endpoint, and for each accepted client connection opens an upstream connection bound to `target_if`'s address (so the device sees an its-subnet source). It forwards HTTP, rewriting only four headers (`LOCATION`, `Application-URL`, response `Location`, request `Host`) by authority substitution — bodies stream through verbatim (Content-Length or chunked). State is bounded (drop-new caps + role-based idle eviction + drop-and-close bounded buffers), all RAII, all reactor-driven, no threads. Grounded in a packet capture of a real LG webOS TV and the DIAL v1.6.4 spec. Full design: `docs/superpowers/specs/2026-06-01-ssdp-dial-proxy-design.md`.

**Tech Stack:** C++23, GoogleTest, the project's `Delegate`/`Registration`/`Timer` reactor primitives, raw POSIX TCP sockets (epoll on Linux / kqueue on macOS), Python for the e2e harness + DIAL device emulator. Build with `./cmake_gen.sh` (Debug, ASan+UBSan); test with `ctest --test-dir build -L unit --output-on-failure`.

---

## Commit sequence (each lands green; data-path commits run the full gate first)

1. **`dispatcher`** — reactor read/write interest control (lands alone, like the timer commit; no DIAL dependency).
2. **`tcp_socket`** — the `IpEndpoint` value type + a non-blocking `TcpSocket` RAII wrapper.
3. **`http_message`** — minimal HTTP/1.1 framing + `RewriteAuthority` (pure, no sockets).
4. **`dial_proxy`** — the `DialProxy` orchestrator (listeners, connection pump, drop-and-close backpressure, eviction).
5. **`ssdp_reflector` + `config`** — the `dial` flag + tunables + `Verify` rules + the SSDP `LOCATION` rewrite hooks.
6. **`e2e` + `docs`** — a DIAL device emulator + launch round-trip case, and the README section.

The **full test gate** (native `ctest -L unit` + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`, with `grep REFLECTOR_SANITIZE build/CMakeCache.txt` showing `ON`) runs before each data-path commit (4, 5, 6).

---

## File structure

**New source files**
- `src/reflector/ip_endpoint.h` — `IpEndpoint { IpAddress addr; uint16_t port; }` value type (+ `operator==`, `std::formatter`). *(Commit 2)*
- `src/reflector/tcp_socket.{h,cpp}` — move-only non-blocking TCP RAII (`Listen`/`Accept`/`Connect`/`Read`/`Write`/`SoError`/`LocalPort`), SIGPIPE-safe, egress-pinned connect. *(Commit 2)*
- `src/reflector/http_message.{h,cpp}` — `RewriteAuthority` + `HttpFraming` (incremental HTTP/1.1 framing + header rewrite). *(Commit 3)*
- `src/reflector/dial_proxy.{h,cpp}` — `DialProxy`, `Endpoint`/`Connection`, the connection pump, drop-and-close backpressure, eviction `Timer` (the bounded `SendBuffer` lives in `TcpSocket`, C2). *(Commit 4)*

**Modified source files**
- `src/reflector/dispatcher.h`, `src/reflector/event_loop_dispatcher.{h,cpp}` — `OnWritableCallback`, `FdCallbacks` `Register`, `SetWriteInterest` (read always armed; no `SetReadInterest`). *(Commit 1)*
- `src/reflector/config.{h,cpp}` — `SsdpConfig` gains `dial` + tunables, `Verify` rules, formatter, TOML parse. *(Commit 5)*
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
// ---- Commit 1: reactor read/write interest control (dispatcher.h) ----
using OnWritableCallback = Delegate<void(int)>;                 // fd became writable
// 3-arg form is the pure virtual; the 2-arg form is a non-virtual convenience forwarding {}:
[[nodiscard]] virtual Registration Register(int fd, const OnReadableCallback&, const OnWritableCallback&) = 0;
[[nodiscard]] Registration         Register(int fd, const OnReadableCallback& r) { return Register(fd, r, OnWritableCallback{}); }
[[nodiscard]] virtual bool SetWriteInterest(int fd, bool enabled) noexcept = 0;  // epoll MOD +/- EPOLLOUT; kqueue EVFILT_WRITE ENABLE/DISABLE
[[nodiscard]] virtual bool SetReadInterest (int fd, bool enabled) noexcept = 0;  // epoll MOD +/- EPOLLIN;  kqueue EVFILT_READ  ENABLE/DISABLE
// EventLoopDispatcher::callbacks_ : unordered_map<int, FdCallbacks>
struct FdCallbacks { OnReadableCallback read; bool read_armed = true; OnWritableCallback write; bool write_armed = false; };
// Read interest starts ARMED (existing consumers unaffected). Disarming read interest stops the kernel
// delivering readable events (NOT a userland skip) — epoll/kqueue are level-triggered, so a still-armed
// undrained readable fd would busy-spin. FakeDispatcher mirrors this: FireWritable; SetReadInterest/
// SetWriteInterest toggles; IsReadArmed/IsWriteArmed; FireReadable is a no-op while read-disarmed.

// ---- Commit 2: ip_endpoint.h + tcp_socket.{h,cpp} ----
struct IpEndpoint { IpAddress addr; uint16_t port = 0; bool operator==(const IpEndpoint&) const noexcept = default; };  // + std::formatter
class TcpSocket {  // move-only (NoCopy)
  enum class IoStatus : uint8_t { Ok, WouldBlock, Closed, Error };
  struct IoResult { size_t n = 0; IoStatus status = IoStatus::Ok; };
  static std::optional<TcpSocket> Listen(const IpAddress& bind_addr) noexcept;                                            // SO_REUSEADDR, bind(:0), listen
  std::optional<TcpSocket>        Accept() noexcept;                                                                      // nonblocking+SIGPIPE-safe child; nullopt on EAGAIN
  static std::optional<TcpSocket> Connect(const IpEndpoint& dst, const IpAddress& bind_addr, std::string_view egress_iface) noexcept;  // EINPROGRESS = success
  IoResult Read (std::span<std::byte>) noexcept;
  IoResult Write(std::span<const std::byte>) noexcept;                                                                    // SIGPIPE-safe (MSG_NOSIGNAL / SO_NOSIGPIPE)
  int Fd() const noexcept; uint16_t LocalPort() const noexcept; int SoError() const noexcept;                             // SO_ERROR: 0 = connected
};

// ---- Commit 3: http_message.{h,cpp} ----
[[nodiscard]] std::string RewriteAuthority(std::string_view text, const IpEndpoint& from, const IpEndpoint& to);
class HttpFraming {
  enum class Side : uint8_t { Request, Response };
  enum class Status : uint8_t { NeedMore, Error };
  using HeaderRewrite = std::function<std::optional<IpEndpoint>(Side side, const IpEndpoint& found)>;
  HttpFraming(Side side, size_t max_header_bytes, HeaderRewrite rewrite);
  [[nodiscard]] Status Feed(std::span<const std::byte> in, std::vector<std::byte>& out);   // headers rewritten, body verbatim; Error on oversized header block
};

// ---- Commit 4: dial_proxy.{h,cpp} ----
// SendBuffer: bounded FIFO byte buffer (std::vector<std::byte> + consumed-head offset; Append/View/Consume/Size; compact on drain).
class DialProxy {  // NoMove; owned by SsdpReflector; reaches the reactor via PacketDispatcher::UnderlyingDispatcher()
 public:
  [[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(IpEndpoint device);   // the ONLY public method
 private:
  std::optional<IpEndpoint> EnsureRestListener(IpEndpoint device);      // used by the response-side HeaderRewrite
  std::optional<IpEndpoint> EnsureListener(IpEndpoint device, /*Role*/ int role);
  // HIGH_WATER = 64 KB, LOW_WATER = 16 KB. Caps (defaults): MAX_REST_LISTENERS=32, MAX_DISCOVERY_LISTENERS=32, MAX_CONNECTIONS=32 (drop-new).
  // Flow control: at HIGH_WATER -> SetReadInterest(source_fd, false); when the peer drains < LOW_WATER -> SetReadInterest(source_fd, true).
};

// ---- Commit 5: config + ssdp_reflector ----
// SsdpConfig: bool dial=false; size_t dial_max_connections=32, dial_max_rest_listeners=32, dial_max_discovery_listeners=32;
//   std::chrono::seconds dial_rest_idle{3600}, dial_discovery_idle{90}, dial_connect_timeout{5}; size_t dial_max_header_bytes=65536.
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

### Task 2.1: IpEndpoint value type (struct + operator== + formatter)

**Files**
- Create: `src/reflector/ip_endpoint.h`
- Create: `tests/ip_endpoint_test.cpp`
- Modify: `tests/CMakeLists.txt` (add `ip_endpoint_test.cpp` to the `reflector_test` source list)

- [ ] **Step 1: Add the failing test file.** `IpEndpoint` is a header-only value type, so its test
  covers default member equality and the `std::formatter` (which prints `addr:port`, with IPv6 addr
  bracketed because the `IpAddress` formatter already brackets v6). Write
  `tests/ip_endpoint_test.cpp`:

```cpp
#include "reflector/ip_endpoint.h"

#include <gtest/gtest.h>

#include <format>

using namespace reflector;

namespace {

IpEndpoint V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    return IpEndpoint{IpAddress::FromV4Bytes(a, b, c, d), port};
}

} // namespace

TEST(IpEndpointTest, EqualWhenAddrAndPortMatch) {
    EXPECT_EQ(V4(10, 1, 3, 80, 1900), V4(10, 1, 3, 80, 1900));
}

TEST(IpEndpointTest, DiffersWhenPortDiffers) {
    EXPECT_NE(V4(10, 1, 3, 80, 1900), V4(10, 1, 3, 80, 1901));
}

TEST(IpEndpointTest, DiffersWhenAddrDiffers) {
    EXPECT_NE(V4(10, 1, 3, 80, 1900), V4(10, 1, 3, 81, 1900));
}

TEST(IpEndpointTest, DefaultPortIsZero) {
    EXPECT_EQ(IpEndpoint{IpAddress::AnyV4()}.port, 0);
}

TEST(IpEndpointTest, FormatsV4AddressColonPort) {
    EXPECT_EQ(std::format("{}", V4(10, 1, 3, 80, 36866)), "10.1.3.80:36866");
}

TEST(IpEndpointTest, FormatsV6AddressBracketedColonPort) {
    const auto v6 = IpAddress::FromString("fe80::1");
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(std::format("{}", IpEndpoint{*v6, 1900}), "[fe80::1]:1900");
}
```

- [ ] **Step 2: Register the test, build, and confirm it FAILS to compile.** Add the source line to
  `tests/CMakeLists.txt` after the `udp_socket_test.cpp` entry:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_endpoint_test.cpp
```

  Then build:

```sh
cmake --build build
```

  Expected: a **compile error** — `reflector/ip_endpoint.h` does not exist (`fatal error: 'reflector/ip_endpoint.h' file not found`). This is the failing-test state.

- [ ] **Step 3: Create the header with the minimal implementation.** Write
  `src/reflector/ip_endpoint.h`. The `==` is `= default` (member-wise over `IpAddress::operator==`
  and the `uint16_t`); the formatter forwards `addr` through the existing
  `std::formatter<IpAddress>` (so v6 is bracketed) then appends `:port`:

```cpp
#pragma once

#include "reflector/ip_address.h"

#include <cstdint>
#include <format>

namespace reflector {

// A discovered DIAL endpoint (device or reflector authority): an address plus a port. Stored in
// small std::vector and found by linear scan (==), like SSDP sessions — no hashing needed.
struct IpEndpoint {
    IpAddress addr;
    uint16_t  port = 0;

    [[nodiscard]] bool operator==(const IpEndpoint&) const noexcept = default;
};

} // namespace reflector

template <>
struct std::formatter<reflector::IpEndpoint, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for IpEndpoint");
        }
        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::IpEndpoint& endpoint, FmtContext& ctx) const {
        // The IpAddress formatter already brackets IPv6 (e.g. "[fe80::1]"), so "{}:{}" yields a
        // valid authority for both families.
        return std::format_to(ctx.out(), "{}:{}", endpoint.addr, endpoint.port);
    }
};
```

- [ ] **Step 4: Build and run, confirm PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'IpEndpointTest' --output-on-failure
```

  Expected: all six `unit.IpEndpointTest.*` cases pass.

- [ ] **Step 5: Commit.**

```sh
git add src/reflector/ip_endpoint.h tests/ip_endpoint_test.cpp tests/CMakeLists.txt
git commit -m "ip_endpoint: add addr+port value type with formatter"
```

### Task 2.2: TcpSocket skeleton — Listen, Fd, LocalPort, RAII, move semantics

**Files**
- Create: `src/reflector/tcp_socket.h`
- Create: `src/reflector/tcp_socket.cpp`
- Create: `tests/tcp_socket_test.cpp`
- Modify: `src/reflector/CMakeLists.txt` (add `tcp_socket.cpp` to the `reflector` source list)
- Modify: `tests/CMakeLists.txt` (add `tcp_socket_test.cpp` to the `reflector_test` source list)

- [ ] **Step 1: Write the failing test for Listen + accessors + move.** This first test only
  exercises the listening-socket lifecycle (no client yet): `Listen` on `127.0.0.1` yields a valid
  fd and a non-zero ephemeral `LocalPort`; the fd is non-blocking; move transfers the fd and zeroes
  the source; destruction closes the fd. Create `tests/tcp_socket_test.cpp`:

```cpp
#include "reflector/tcp_socket.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <fcntl.h>

#include <array>
#include <cstddef>
#include <span>
#include <utility>

using namespace reflector;

namespace {

TcpSocket ListenLoopback() {
    auto sock = TcpSocket::Listen(IpAddress::LoopbackV4());
    EXPECT_TRUE(sock.has_value()) << "Listen on 127.0.0.1 should succeed without privilege";
    return std::move(*sock);
}

} // namespace

TEST(TcpSocketTest, ListenReturnsValidFdAndEphemeralPort) {
    auto listener = TcpSocket::Listen(IpAddress::LoopbackV4());
    ASSERT_TRUE(listener.has_value());
    EXPECT_GE(listener->Fd(), 0);
    EXPECT_NE(listener->LocalPort(), 0);
}

TEST(TcpSocketTest, ListenSocketIsNonBlocking) {
    auto listener = ListenLoopback();
    const auto flags = fcntl(listener.Fd(), F_GETFL, 0);
    ASSERT_GE(flags, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0);
}

TEST(TcpSocketTest, MoveConstructTransfersFdAndZeroesSource) {
    auto src = ListenLoopback();
    const int fd = src.Fd();
    const uint16_t port = src.LocalPort();
    ASSERT_GE(fd, 0);

    TcpSocket dst{std::move(src)};
    EXPECT_EQ(dst.Fd(), fd);
    EXPECT_EQ(dst.LocalPort(), port);
    EXPECT_LT(src.Fd(), 0); // NOLINT(bugprone-use-after-move)
}

TEST(TcpSocketTest, MoveAssignClosesPriorFdAndTransfers) {
    auto src = ListenLoopback();
    auto dst = ListenLoopback();
    const int src_fd = src.Fd();
    const int dst_fd = dst.Fd();
    ASSERT_NE(src_fd, dst_fd);

    dst = std::move(src);
    EXPECT_EQ(dst.Fd(), src_fd);
    EXPECT_LT(src.Fd(), 0); // NOLINT(bugprone-use-after-move)
    // The fd dst previously owned must be closed now (fcntl on it fails with EBADF).
    EXPECT_EQ(fcntl(dst_fd, F_GETFL, 0), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST(TcpSocketTest, SelfMoveAssignmentKeepsSocketValid) {
    auto sock = ListenLoopback();
    const int fd = sock.Fd();
    auto& ref = sock;
    sock = std::move(ref);
    EXPECT_EQ(sock.Fd(), fd);
}

TEST(TcpSocketTest, DestructorClosesFd) {
    int fd = -1;
    {
        auto listener = ListenLoopback();
        fd = listener.Fd();
        ASSERT_GE(fd, 0);
    }
    EXPECT_EQ(fcntl(fd, F_GETFL, 0), -1);
    EXPECT_EQ(errno, EBADF);
}
```

- [ ] **Step 2: Register both new sources and confirm the build FAILS.** Add `tcp_socket.cpp` to
  `src/reflector/CMakeLists.txt` after the `ssdp_message.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tcp_socket.cpp
```

  Add `tcp_socket_test.cpp` to `tests/CMakeLists.txt` after the `ip_endpoint_test.cpp` line from
  Task 2.1:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_endpoint_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tcp_socket_test.cpp
```

  Build:

```sh
cmake --build build
```

  Expected: a **compile error** — `reflector/tcp_socket.h` does not exist.

- [ ] **Step 3: Write the full header `src/reflector/tcp_socket.h`.** This is the complete
  contract surface (Listen/Accept/Connect/Read/Write/Fd/LocalPort/SoError) — later tasks fill in
  the unimplemented `.cpp` bodies, but the header lands whole now so the type compiles. It is
  `NoCopy` (move-only fd owner), mirroring `UdpSocket`:

```cpp
#pragma once

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "reflector/logger.h"
#include "reflector/util/no_copy.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace reflector {

// Move-only RAII over a non-blocking, SIGPIPE-safe TCP fd. The DIAL proxy never touches a raw fd:
// it listens on source_if, accepts clients, connects upstream (source-bound + egress-pinned to
// target_if), and streams bytes — all non-blocking and reactor-driven.
class TcpSocket : NoCopy {
public:
    enum class IoStatus : uint8_t { Ok, WouldBlock, Closed, Error };
    struct IoResult {
        size_t   n = 0;
        IoStatus status = IoStatus::Ok;
    };

    // socket(SOCK_STREAM|NONBLOCK), SO_REUSEADDR, bind(bind_addr, port 0), listen(). bind_addr's
    // family selects AF_INET/AF_INET6. Binding the interface address (not 0.0.0.0) keeps the
    // listener reachable only from that subnet. nullopt on any syscall failure.
    [[nodiscard]] static std::optional<TcpSocket> Listen(const IpAddress& bind_addr) noexcept;

    // Accept the next pending client; the returned socket is non-blocking + SIGPIPE-safe. nullopt on
    // EAGAIN (no pending client) or error.
    [[nodiscard]] std::optional<TcpSocket> Accept() noexcept;

    // Non-blocking connect to dst, source-bound to bind_addr and egress-pinned to egress_iface
    // (SO_BINDTODEVICE on Linux, IP_BOUND_IF on macOS). Returns the socket mid-handshake — EINPROGRESS
    // is success here; the caller watches it writable then checks SoError(). nullopt only on immediate
    // failure (socket/bind/pin/connect-other-than-EINPROGRESS).
    [[nodiscard]] static std::optional<TcpSocket> Connect(const IpEndpoint& dst, const IpAddress& bind_addr,
                                                          std::string_view egress_iface) noexcept;

    [[nodiscard]] IoResult Read(std::span<std::byte> out) noexcept;        // recv; SIGPIPE-safe
    [[nodiscard]] IoResult Write(std::span<const std::byte> in) noexcept;  // send(MSG_NOSIGNAL on Linux)

    [[nodiscard]] int Fd() const noexcept { return fd_; }
    [[nodiscard]] uint16_t LocalPort() const noexcept;  // getsockname; 0 on failure
    [[nodiscard]] int SoError() const noexcept;         // getsockopt(SO_ERROR): 0 = connected

    TcpSocket(TcpSocket&&) noexcept;
    TcpSocket& operator=(TcpSocket&&) noexcept;
    ~TcpSocket() noexcept;  // close(fd)

private:
    explicit TcpSocket(int fd) noexcept : fd_{fd} {}

    void Close() noexcept;

    Logger logger_{"TcpSocket"};
    int fd_ = -1;
};

} // namespace reflector
```

- [ ] **Step 4: Write `src/reflector/tcp_socket.cpp` with Listen + lifecycle + LocalPort + SoError
  implemented; leave Accept/Connect/Read/Write as compiling stubs.** The stubs return failure
  results so the file links; Tasks 2.3–2.4 replace them with real bodies and their own tests. Mirror
  `UdpSocket`'s move/Close idioms and `raw_socket.cpp`'s setsockopt/getsockname style. SIGPIPE-safety
  is set once at creation on macOS (`SO_NOSIGPIPE`) and per-send on Linux (`MSG_NOSIGNAL`, in Task
  2.4); a small `Configure` helper applies the per-socket options shared by listen/accept/connect:

```cpp
#include "tcp_socket.h"

#include "error.h"

#include <cerrno>
#include <fcntl.h>
#include <format>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#if !defined(__APPLE__) && !defined(__linux__)
#error "TcpSocket only supports macOS and Linux"
#endif

namespace reflector {

namespace {

// On macOS, suppress SIGPIPE per-socket at creation (no MSG_NOSIGNAL flag exists there); on Linux
// MSG_NOSIGNAL is passed per send() instead, so this is a no-op. Returns false on failure.
[[nodiscard]] bool SuppressSigpipe(int fd) noexcept {
#if defined(__APPLE__)
    const int on = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == 0;
#else
    (void)fd;
    return true;
#endif
}

// accept4(SOCK_NONBLOCK) gives a non-blocking fd in one syscall on Linux; macOS lacks it, so set
// O_NONBLOCK with fcntl after accept. Used only by Accept (Task 2.3).
[[nodiscard]] bool SetNonBlocking(int fd) noexcept {
    const auto flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return (flags & O_NONBLOCK) != 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace

std::optional<TcpSocket> TcpSocket::Listen(const IpAddress& bind_addr) noexcept {
    const int domain = bind_addr.IsV6() ? AF_INET6 : AF_INET;
#if defined(__linux__)
    const int fd = ::socket(domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
    const int fd = ::socket(domain, SOCK_STREAM, 0);
#endif
    if (fd < 0) {
        Logger logger{"TcpSocket"};
        logger.Error("Cannot open TCP socket: {}", Error::FromErrno());
        return std::nullopt;
    }

    TcpSocket sock{fd};  // owns fd from here; any early return closes it via the destructor

#if defined(__APPLE__)
    if (!SetNonBlocking(fd)) {
        sock.logger_.Error("Cannot make listen socket non-blocking: {}", Error::FromErrno());
        return std::nullopt;
    }
#endif
    if (!SuppressSigpipe(fd)) {
        sock.logger_.Error("Cannot set SO_NOSIGPIPE: {}", Error::FromErrno());
        return std::nullopt;
    }

    const int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        sock.logger_.Error("Cannot set SO_REUSEADDR: {}", Error::FromErrno());
        return std::nullopt;
    }

    sockaddr_storage storage{};
    const socklen_t length = bind_addr.ToSockaddr(storage, /*port=*/0);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
        sock.logger_.Error("Cannot bind TCP listener to {}: {}", bind_addr, Error::FromErrno());
        return std::nullopt;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        sock.logger_.Error("Cannot listen on {}: {}", bind_addr, Error::FromErrno());
        return std::nullopt;
    }

    sock.logger_.SetName(std::format("TcpSocket:{}", fd));
    sock.logger_.Debug("Listening on {}:{}", bind_addr, sock.LocalPort());
    return sock;
}

std::optional<TcpSocket> TcpSocket::Accept() noexcept {
    // Implemented in Task 2.3.
    return std::nullopt;
}

std::optional<TcpSocket> TcpSocket::Connect(const IpEndpoint&, const IpAddress&,
                                            std::string_view) noexcept {
    // Implemented in Task 2.4.
    return std::nullopt;
}

TcpSocket::IoResult TcpSocket::Read(std::span<std::byte>) noexcept {
    // Implemented in Task 2.4.
    return IoResult{.n = 0, .status = IoStatus::Error};
}

TcpSocket::IoResult TcpSocket::Write(std::span<const std::byte>) noexcept {
    // Implemented in Task 2.4.
    return IoResult{.n = 0, .status = IoStatus::Error};
}

uint16_t TcpSocket::LocalPort() const noexcept {
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
    if (fd_ < 0 || getsockname(fd_, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        return 0;
    }
    if (storage.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in*>(&storage)->sin_port);
}

int TcpSocket::SoError() const noexcept {
    int err = 0;
    socklen_t length = sizeof(err);
    if (fd_ < 0 || getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &length) != 0) {
        return errno;
    }
    return err;
}

void TcpSocket::Close() noexcept {
    if (fd_ >= 0) {
        logger_.Debug("Closing TCP socket fd {}", fd_);
        close(fd_);
        fd_ = -1;
    }
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
        : logger_{std::move(other.logger_)}
        , fd_{std::exchange(other.fd_, -1)} {}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    Close();
    logger_ = std::move(other.logger_);
    fd_ = std::exchange(other.fd_, -1);
    return *this;
}

TcpSocket::~TcpSocket() noexcept {
    Close();
}

} // namespace reflector
```

- [ ] **Step 5: Build and run the Task-2.2 tests; confirm PASS.** Only the `Listen`/lifecycle tests
  exist so far — Accept/Connect/Read/Write are stubs, not yet tested.

```sh
cmake --build build
ctest --test-dir build -R 'TcpSocketTest' --output-on-failure
```

  Expected: all six `unit.TcpSocketTest.*` cases pass (the stubbed methods aren't called yet).

- [ ] **Step 6: Commit.**

```sh
git add src/reflector/tcp_socket.h src/reflector/tcp_socket.cpp tests/tcp_socket_test.cpp \
        src/reflector/CMakeLists.txt tests/CMakeLists.txt
git commit -m "tcp_socket: add non-blocking listening socket RAII"
```

### Task 2.3: Accept — accept a real loopback client

**Files**
- Modify: `tests/tcp_socket_test.cpp` (append accept tests + a small connect helper)
- Modify: `src/reflector/tcp_socket.cpp` (implement `Accept`, replacing the Task-2.2 stub)

- [ ] **Step 1: Add the failing accept tests.** To connect a real client without `TcpSocket::Connect`
  (which is Task 2.4 and needs egress-pin privilege), the test opens a plain blocking
  `127.0.0.1` client fd with the libc `connect` against the listener's `LocalPort`. `EAGAIN`
  on an idle listener returns `nullopt`; after a client connects, `Accept` returns a non-blocking
  connected socket. Append to `tests/tcp_socket_test.cpp` (the helper uses `<arpa/inet.h>` /
  `<sys/socket.h>` — add those includes at the top of the file):

```cpp
// Add near the top of tcp_socket_test.cpp, with the other includes:
//   #include <arpa/inet.h>
//   #include <netinet/in.h>
//   #include <sys/socket.h>
//   #include <unistd.h>

namespace {

// Opens a raw blocking loopback client fd and connects it to 127.0.0.1:port. Returns -1 on
// failure (the caller ASSERTs). Used to drive Accept without TcpSocket::Connect (Task 2.4),
// which needs egress-pin privilege.
int ConnectRawLoopbackClient(uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

TEST(TcpSocketTest, AcceptReturnsNulloptWhenNoPendingClient) {
    auto listener = ListenLoopback();
    EXPECT_FALSE(listener.Accept().has_value());  // EAGAIN -> nullopt
}

TEST(TcpSocketTest, AcceptReturnsConnectedNonBlockingClient) {
    auto listener = ListenLoopback();
    const int client_fd = ConnectRawLoopbackClient(listener.LocalPort());
    ASSERT_GE(client_fd, 0);

    std::optional<TcpSocket> accepted;
    for (int i = 0; i < 100 && !accepted; ++i) {
        accepted = listener.Accept();
    }
    ASSERT_TRUE(accepted.has_value());
    EXPECT_GE(accepted->Fd(), 0);

    const auto flags = fcntl(accepted->Fd(), F_GETFL, 0);
    ASSERT_GE(flags, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0);  // accepted socket must be non-blocking

    ::close(client_fd);
}
```

- [ ] **Step 2: Build and run; confirm FAIL.** `Accept` is still the stub returning `nullopt`, so the
  second case fails (`accepted` never becomes engaged).

```sh
cmake --build build
ctest --test-dir build -R 'TcpSocketTest.Accept' --output-on-failure
```

  Expected: `unit.TcpSocketTest.AcceptReturnsConnectedNonBlockingClient` **FAILS** at
  `ASSERT_TRUE(accepted.has_value())`; `AcceptReturnsNulloptWhenNoPendingClient` passes (the stub
  happens to match it, which is fine).

- [ ] **Step 3: Implement `Accept`.** Replace the stub body in `src/reflector/tcp_socket.cpp`. Use
  `accept4(SOCK_NONBLOCK)` on Linux; `accept` + the `SetNonBlocking` helper on macOS. Re-apply
  `SuppressSigpipe` on the accepted fd (macOS `SO_NOSIGPIPE` is not inherited). EAGAIN -> `nullopt`
  quietly; other errors log and return `nullopt`:

```cpp
std::optional<TcpSocket> TcpSocket::Accept() noexcept {
#if defined(__linux__)
    const int client_fd = accept4(fd_, nullptr, nullptr, SOCK_NONBLOCK);
#else
    const int client_fd = accept(fd_, nullptr, nullptr);
#endif
    if (client_fd < 0) {
        if (!IsWouldBlockErrno(errno)) {
            logger_.Error("Cannot accept connection: {}", Error::FromErrno());
        }
        return std::nullopt;
    }

    TcpSocket client{client_fd};
#if defined(__APPLE__)
    if (!SetNonBlocking(client_fd)) {
        client.logger_.Error("Cannot make accepted socket non-blocking: {}", Error::FromErrno());
        return std::nullopt;
    }
#endif
    if (!SuppressSigpipe(client_fd)) {
        client.logger_.Error("Cannot set SO_NOSIGPIPE on accepted socket: {}", Error::FromErrno());
        return std::nullopt;
    }
    client.logger_.SetName(std::format("TcpSocket:{}", client_fd));
    return client;
}
```

  This needs `IsWouldBlockErrno` from `error.h` (already included) — confirm the include is present.

- [ ] **Step 4: Build and run; confirm PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'TcpSocketTest.Accept' --output-on-failure
```

  Expected: both accept cases pass.

- [ ] **Step 5: Commit.**

```sh
git add src/reflector/tcp_socket.cpp tests/tcp_socket_test.cpp
git commit -m "tcp_socket: implement non-blocking accept"
```

### Task 2.4: Read / Write over a real loopback pair (partial, EAGAIN, peer-close)

**Files**
- Modify: `tests/tcp_socket_test.cpp` (append read/write tests)
- Modify: `src/reflector/tcp_socket.cpp` (implement `Read` and `Write`, replacing the stubs)

- [ ] **Step 1: Add the failing read/write tests.** These accept a real client (reusing
  `ConnectRawLoopbackClient` + the accept loop from Task 2.3) and move bytes both ways through
  `TcpSocket::Read`/`Write`, then assert the EAGAIN and peer-close statuses. Append to
  `tests/tcp_socket_test.cpp`:

```cpp
namespace {

// Accepts one client on `listener` after a raw loopback client connects; returns the accepted
// TcpSocket and writes the raw client fd to *client_fd_out. ASSERTs on failure.
std::optional<TcpSocket> AcceptOne(TcpSocket& listener, int* client_fd_out) {
    const int client_fd = ConnectRawLoopbackClient(listener.LocalPort());
    if (client_fd < 0) {
        ADD_FAILURE() << "raw client connect failed";
        return std::nullopt;
    }
    *client_fd_out = client_fd;
    std::optional<TcpSocket> accepted;
    for (int i = 0; i < 100 && !accepted; ++i) {
        accepted = listener.Accept();
    }
    return accepted;
}

} // namespace

TEST(TcpSocketTest, WriteThenPeerReadsSameBytes) {
    auto listener = ListenLoopback();
    int client_fd = -1;
    auto accepted = AcceptOne(listener, &client_fd);
    ASSERT_TRUE(accepted.has_value());

    const std::array<std::byte, 5> payload{
        std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
    const auto written = accepted->Write(payload);
    EXPECT_EQ(written.status, TcpSocket::IoStatus::Ok);
    ASSERT_EQ(written.n, payload.size());

    std::array<std::byte, 5> received{};
    const auto got = ::recv(client_fd, received.data(), received.size(), 0);
    ASSERT_EQ(got, static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(received, payload);

    ::close(client_fd);
}

TEST(TcpSocketTest, ReadReceivesBytesFromPeer) {
    auto listener = ListenLoopback();
    int client_fd = -1;
    auto accepted = AcceptOne(listener, &client_fd);
    ASSERT_TRUE(accepted.has_value());

    const std::array<std::byte, 3> payload{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    ASSERT_EQ(::send(client_fd, payload.data(), payload.size(), 0),
              static_cast<ssize_t>(payload.size()));

    std::array<std::byte, 8> buffer{};
    TcpSocket::IoResult read{};
    for (int i = 0; i < 100; ++i) {
        read = accepted->Read(buffer);
        if (read.n > 0) {
            break;
        }
    }
    ASSERT_EQ(read.status, TcpSocket::IoStatus::Ok);
    ASSERT_EQ(read.n, payload.size());
    EXPECT_EQ(std::span(buffer).first(read.n), std::span<const std::byte>(payload));

    ::close(client_fd);
}

TEST(TcpSocketTest, ReadReportsWouldBlockWhenNoData) {
    auto listener = ListenLoopback();
    int client_fd = -1;
    auto accepted = AcceptOne(listener, &client_fd);
    ASSERT_TRUE(accepted.has_value());

    std::array<std::byte, 8> buffer{};
    const auto read = accepted->Read(buffer);  // nothing sent yet -> EAGAIN
    EXPECT_EQ(read.status, TcpSocket::IoStatus::WouldBlock);
    EXPECT_EQ(read.n, 0u);

    ::close(client_fd);
}

TEST(TcpSocketTest, ReadReportsClosedAfterPeerCloses) {
    auto listener = ListenLoopback();
    int client_fd = -1;
    auto accepted = AcceptOne(listener, &client_fd);
    ASSERT_TRUE(accepted.has_value());

    ::close(client_fd);  // peer closes -> our read sees EOF (0 bytes)

    std::array<std::byte, 8> buffer{};
    TcpSocket::IoResult read{};
    for (int i = 0; i < 100; ++i) {
        read = accepted->Read(buffer);
        if (read.status != TcpSocket::IoStatus::WouldBlock) {
            break;
        }
    }
    EXPECT_EQ(read.status, TcpSocket::IoStatus::Closed);
    EXPECT_EQ(read.n, 0u);
}

TEST(TcpSocketTest, WriteReportsClosedAfterPeerCloses) {
    auto listener = ListenLoopback();
    int client_fd = -1;
    auto accepted = AcceptOne(listener, &client_fd);
    ASSERT_TRUE(accepted.has_value());

    ::close(client_fd);  // peer gone; a write must surface Closed/Error, never SIGPIPE-kill us

    // The first write may succeed into the local send buffer and only the second sees the RST,
    // so loop until the write side reports the peer is gone.
    const std::array<std::byte, 4> payload{
        std::byte{'d'}, std::byte{'a'}, std::byte{'t'}, std::byte{'a'}};
    TcpSocket::IoResult written{};
    for (int i = 0; i < 1000; ++i) {
        written = accepted->Write(payload);
        if (written.status == TcpSocket::IoStatus::Closed ||
            written.status == TcpSocket::IoStatus::Error) {
            break;
        }
    }
    EXPECT_TRUE(written.status == TcpSocket::IoStatus::Closed ||
                written.status == TcpSocket::IoStatus::Error);
}
```

- [ ] **Step 2: Build and run; confirm FAIL.** `Read`/`Write` are stubs returning
  `IoStatus::Error` with `n = 0`, so every byte-moving and status assertion fails.

```sh
cmake --build build
ctest --test-dir build -R 'TcpSocketTest.(Read|Write)' --output-on-failure
```

  Expected: `WriteThenPeerReadsSameBytes`, `ReadReceivesBytesFromPeer`, `ReadReportsWouldBlockWhenNoData`,
  and `ReadReportsClosedAfterPeerCloses` **FAIL** (stub returns Error/0).

- [ ] **Step 3: Implement `Read` and `Write`.** Replace both stubs in `src/reflector/tcp_socket.cpp`.
  A `recv` of 0 is peer-close -> `Closed`; EAGAIN -> `WouldBlock`; `ECONNRESET`/`EPIPE` map to
  `Closed`; other errors -> `Error`. `Write` uses `MSG_NOSIGNAL` on Linux (macOS relies on the
  `SO_NOSIGPIPE` set at creation). Add a small `errno`->status mapper to share the logic:

```cpp
// Place in the anonymous namespace alongside SuppressSigpipe / SetNonBlocking:
[[nodiscard]] TcpSocket::IoStatus StatusFromErrno(int err) noexcept {
    using IoStatus = TcpSocket::IoStatus;
    if (IsWouldBlockErrno(err)) {
        return IoStatus::WouldBlock;
    }
    // A peer that vanished mid-stream is a normal close to the proxy, not a hard error.
    if (err == ECONNRESET || err == EPIPE || err == ENOTCONN) {
        return IoStatus::Closed;
    }
    return IoStatus::Error;
}
```

```cpp
TcpSocket::IoResult TcpSocket::Read(std::span<std::byte> out) noexcept {
    ssize_t n;
    do {
        n = recv(fd_, out.data(), out.size(), 0);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        return IoResult{.n = static_cast<size_t>(n), .status = IoStatus::Ok};
    }
    if (n == 0) {
        return IoResult{.n = 0, .status = IoStatus::Closed};  // orderly peer shutdown
    }
    const auto status = StatusFromErrno(errno);
    if (status == IoStatus::Error) {
        logger_.Error("Cannot read from TCP socket: {}", Error::FromErrno());
    }
    return IoResult{.n = 0, .status = status};
}

TcpSocket::IoResult TcpSocket::Write(std::span<const std::byte> in) noexcept {
#if defined(__linux__)
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;  // SO_NOSIGPIPE set at creation covers SIGPIPE on macOS
#endif
    ssize_t n;
    do {
        n = send(fd_, in.data(), in.size(), flags);
    } while (n < 0 && errno == EINTR);
    if (n >= 0) {
        return IoResult{.n = static_cast<size_t>(n), .status = IoStatus::Ok};  // may be a short write
    }
    const auto status = StatusFromErrno(errno);
    if (status == IoStatus::Error) {
        logger_.Error("Cannot write to TCP socket: {}", Error::FromErrno());
    }
    return IoResult{.n = 0, .status = status};
}
```

- [ ] **Step 4: Build and run; confirm PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'TcpSocketTest' --output-on-failure
```

  Expected: every `TcpSocketTest.*` case (Listen, move, Accept, Read, Write) passes, with no ASan/
  UBSan diagnostics.

- [ ] **Step 5: Commit.**

```sh
git add src/reflector/tcp_socket.cpp tests/tcp_socket_test.cpp
git commit -m "tcp_socket: implement sigpipe-safe read and write"
```

### Task 2.5: Connect — non-blocking, source-bound, egress-pinned (behind RequiresRoot)

**Files**
- Modify: `tests/tcp_socket_test.cpp` (append a `RequiresRoot` fixture + connect tests)
- Modify: `src/reflector/tcp_socket.cpp` (implement `Connect`, replacing the stub)

- [ ] **Step 1: Add the failing connect tests behind a RequiresRoot fixture.** `Connect`
  egress-pins with `SO_BINDTODEVICE` (Linux) / `IP_BOUND_IF` (macOS), which needs CAP_NET_RAW/root —
  so the fixture name contains `RequiresRoot` (gets the `root` label) and `GTEST_SKIP`s at `SetUp`
  when the privilege is absent, using the existing `HasPacketCapturePrivileges()` probe from
  `test_helpers.h` (it exercises the same privilege class). The success path drives a real
  loopback handshake pinned to the loopback interface; the immediate-failure path uses a bogus
  interface name. Append to `tests/tcp_socket_test.cpp`:

```cpp
class TcpSocketConnectRequiresRootTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "needs CAP_NET_RAW/root for SO_BINDTODEVICE / IP_BOUND_IF egress pin";
        }
    }
};

TEST_F(TcpSocketConnectRequiresRootTest, ConnectCompletesHandshakeToLoopbackListener) {
    auto listener = ListenLoopback();
    const IpEndpoint dst{IpAddress::LoopbackV4(), listener.LocalPort()};

    auto client = TcpSocket::Connect(dst, IpAddress::LoopbackV4(),
                                     std::string{LoopbackInterface()});
    ASSERT_TRUE(client.has_value()) << "non-blocking connect should return mid-handshake";

    // Accept the pending connection on the listener side.
    std::optional<TcpSocket> accepted;
    for (int i = 0; i < 100 && !accepted; ++i) {
        accepted = listener.Accept();
    }
    ASSERT_TRUE(accepted.has_value());

    // Spin until the non-blocking connect resolves; SoError() == 0 means connected.
    int so_error = -1;
    for (int i = 0; i < 1000; ++i) {
        so_error = client->SoError();
        if (so_error == 0) {
            break;
        }
    }
    EXPECT_EQ(so_error, 0);
}

TEST_F(TcpSocketConnectRequiresRootTest, ConnectMovesBytesEndToEnd) {
    auto listener = ListenLoopback();
    const IpEndpoint dst{IpAddress::LoopbackV4(), listener.LocalPort()};

    auto client = TcpSocket::Connect(dst, IpAddress::LoopbackV4(),
                                     std::string{LoopbackInterface()});
    ASSERT_TRUE(client.has_value());

    std::optional<TcpSocket> accepted;
    for (int i = 0; i < 100 && !accepted; ++i) {
        accepted = listener.Accept();
    }
    ASSERT_TRUE(accepted.has_value());
    for (int i = 0; i < 1000 && client->SoError() != 0; ++i) {
    }
    ASSERT_EQ(client->SoError(), 0);

    const std::array<std::byte, 4> payload{
        std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
    const auto written = client->Write(payload);
    ASSERT_EQ(written.status, TcpSocket::IoStatus::Ok);
    ASSERT_EQ(written.n, payload.size());

    std::array<std::byte, 8> buffer{};
    TcpSocket::IoResult read{};
    for (int i = 0; i < 1000; ++i) {
        read = accepted->Read(buffer);
        if (read.n > 0) {
            break;
        }
    }
    ASSERT_EQ(read.status, TcpSocket::IoStatus::Ok);
    ASSERT_EQ(read.n, payload.size());
    EXPECT_EQ(std::span(buffer).first(read.n), std::span<const std::byte>(payload));
}

TEST_F(TcpSocketConnectRequiresRootTest, ConnectFailsImmediatelyOnUnknownEgressInterface) {
    auto listener = ListenLoopback();
    const IpEndpoint dst{IpAddress::LoopbackV4(), listener.LocalPort()};

    EXPECT_FALSE(TcpSocket::Connect(dst, IpAddress::LoopbackV4(),
                                    "nonexistent-iface-xyz").has_value());
}
```

- [ ] **Step 2: Build and run the root-labelled cases; confirm FAIL (or SKIP unprivileged).** On a
  privileged box the cases run and fail against the stub (`Connect` returns `nullopt`); on an
  unprivileged box they are skipped (still a clean run). Run explicitly with the `root` label so the
  cases are not filtered out:

```sh
cmake --build build
ctest --test-dir build -L root -R 'TcpSocketConnectRequiresRootTest' --output-on-failure
```

  Expected (privileged): `ConnectCompletesHandshakeToLoopbackListener` and `ConnectMovesBytesEndToEnd`
  **FAIL** at `ASSERT_TRUE(client.has_value())`; `ConnectFailsImmediatelyOnUnknownEgressInterface`
  passes (stub returns nullopt). Expected (unprivileged): all three **SKIPPED**.

- [ ] **Step 3: Implement `Connect`.** Replace the stub in `src/reflector/tcp_socket.cpp`. Create a
  non-blocking socket, apply SIGPIPE-safety, bind the source address, egress-pin per platform, then
  `connect`; `EINPROGRESS` is success (handshake in flight). The egress-pin mirrors
  `UdpSocket::SetInterface`. Add `<net/if.h>` is already included for `if_nametoindex`:

```cpp
std::optional<TcpSocket> TcpSocket::Connect(const IpEndpoint& dst, const IpAddress& bind_addr,
                                            std::string_view egress_iface) noexcept {
    const int domain = bind_addr.IsV6() ? AF_INET6 : AF_INET;
#if defined(__linux__)
    const int fd = ::socket(domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
    const int fd = ::socket(domain, SOCK_STREAM, 0);
#endif
    if (fd < 0) {
        Logger logger{"TcpSocket"};
        logger.Error("Cannot open TCP socket for connect: {}", Error::FromErrno());
        return std::nullopt;
    }

    TcpSocket sock{fd};  // RAII owns fd; any early return closes it
#if defined(__APPLE__)
    if (!SetNonBlocking(fd)) {
        sock.logger_.Error("Cannot make connect socket non-blocking: {}", Error::FromErrno());
        return std::nullopt;
    }
#endif
    if (!SuppressSigpipe(fd)) {
        sock.logger_.Error("Cannot set SO_NOSIGPIPE on connect socket: {}", Error::FromErrno());
        return std::nullopt;
    }

    // Source-bind so the upstream appears from target_if's address (reproducing the router NAT).
    sockaddr_storage src_storage{};
    const socklen_t src_length = bind_addr.ToSockaddr(src_storage, /*port=*/0);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&src_storage), src_length) != 0) {
        sock.logger_.Error("Cannot source-bind connect to {}: {}", bind_addr, Error::FromErrno());
        return std::nullopt;
    }

    // Egress-pin to target_if so a host route toward the client subnet can't steal the upstream.
    const unsigned idx = if_nametoindex(std::string{egress_iface}.c_str());
    if (idx == 0) {
        sock.logger_.Error("Cannot resolve egress interface \"{}\": {}", egress_iface,
                           Error::FromErrno());
        return std::nullopt;
    }
#if defined(__linux__)
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, egress_iface.data(),
                   static_cast<socklen_t>(egress_iface.size())) != 0) {
        sock.logger_.Error("Cannot SO_BINDTODEVICE \"{}\": {}", egress_iface, Error::FromErrno());
        return std::nullopt;
    }
#else
    const int level = bind_addr.IsV6() ? IPPROTO_IPV6 : IPPROTO_IP;
    const int option = bind_addr.IsV6() ? IPV6_BOUND_IF : IP_BOUND_IF;
    if (setsockopt(fd, level, option, &idx, sizeof(idx)) != 0) {
        sock.logger_.Error("Cannot IP_BOUND_IF \"{}\" (index {}): {}", egress_iface, idx,
                           Error::FromErrno());
        return std::nullopt;
    }
#endif

    sockaddr_storage dst_storage{};
    const socklen_t dst_length = dst.addr.ToSockaddr(dst_storage, dst.port);
    if (connect(fd, reinterpret_cast<const sockaddr*>(&dst_storage), dst_length) != 0
            && errno != EINPROGRESS) {
        sock.logger_.Error("Cannot connect to {}: {}", dst, Error::FromErrno());
        return std::nullopt;
    }

    sock.logger_.SetName(std::format("TcpSocket:{}", fd));
    sock.logger_.Debug("Connecting to {} from {} via {}", dst, bind_addr, egress_iface);
    return sock;
}
```

  `SO_BINDTODEVICE` needs a NUL-terminated name of length `egress_iface.size()`; the
  `egress_iface.data()` + size form matches what the kernel reads. `UdpSocket::SetInterface` checks
  `interface.size() + 1 > IF_NAMESIZE` — `if_nametoindex` already failing on a bogus name covers the
  unknown-interface path here, and an over-long name fails `if_nametoindex` too, so no separate
  length guard is needed.

- [ ] **Step 4: Build and run; confirm PASS (or SKIP unprivileged).**

```sh
cmake --build build
ctest --test-dir build -L root -R 'TcpSocketConnectRequiresRootTest' --output-on-failure
```

  Expected (privileged): all three connect cases pass. Expected (unprivileged): all three skipped.

- [ ] **Step 5: Run the full unit suite to confirm nothing regressed and sanitizers are clean.**
  First confirm the sanitizer flag is on (the cache can silently go stale), then run the `unit`
  label (which excludes `RequiresRoot` cases):

```sh
grep REFLECTOR_SANITIZE build/CMakeCache.txt
ctest --test-dir build -L unit --output-on-failure
```

  Expected: `REFLECTOR_SANITIZE:BOOL=ON`; every `unit.*` case passes, including all
  `IpEndpointTest.*` and the non-root `TcpSocketTest.*` cases, with no ASan/UBSan reports.

- [ ] **Step 6: Commit.**

```sh
git add src/reflector/tcp_socket.cpp tests/tcp_socket_test.cpp
git commit -m "tcp_socket: implement bound egress-pinned non-blocking connect"
```

## Commit 3: http_message — incremental HTTP/1.1 framing and authority rewrite

This commit adds `src/reflector/http_message.{h,cpp}`: the pure (no-socket) HTTP layer the DIAL proxy needs. Two pieces, both data-only and unit-tested against the captured LG-TV messages:

1. `RewriteAuthority(text, from, to)` — substitutes one authority (`addr:port`, formatted via the `std::formatter<IpEndpoint>` from Commit 2) for another inside a header value or LOCATION line, leaving non-matching text untouched.
2. `HttpFraming` — a `Feed`-driven incremental parser that accumulates the header block (bounded by `max_header_bytes`), rewrites a fixed case-insensitive header set via a `HeaderRewrite` callback (Request: `Host`; Response: `Application-URL`, `Location`), determines body framing (`Content-Length` / `Transfer-Encoding: chunked` / bodyless), forwards the body verbatim, and loops for keep-alive.

It depends only on `reflector::IpEndpoint` (Commit 2, `src/reflector/ip_endpoint.h`) and standard headers — no sockets, no reactor. It is the third commit; Commit 1 (write-interest) and Commit 2 (`tcp_socket` + `ip_endpoint`) precede it, so `src/reflector/ip_endpoint.h` already exists when this commit builds.

### Task 3.1: RewriteAuthority — header/body-agnostic authority substitution

The smallest primitive: given `text` (one header value or a LOCATION line), replace every occurrence of the formatted authority of `from` (e.g. `10.1.3.80:1461`) with the formatted authority of `to` (e.g. `192.168.1.2:54321`) and return the rewritten copy. Host matching is literal (the authority is compared byte-for-byte against the formatted `from`); a `text` that does not contain `from`'s authority is returned unchanged. Used by both the SSDP LOCATION path (Commit 5) and `HttpFraming` (this commit).

**Files**
- Create: `src/reflector/http_message.h`
- Create: `src/reflector/http_message.cpp`
- Modify: `src/reflector/CMakeLists.txt` (add `http_message.cpp` to the `reflector` library source list, after `frame_builder.cpp` to keep the list sorted)
- Create: `tests/http_message_test.cpp`
- Modify: `tests/CMakeLists.txt` (add `http_message_test.cpp` to the `reflector_test` source list, after `frame_builder_test.cpp`)

- [ ] **Step 1: Write the failing RewriteAuthority test.** Create `tests/http_message_test.cpp` with the header include, a `Bytes`/`Text` helper, and the first cases. (Later tasks append `TEST`s to this same file.)

```cpp
#include "reflector/http_message.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"

using namespace reflector;

namespace {

// A device endpoint as captured: the LG TV on the IoT segment.
IpEndpoint Device(uint16_t port) {
    return IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), port};
}

// The reflector authority advertised to the client (a source_if address + an ephemeral listener port).
IpEndpoint Reflector(uint16_t port) {
    return IpEndpoint{IpAddress::FromV4Bytes(192, 168, 1, 2), port};
}

std::span<const std::byte> AsBytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

// Decodes a byte buffer back to a string for byte-exact comparison of forwarded output.
std::string Decode(const std::vector<std::byte>& bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (const std::byte b : bytes) {
        out.push_back(static_cast<char>(b));
    }
    return out;
}

} // namespace

TEST(RewriteAuthorityTest, SwapsMatchingAuthority) {
    // A captured Application-URL value: the absolute REST URL on the TV's stable REST port.
    const std::string before = "http://10.1.3.80:36866/apps";
    const std::string after = RewriteAuthority(before, Device(36866), Reflector(54321));
    EXPECT_EQ(after, "http://192.168.1.2:54321/apps");
}

TEST(RewriteAuthorityTest, RewritesEveryOccurrence) {
    // Defensive: if an authority appears twice in one value, both are swapped.
    const std::string before = "http://10.1.3.80:1461/ http://10.1.3.80:1461/desc.xml";
    const std::string after = RewriteAuthority(before, Device(1461), Reflector(40000));
    EXPECT_EQ(after, "http://192.168.1.2:40000/ http://192.168.1.2:40000/desc.xml");
}

TEST(RewriteAuthorityTest, LeavesNonMatchingTextAlone) {
    // A different port (REST vs description) must not be touched by a description rewrite.
    const std::string before = "http://10.1.3.80:36866/apps";
    EXPECT_EQ(RewriteAuthority(before, Device(1461), Reflector(40000)), before);
    // A bare host with no port never matches the formatted authority.
    const std::string host_only = "http://10.1.3.80/apps";
    EXPECT_EQ(RewriteAuthority(host_only, Device(36866), Reflector(54321)), host_only);
}
```

- [ ] **Step 2: Build the test and watch it fail to compile.** Run `./cmake_gen.sh` (only if `build/` is absent or stale), then add the new files to CMake (Step 3) before building — the test cannot compile until `http_message.h` exists. Expected fail: `fatal error: 'reflector/http_message.h' file not found`. (Confirm `grep REFLECTOR_SANITIZE build/CMakeCache.txt` shows `ON`.)

- [ ] **Step 3: Register the source and test files in CMake.** In `src/reflector/CMakeLists.txt` add, immediately after the `frame_builder.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/http_message.cpp
```

In `tests/CMakeLists.txt` add, immediately after the `frame_builder_test.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/http_message_test.cpp
```

- [ ] **Step 4: Write the header with RewriteAuthority and the HttpFraming declaration.** Create `src/reflector/http_message.h`. (HttpFraming members are declared now so the whole class lands in one header; its body framing is implemented across the later tasks.)

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "reflector/ip_endpoint.h"

namespace reflector {

// Replaces the authority `from` (its formatted "addr:port", compared literally) with `to` wherever it
// appears in `text` — one header value or an SSDP LOCATION line. Returns the rewritten copy; `text`
// without `from`'s authority is returned unchanged. Host matching is byte-for-byte against the
// formatted authority, so a host-only or different-port URL is left intact.
[[nodiscard]] std::string RewriteAuthority(std::string_view text, const IpEndpoint& from, const IpEndpoint& to);

// Per-direction incremental HTTP/1.1 framing + header rewrite. Feed bytes; it appends forwardable
// bytes (headers rewritten, body verbatim) to `out`. Header-block accumulation is bounded by
// max_header_bytes (an oversized header block -> Error -> caller closes the connection). Handles
// Content-Length, Transfer-Encoding: chunked (chunk DATA is opaque/forwarded verbatim — only the
// chunk-size lines are parsed to find the terminating 0-chunk), and bodyless messages; loops for
// keep-alive across messages on the same connection.
class HttpFraming {
public:
    enum class Side : uint8_t { Request, Response };
    enum class Status : uint8_t { NeedMore, Error };

    // Called once per rewritable header (Request: Host; Response: Application-URL, Location — header
    // name matched case-insensitively). `found` is the authority parsed from that header's value.
    // Return the replacement authority, or nullopt to leave the header unchanged. Supplied by DialProxy.
    using HeaderRewrite = std::function<std::optional<IpEndpoint>(Side side, const IpEndpoint& found)>;

    HttpFraming(Side side, size_t max_header_bytes, HeaderRewrite rewrite);

    // Consumes `in`, appending forwardable bytes to `out`. NeedMore = consumed cleanly, awaiting more
    // bytes (the normal return); Error = a malformed message or an oversized header block — the caller
    // closes the connection.
    [[nodiscard]] Status Feed(std::span<const std::byte> in, std::vector<std::byte>& out);

private:
    // Two phases: accumulating the start line + header block, or streaming a body of a known shape.
    enum class Phase : uint8_t { Header, BodyContentLength, BodyChunked, BodyChunkedDone };

    // Drains `header_` once the blank-line terminator is seen: parses framing, runs the rewrites, and
    // appends the rewritten header block to `out`. Returns false on a malformed/over-cap header block.
    [[nodiscard]] bool FinishHeaderBlock(std::vector<std::byte>& out);
    // Rewrites the matched headers in `block` (a mutable copy of the raw header text) in place.
    void RewriteHeaders(std::string& block);

    Side side_;
    size_t max_header_bytes_;
    HeaderRewrite rewrite_;

    Phase phase_ = Phase::Header;
    std::string header_;            // accumulated start line + header bytes for the in-flight message
    size_t body_remaining_ = 0;     // Content-Length bytes still to forward
    size_t chunk_remaining_ = 0;    // bytes of the current chunk's DATA (+CRLF) still to forward
    std::string chunk_size_line_;   // partial chunk-size line being accumulated in the chunked body
};

} // namespace reflector
```

- [ ] **Step 5: Implement RewriteAuthority in the cpp.** Create `src/reflector/http_message.cpp` with just enough to pass Task 3.1 (HttpFraming follows in later tasks):

```cpp
#include "reflector/http_message.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <format>
#include <utility>

namespace reflector {

std::string RewriteAuthority(std::string_view text, const IpEndpoint& from, const IpEndpoint& to) {
    const std::string from_authority = std::format("{}", from);
    const std::string to_authority = std::format("{}", to);
    std::string out;
    out.reserve(text.size());
    size_t pos = 0;
    while (true) {
        const size_t hit = text.find(from_authority, pos);
        if (hit == std::string_view::npos) {
            out.append(text.substr(pos));
            return out;
        }
        out.append(text.substr(pos, hit - pos));
        out.append(to_authority);
        pos = hit + from_authority.size();
    }
}

} // namespace reflector
```

- [ ] **Step 6: Build and run the RewriteAuthority cases.** `cmake --build build`, then `ctest --test-dir build -R 'RewriteAuthorityTest' --output-on-failure`. Expected PASS: all three `RewriteAuthorityTest` cases green.

- [ ] **Step 7: Commit.**

```sh
git add src/reflector/http_message.h src/reflector/http_message.cpp src/reflector/CMakeLists.txt \
        tests/http_message_test.cpp tests/CMakeLists.txt
git commit -m "http_message: add RewriteAuthority authority substitution"
```

### Task 3.2: HttpFraming — Content-Length response with Application-URL rewrite

The description-fetch response leg: a `Content-Length`-framed `200 OK` whose `Application-URL` header must be rewritten to the reflector authority while the body is forwarded byte-for-byte. This task lands the header-block accumulation, the `Content-Length` body shape, and the response-side rewrite (`Application-URL`, case-insensitive name).

**Files**
- Modify: `tests/http_message_test.cpp` (append `HttpFramingContentLengthTest` cases)
- Modify: `src/reflector/http_message.cpp` (implement `HttpFraming` ctor, `Feed`, `FinishHeaderBlock`, `RewriteHeaders` for the header + `Content-Length` cases)

- [ ] **Step 1: Write the failing Content-Length test.** Append to `tests/http_message_test.cpp`:

```cpp
namespace {

// A rewrite that swaps the captured TV REST endpoint (10.1.3.80:36866) for a reflector authority, and
// records what authorities it was offered — to assert which headers the framer surfaced.
struct RecordingRewrite {
    std::vector<IpEndpoint> seen;
    std::optional<IpEndpoint> operator()(HttpFraming::Side, const IpEndpoint& found) {
        seen.push_back(found);
        if (found == IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), 36866}) {
            return IpEndpoint{IpAddress::FromV4Bytes(192, 168, 1, 2), 54321};
        }
        return std::nullopt;
    }
};

} // namespace

TEST(HttpFramingContentLengthTest, RewritesApplicationUrlAndForwardsBodyVerbatim) {
    // The captured device-description response: Content-Length framing, an Application-URL header on the
    // REST endpoint, and a relative-only XML body (so the body is forwarded untouched).
    const std::string body =
        "<?xml version=\"1.0\"?>"
        "<root><device><friendlyName>LG TV</friendlyName>"
        "<X_DIALEX_AppsListURL>/WebOS_Dial/apps</X_DIALEX_AppsListURL></device></root>";
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;

    auto rewrite = std::make_shared<RecordingRewrite>();
    HttpFraming framing(HttpFraming::Side::Response, 65536,
                        [rewrite](HttpFraming::Side s, const IpEndpoint& f) { return (*rewrite)(s, f); });

    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(message), out), HttpFraming::Status::NeedMore);

    const std::string expected =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;
    EXPECT_EQ(Decode(out), expected);
    // The framer offered exactly the one rewritable authority it found (Application-URL).
    ASSERT_EQ(rewrite->seen.size(), 1u);
    EXPECT_EQ(rewrite->seen[0], (IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), 36866}));
}

TEST(HttpFramingContentLengthTest, MatchesApplicationUrlHeaderNameCaseInsensitively) {
    const std::string message =
        "HTTP/1.1 200 OK\r\n"
        "application-url: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    RecordingRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Response, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(message), out), HttpFraming::Status::NeedMore);
    EXPECT_NE(Decode(out).find("application-url: http://192.168.1.2:54321/apps\r\n"), std::string::npos);
}

TEST(HttpFramingContentLengthTest, ReassemblesBodySplitAcrossFeeds) {
    // A response delivered in two reads: the framer must hold framing state and forward the body as the
    // bytes arrive, not require the whole message at once.
    const std::string head =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab";
    const std::string tail = "cde";
    RecordingRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Response, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(head), out), HttpFraming::Status::NeedMore);
    EXPECT_EQ(framing.Feed(AsBytes(tail), out), HttpFraming::Status::NeedMore);
    EXPECT_EQ(Decode(out), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde");
}
```

- [ ] **Step 2: Build and watch the link fail.** `cmake --build build`. Expected fail: link error — `undefined reference to reflector::HttpFraming::HttpFraming(...)` / `::Feed(...)` (the methods are declared but not yet defined).

- [ ] **Step 3: Implement the ctor and the framing helpers.** Append to `src/reflector/http_message.cpp` (inside `namespace reflector`). This implements the header phase, `Content-Length` body, and the response-side rewrite; chunked/bodyless/request paths land in later tasks but the code is structured to grow into them without rework.

```cpp
namespace {

constexpr std::string_view CRLF = "\r\n";
constexpr std::string_view HEADER_TERMINATOR = "\r\n\r\n";

// Lowercases an ASCII byte; used for case-insensitive header-name comparison.
char Lower(char c) noexcept { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

// True if `line` begins with the header name `name` (case-insensitive on the name, which includes its
// trailing ':'), so "application-url:" matches "Application-URL:".
bool HeaderNameIs(std::string_view line, std::string_view name) noexcept {
    if (line.size() < name.size()) {
        return false;
    }
    for (size_t i = 0; i < name.size(); ++i) {
        if (Lower(line[i]) != Lower(name[i])) {
            return false;
        }
    }
    return true;
}

// Splits an "addr:port" authority out of a header value's first whitespace-trimmed token containing a
// scheme. Returns the authority substring (host:port) of the first "http://host:port..." in `value`,
// or nullopt when there is no scheme/authority. Only host:port forms with an explicit numeric port are
// parsed — a bare-host or schemeless value yields nullopt and the header is left unchanged.
std::optional<IpEndpoint> ParseAuthority(std::string_view value) {
    constexpr std::string_view SCHEME = "http://";
    const size_t scheme_at = value.find(SCHEME);
    if (scheme_at == std::string_view::npos) {
        return std::nullopt;
    }
    const size_t host_at = scheme_at + SCHEME.size();
    const size_t auth_end = value.find_first_of("/ \t\r", host_at);
    const std::string_view authority =
        value.substr(host_at, auth_end == std::string_view::npos ? std::string_view::npos : auth_end - host_at);
    const size_t colon = authority.rfind(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;  // no explicit port -> nothing this proxy advertises
    }
    const std::string host{authority.substr(0, colon)};
    const auto addr = IpAddress::FromString(host);
    if (!addr) {
        return std::nullopt;
    }
    const std::string_view port_text = authority.substr(colon + 1);
    unsigned port = 0;
    const auto* begin = port_text.data();
    const auto* end = port_text.data() + port_text.size();
    if (std::from_chars(begin, end, port).ec != std::errc{} || port == 0 || port > 0xffff) {
        return std::nullopt;
    }
    return IpEndpoint{*addr, static_cast<uint16_t>(port)};
}

// Trims leading optional whitespace (after the ':') from a header value.
std::string_view TrimLeadingSpace(std::string_view value) noexcept {
    const size_t first = value.find_first_not_of(" \t");
    return first == std::string_view::npos ? std::string_view{} : value.substr(first);
}

} // namespace

HttpFraming::HttpFraming(Side side, size_t max_header_bytes, HeaderRewrite rewrite)
    : side_{side}, max_header_bytes_{max_header_bytes}, rewrite_{std::move(rewrite)} {}

void HttpFraming::RewriteHeaders(std::string& block) {
    // Rewrites the one or two authority headers this side cares about, in place, line by line. The
    // start line and every other header are copied verbatim.
    std::string rebuilt;
    rebuilt.reserve(block.size());
    size_t pos = 0;
    while (pos < block.size()) {
        size_t eol = block.find(CRLF, pos);
        const bool last = eol == std::string::npos;
        const std::string_view line =
            std::string_view{block}.substr(pos, last ? std::string::npos : eol - pos);

        const bool is_host = side_ == Side::Request && HeaderNameIs(line, "Host:");
        const bool is_app_url = side_ == Side::Response && HeaderNameIs(line, "Application-URL:");
        const bool is_location = side_ == Side::Response && HeaderNameIs(line, "Location:");

        if (is_host || is_app_url || is_location) {
            const size_t colon = line.find(':');
            const std::string_view name = line.substr(0, colon + 1);
            const std::string_view raw_value = line.substr(colon + 1);
            const std::string_view value = TrimLeadingSpace(raw_value);
            // Host: carries a bare "host:port" with no scheme; the URL headers carry an absoluteURI.
            std::optional<IpEndpoint> found =
                is_host ? ParseAuthority(std::string{"http://"} + std::string{value}) : ParseAuthority(value);
            std::optional<IpEndpoint> replacement = found ? rewrite_(side_, *found) : std::nullopt;
            if (found && replacement) {
                rebuilt.append(name);
                rebuilt.push_back(' ');
                rebuilt.append(RewriteAuthority(value, *found, *replacement));
            } else {
                rebuilt.append(line);
            }
        } else {
            rebuilt.append(line);
        }
        if (last) {
            break;
        }
        rebuilt.append(CRLF);
        pos = eol + CRLF.size();
    }
    block = std::move(rebuilt);
}

bool HttpFraming::FinishHeaderBlock(std::vector<std::byte>& out) {
    // header_ holds the start line + headers + the terminating blank line. Determine body framing from
    // the (pre-rewrite) header text, then emit the rewritten header block.
    const std::string_view headers{header_};
    size_t content_length = 0;
    bool has_content_length = false;
    bool chunked = false;
    size_t pos = headers.find(CRLF);  // skip the start line
    pos = pos == std::string_view::npos ? headers.size() : pos + CRLF.size();
    while (pos < headers.size()) {
        const size_t eol = headers.find(CRLF, pos);
        const std::string_view line =
            headers.substr(pos, eol == std::string_view::npos ? std::string_view::npos : eol - pos);
        if (line.empty()) {
            break;  // the blank line terminating the block
        }
        if (HeaderNameIs(line, "Content-Length:")) {
            const std::string_view value = TrimLeadingSpace(line.substr(line.find(':') + 1));
            unsigned parsed = 0;
            const auto* begin = value.data();
            const auto* end = value.data() + value.size();
            if (std::from_chars(begin, end, parsed).ec != std::errc{}) {
                return false;
            }
            content_length = parsed;
            has_content_length = true;
        } else if (HeaderNameIs(line, "Transfer-Encoding:")) {
            const std::string_view value = line.substr(line.find(':') + 1);
            chunked = value.find("chunked") != std::string_view::npos
                   || value.find("Chunked") != std::string_view::npos;
        }
        if (eol == std::string_view::npos) {
            break;
        }
        pos = eol + CRLF.size();
    }

    std::string block = std::move(header_);
    header_.clear();
    RewriteHeaders(block);
    const auto* block_bytes = reinterpret_cast<const std::byte*>(block.data());
    out.insert(out.end(), block_bytes, block_bytes + block.size());

    if (chunked) {
        phase_ = Phase::BodyChunked;
        chunk_remaining_ = 0;
        chunk_size_line_.clear();
    } else if (has_content_length && content_length > 0) {
        phase_ = Phase::BodyContentLength;
        body_remaining_ = content_length;
    } else {
        phase_ = Phase::Header;  // bodyless: ready for the next pipelined message
    }
    return true;
}

HttpFraming::Status HttpFraming::Feed(std::span<const std::byte> in, std::vector<std::byte>& out) {
    std::string_view input{reinterpret_cast<const char*>(in.data()), in.size()};
    while (!input.empty()) {
        switch (phase_) {
            case Phase::Header: {
                // Accumulate until the blank-line terminator, bounded by max_header_bytes_.
                const size_t want = input.size();
                if (header_.size() + want > max_header_bytes_) {
                    // Only over-cap if the terminator isn't already within the budget.
                    header_.append(input.substr(0, max_header_bytes_ - header_.size() + HEADER_TERMINATOR.size()));
                    if (header_.find(HEADER_TERMINATOR) == std::string::npos) {
                        return Status::Error;
                    }
                } else {
                    header_.append(input);
                }
                const size_t term = header_.find(HEADER_TERMINATOR);
                if (term == std::string::npos) {
                    if (header_.size() > max_header_bytes_) {
                        return Status::Error;
                    }
                    return Status::NeedMore;  // need more header bytes
                }
                // Everything past the terminator is body/next-message; rewind `input` to it.
                const size_t header_len = term + HEADER_TERMINATOR.size();
                const size_t consumed_from_input = header_len - (header_.size() - want);
                header_.resize(header_len);
                input = input.substr(consumed_from_input);
                if (!FinishHeaderBlock(out)) {
                    return Status::Error;
                }
                break;
            }
            case Phase::BodyContentLength: {
                const size_t take = std::min(body_remaining_, input.size());
                const auto* p = reinterpret_cast<const std::byte*>(input.data());
                out.insert(out.end(), p, p + take);
                input = input.substr(take);
                body_remaining_ -= take;
                if (body_remaining_ == 0) {
                    phase_ = Phase::Header;  // keep-alive: ready for the next message
                }
                break;
            }
            case Phase::BodyChunked:
            case Phase::BodyChunkedDone:
                // Implemented in Task 3.3.
                return Status::Error;
        }
    }
    return Status::NeedMore;
}
```

- [ ] **Step 4: Build and run the Content-Length cases.** `cmake --build build`, then `ctest --test-dir build -R 'HttpFramingContentLengthTest' --output-on-failure`. Expected PASS: all three `HttpFramingContentLengthTest` cases green (Application-URL rewritten authority-only, case-insensitive name match, split-feed reassembly with the body byte-exact).

- [ ] **Step 5: Commit.**

```sh
git add src/reflector/http_message.cpp tests/http_message_test.cpp
git commit -m "http_message: frame Content-Length responses and rewrite Application-URL"
```

### Task 3.3: HttpFraming — chunked response with a Location rewrite

The launch leg: a `Transfer-Encoding: chunked` `201 Created` whose `LOCATION` header (upper-case in the capture) must be rewritten while the chunk DATA is forwarded verbatim and only the chunk-size lines are parsed to find the terminating `0`-chunk.

**Files**
- Modify: `tests/http_message_test.cpp` (append `HttpFramingChunkedTest` cases)
- Modify: `src/reflector/http_message.cpp` (implement the `Phase::BodyChunked` / `BodyChunkedDone` arms of `Feed`)

- [ ] **Step 1: Write the failing chunked test.** Append to `tests/http_message_test.cpp`:

```cpp
TEST(HttpFramingChunkedTest, RewritesUppercaseLocationAndForwardsChunksVerbatim) {
    // The captured launch response: 201 with an upper-case LOCATION on the REST endpoint and a chunked
    // body. Chunk-size lines and DATA are forwarded byte-for-byte; only LOCATION's authority changes.
    const std::string message =
        "HTTP/1.1 201 Created\r\n"
        "LOCATION: http://10.1.3.80:36866/apps/YouTube/run\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1a\r\n<service><ok>true</ok></s>\r\n"
        "0\r\n\r\n";
    RecordingRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Response, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(message), out), HttpFraming::Status::NeedMore);

    const std::string expected =
        "HTTP/1.1 201 Created\r\n"
        "LOCATION: http://192.168.1.2:54321/apps/YouTube/run\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1a\r\n<service><ok>true</ok></s>\r\n"
        "0\r\n\r\n";
    EXPECT_EQ(Decode(out), expected);
}

TEST(HttpFramingChunkedTest, ReassemblesChunkBoundariesSplitAcrossFeeds) {
    // Chunk framing must survive a feed boundary landing mid-size-line and mid-data.
    RecordingRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Response, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"), out),
        HttpFraming::Status::NeedMore);
    EXPECT_EQ(framing.Feed(AsBytes("cde\r\n0\r\n\r\n"), out), HttpFraming::Status::NeedMore);
    EXPECT_EQ(Decode(out),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n");
}
```

- [ ] **Step 2: Build and watch the chunked cases fail.** `cmake --build build`, then `ctest --test-dir build -R 'HttpFramingChunkedTest' --output-on-failure`. Expected fail: the chunked arm currently returns `Status::Error`, so `Feed` returns `Error` (≠ `NeedMore`) and the cases fail.

- [ ] **Step 3: Add chunk-size-line accumulation state.** In `src/reflector/http_message.h`, the `chunk_size_line_` and `chunk_remaining_` members already exist (Step 4 of Task 3.1) — no header change needed. Replace the placeholder chunked arm in `Feed` (the `case Phase::BodyChunked: case Phase::BodyChunkedDone:` block from Task 3.2) with the implementation:

```cpp
            case Phase::BodyChunked: {
                if (chunk_remaining_ > 0) {
                    // Streaming the current chunk's DATA + its trailing CRLF, opaque.
                    const size_t take = std::min(chunk_remaining_, input.size());
                    const auto* p = reinterpret_cast<const std::byte*>(input.data());
                    out.insert(out.end(), p, p + take);
                    input = input.substr(take);
                    chunk_remaining_ -= take;
                    break;
                }
                // Accumulate a chunk-size line (up to its CRLF), forwarding it verbatim once complete.
                const size_t eol = input.find(CRLF);
                if (eol == std::string_view::npos) {
                    chunk_size_line_.append(input);
                    input = {};
                    return Status::NeedMore;  // size line spans feeds
                }
                chunk_size_line_.append(input.substr(0, eol));
                const std::string size_line = chunk_size_line_ + std::string{CRLF};
                chunk_size_line_.clear();
                input = input.substr(eol + CRLF.size());

                // Parse the hex chunk size (ignore any chunk extensions after ';').
                std::string_view digits{size_line};
                digits = digits.substr(0, digits.find_first_of(";\r"));
                size_t size = 0;
                const auto* begin = digits.data();
                const auto* end = digits.data() + digits.size();
                if (std::from_chars(begin, end, size, 16).ec != std::errc{}) {
                    return Status::Error;
                }
                const auto* sp = reinterpret_cast<const std::byte*>(size_line.data());
                out.insert(out.end(), sp, sp + size_line.size());
                if (size == 0) {
                    phase_ = Phase::BodyChunkedDone;  // forward the trailing CRLF, then loop
                } else {
                    chunk_remaining_ = size + CRLF.size();  // chunk DATA + its terminating CRLF
                }
                break;
            }
            case Phase::BodyChunkedDone: {
                // Forward the final CRLF that closes the chunked body, then return to header phase.
                const size_t take = std::min<size_t>(CRLF.size(), input.size());
                const auto* p = reinterpret_cast<const std::byte*>(input.data());
                out.insert(out.end(), p, p + take);
                input = input.substr(take);
                if (take == CRLF.size()) {
                    phase_ = Phase::Header;  // keep-alive: next message
                }
                break;
            }
```

- [ ] **Step 4: Build and run the chunked cases.** `cmake --build build`, then `ctest --test-dir build -R 'HttpFramingChunkedTest' --output-on-failure`. Expected PASS: both `HttpFramingChunkedTest` cases green — `LOCATION` authority rewritten, chunk-size lines and DATA byte-for-byte intact across the split feed.

- [ ] **Step 5: Commit.**

```sh
git add src/reflector/http_message.cpp tests/http_message_test.cpp
git commit -m "http_message: stream chunked bodies and rewrite Location"
```

### Task 3.4: HttpFraming — bodyless request Host rewrite, oversized header refusal, keep-alive pipelining

The remaining behaviors: a bodyless `GET` request with its `Host` rewritten on the request side; an over-cap header block refused with `Status::Error`; and two pipelined keep-alive messages framed back-to-back in one `Feed`. The implementation from Tasks 3.2–3.3 already covers these (request-side `Host` in `RewriteHeaders`, the `max_header_bytes_` guard in the header phase, and the `Phase::Header` reset after each body) — so this task is a test-only proof that locks the behavior in.

**Files**
- Modify: `tests/http_message_test.cpp` (append `HttpFramingMiscTest` cases)

- [ ] **Step 1: Write the failing tests.** Append to `tests/http_message_test.cpp`. The request rewrite swaps the captured TV description endpoint (`10.1.3.80:1461`) in `Host`:

```cpp
namespace {

// A request-side rewrite swapping the description endpoint's authority for the reflector listener
// authority the client actually connected to.
struct HostRewrite {
    std::optional<IpEndpoint> operator()(HttpFraming::Side, const IpEndpoint& found) {
        if (found == IpEndpoint{IpAddress::FromV4Bytes(10, 1, 3, 80), 1461}) {
            return IpEndpoint{IpAddress::FromV4Bytes(192, 168, 1, 2), 40000};
        }
        return std::nullopt;
    }
};

} // namespace

TEST(HttpFramingMiscTest, RewritesHostOnBodylessGetRequest) {
    // The captured description GET: bodyless, keep-alive, Host carries the device authority the client
    // reached the reflector listener for. The reverse (request) leg rewrites Host back to the device.
    const std::string message =
        "GET / HTTP/1.1\r\n"
        "Host: 10.1.3.80:1461\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    HostRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Request, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(message), out), HttpFraming::Status::NeedMore);
    EXPECT_EQ(Decode(out),
        "GET / HTTP/1.1\r\n"
        "Host: 10.1.3.80:1461\r\n"  // placeholder; replaced below by the rewritten expectation
        "Connection: keep-alive\r\n"
        "\r\n");
}

TEST(HttpFramingMiscTest, RefusesOversizedHeaderBlock) {
    // A header block larger than the cap (no terminator within budget) is refused so the connection is
    // closed — the only unbounded-buffer risk, since bodies are streamed.
    std::string message = "GET / HTTP/1.1\r\nX-Pad: ";
    message.append(200, 'a');  // overflow the tiny cap with no terminating blank line yet
    HostRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Request, /*max_header_bytes=*/64, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(message), out), HttpFraming::Status::Error);
}

TEST(HttpFramingMiscTest, FramesTwoPipelinedKeepAliveMessages) {
    // Two responses on one keep-alive connection in a single Feed: a Content-Length body then a
    // bodyless 204. Each Application-URL is rewritten; the framer returns to header phase between them.
    const std::string first =
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "Content-Length: 2\r\n"
        "\r\nhi";
    const std::string second =
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://10.1.3.80:36866/apps\r\n"
        "\r\n";
    RecordingRewrite rewrite;
    HttpFraming framing(HttpFraming::Side::Response, 65536, std::ref(rewrite));
    std::vector<std::byte> out;
    EXPECT_EQ(framing.Feed(AsBytes(first + second), out), HttpFraming::Status::NeedMore);
    EXPECT_EQ(Decode(out),
        "HTTP/1.1 200 OK\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "Content-Length: 2\r\n"
        "\r\nhi"
        "HTTP/1.1 204 No Content\r\n"
        "Application-URL: http://192.168.1.2:54321/apps\r\n"
        "\r\n");
    // Both messages' Application-URL headers were surfaced to the rewrite.
    EXPECT_EQ(rewrite.seen.size(), 2u);
}
```

- [ ] **Step 2: Fix the Host-rewrite expectation to assert the rewritten bytes.** The placeholder line above is wrong on purpose so the test fails first; correct it to the post-rewrite authority before running. Replace the `RewritesHostOnBodylessGetRequest` expected block's `Host:` line:

```cpp
    EXPECT_EQ(Decode(out),
        "GET / HTTP/1.1\r\n"
        "Host: 192.168.1.2:40000\r\n"
        "Connection: keep-alive\r\n"
        "\r\n");
```

- [ ] **Step 3: Build and run the misc cases.** `cmake --build build`, then `ctest --test-dir build -R 'HttpFramingMiscTest' --output-on-failure`. Expected PASS: all three cases — `Host` rewritten on the request leg, the over-cap header block returns `Status::Error`, and the two pipelined keep-alive messages are framed with both `Application-URL` headers rewritten and the boundary handled.

- [ ] **Step 4: Run the whole unit suite to confirm nothing regressed.** `ctest --test-dir build -L unit --output-on-failure`. Expected PASS: the full suite green, including all `RewriteAuthorityTest`, `HttpFramingContentLengthTest`, `HttpFramingChunkedTest`, and `HttpFramingMiscTest` cases.

- [ ] **Step 5: Commit.**

```sh
git add tests/http_message_test.cpp
git commit -m "http_message: cover Host rewrite, header cap, and keep-alive pipelining"
```

## Commit 4: dial_proxy — DialProxy orchestrator with read-interest flow control

This commit lands `src/reflector/dial_proxy.{h,cpp}`: the `SendBuffer` byte FIFO, the `Endpoint`/`Connection` state (no `*_read_paused` bools), the two listener caps + `MAX_CONNECTIONS` drop-new, `EnsureListener`/`EnsureDiscoveryListener`/`EnsureRestListener`, the non-blocking connection pump, the connect/idle eviction `Timer`, and — the reason this commit is being redone — **backpressure via kernel read interest** (`SetReadInterest(source, false)` at `HIGH_WATER`, `SetReadInterest(source, true)` when the peer drains below `LOW_WATER`), never a pause bool and never a read early-return.

It depends on Commits 1–3 (reactor read/write interest control + `FakeDispatcher::{FireWritable,SetReadInterest,SetWriteInterest,IsReadArmed,IsWriteArmed}`; `IpEndpoint`; `TcpSocket`; `HttpFraming`/`RewriteAuthority`), all already landed and fixed. `DialProxy` reaches the reactor through `PacketDispatcher::UnderlyingDispatcher()` exactly as the SSDP eviction `Timer` does.

The cap/reuse/drop-new/idle-eviction cases use no real sockets and run unprivileged; the accept→connect→forward and flow-control cases use a real loopback `TcpSocket` plus egress-pinned `Connect`, so they live behind a `*RequiresRoot*` fixture that `GTEST_SKIP`s when `CAP_NET_RAW`/root is absent.

### Task 4.1: SendBuffer — bounded byte FIFO

A growable byte buffer with a consumed-head offset, compacted on drain. This is the per-direction unflushed-bytes queue the connection pump fills on a short write and drains on the peer's writable. Landing it first (pure data, no reactor) lets the pump tasks build on a tested primitive.

**Files**
- Create: `src/reflector/dial_proxy.h` (the `SendBuffer` class only, in this task)
- Create: `tests/dial_proxy_test.cpp`
- Modify: `tests/CMakeLists.txt` (add `dial_proxy_test.cpp` to the `reflector_test` source list)

- [ ] **Step 1: Add the new test file to the build.** Insert the source path into the `reflector_test` `add_executable` list in `tests/CMakeLists.txt`, after the `default_packet_dispatcher_test.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/default_packet_dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dial_proxy_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_test.cpp
```

- [ ] **Step 2: Write the failing SendBuffer test.** Create `tests/dial_proxy_test.cpp` with the includes the whole file will need and the `SendBuffer` cases. (`SendBuffer` is a public nested type of `DialProxy` so tests can construct it directly; the rest of `DialProxy` is exercised in later tasks.)

```cpp
#include "reflector/dial_proxy.h"

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "reflector/mac_address.h"
#include "reflector/tcp_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reflector {
namespace {

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

std::string ToText(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (const std::byte b : bytes) {
        out.push_back(static_cast<char>(b));
    }
    return out;
}

} // namespace

using SendBuffer = DialProxy::SendBuffer;

TEST(DialProxySendBufferTest, EmptyHasZeroSizeAndEmptyView) {
    SendBuffer buffer;
    EXPECT_EQ(buffer.Size(), 0u);
    EXPECT_TRUE(buffer.View().empty());
}

TEST(DialProxySendBufferTest, AppendThenViewReturnsAllBytesInOrder) {
    SendBuffer buffer;
    const auto first = Bytes("hello ");
    const auto second = Bytes("world");
    buffer.Append(first);
    buffer.Append(second);

    EXPECT_EQ(buffer.Size(), first.size() + second.size());
    EXPECT_EQ(ToText(buffer.View()), "hello world");
}

TEST(DialProxySendBufferTest, ConsumeAdvancesTheHeadAndShrinksSize) {
    SendBuffer buffer;
    buffer.Append(Bytes("hello world"));

    buffer.Consume(6);  // drop "hello "
    EXPECT_EQ(buffer.Size(), 5u);
    EXPECT_EQ(ToText(buffer.View()), "world");
}

TEST(DialProxySendBufferTest, FullyDrainingResetsToEmpty) {
    SendBuffer buffer;
    buffer.Append(Bytes("data"));
    buffer.Consume(4);

    EXPECT_EQ(buffer.Size(), 0u);
    EXPECT_TRUE(buffer.View().empty());

    // A drained buffer is reusable: appending after a full drain starts a fresh region.
    buffer.Append(Bytes("again"));
    EXPECT_EQ(ToText(buffer.View()), "again");
}

TEST(DialProxySendBufferTest, AppendAfterPartialConsumeCompactsAndPreservesRemainder) {
    SendBuffer buffer;
    buffer.Append(Bytes("abcdef"));
    buffer.Consume(4);  // head now points at "ef"
    buffer.Append(Bytes("gh"));

    EXPECT_EQ(buffer.Size(), 4u);
    EXPECT_EQ(ToText(buffer.View()), "efgh");
}

} // namespace reflector
```

- [ ] **Step 3: Run it — expect a compile FAIL.** `dial_proxy.h` does not exist yet, so the file won't compile:

```sh
./cmake_gen.sh
cmake --build build
ctest --test-dir build -R 'DialProxySendBufferTest' --output-on-failure
```
Expected: build error `fatal error: 'reflector/dial_proxy.h' file not found`.

- [ ] **Step 4: Create `dial_proxy.h` with the SendBuffer implementation.** Write the header with only `SendBuffer` filled in for now; the rest of the class is added in later tasks. `SendBuffer` keeps a `std::vector<std::byte>` plus a `head_` offset; `Append` compacts (drops the consumed prefix) before growing so the buffer can't ratchet, and `Consume` that empties the region resets both to zero.

```cpp
#pragma once

#include "ip_address.h"
#include "ip_endpoint.h"
#include "mac_address.h"
#include "packet_dispatcher.h"
#include "tcp_socket.h"
#include "http_message.h"
#include "timer.h"
#include "logger.h"
#include "dispatcher.h"
#include "util/no_move.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace reflector {

// L7 DIAL application proxy. Owned by SsdpReflector as std::optional<DialProxy>, reaching the
// reactor via PacketDispatcher::UnderlyingDispatcher(). Stands up per-device-endpoint TCP
// listeners on source_if's address, accepts client connections, connects upstream pinned to
// target_if, and reverse-proxies the DIAL control HTTP, rewriting a small header set so the
// client sees reflector authorities. Single-threaded and reactor-driven throughout. Immovable
// (NoMove): it hands the reactor stable `this` pointers via CreateDelegate.
class DialProxy : NoMove {
public:
    // Bounded FIFO byte buffer: a std::vector<std::byte> with a consumed-head offset. Append fills
    // the tail; View exposes the unconsumed bytes; Consume drops a prefix. Compacted on Append (the
    // consumed prefix is dropped before growing) and reset when fully drained, so it can't ratchet —
    // flow control caps its Size at ~HIGH_WATER, so the rare compaction memmove is a small copy.
    class SendBuffer {
    public:
        void Append(std::span<const std::byte> data) {
            if (head_ > 0) {
                bytes_.erase(bytes_.begin(), bytes_.begin() + static_cast<std::ptrdiff_t>(head_));
                head_ = 0;
            }
            bytes_.insert(bytes_.end(), data.begin(), data.end());
        }

        [[nodiscard]] std::span<const std::byte> View() const noexcept {
            return std::span<const std::byte>{bytes_.data() + head_, Size()};
        }

        void Consume(size_t n) noexcept {
            head_ += n;
            if (head_ >= bytes_.size()) {
                bytes_.clear();
                head_ = 0;
            }
        }

        [[nodiscard]] size_t Size() const noexcept { return bytes_.size() - head_; }

    private:
        std::vector<std::byte> bytes_;
        size_t head_ = 0;
    };

    struct Tunables {
        size_t max_connections = 32;
        size_t max_rest_listeners = 32;
        size_t max_discovery_listeners = 32;
        size_t max_header_bytes = 65536;   // per-message header-block cap (passed to each HttpFraming)
        size_t high_water = 64 * 1024;
        size_t low_water = 16 * 1024;
        std::chrono::milliseconds connect_timeout{5000};
        std::chrono::milliseconds discovery_idle{90 * 1000};
        std::chrono::milliseconds rest_idle{60 * 60 * 1000};
        std::chrono::milliseconds eviction_interval{1000};
    };

    // source_if_addr is the IPv4 address listeners bind to and that the rewritten authorities name;
    // source_if_name/target_if_name are interface names (target_if_name pins the upstream egress);
    // device_mac scopes nothing here (the SSDP path already filters) but is retained for parity/logs.
    DialProxy(PacketDispatcher& packet_dispatcher, IpAddress source_if_addr, std::string source_if_name,
        std::string target_if_name, std::optional<MacAddress> device_mac, Tunables tunables);

    // Find or create a Discovery-role listener for a device's description endpoint, returning the
    // reflector authority (source_if-addr:listener-port) to advertise in the rewritten LOCATION.
    // Called only by the owning SsdpReflector from its SSDP dispatch callback; refreshes last_active.
    // nullopt if the discovery-listener cap is hit or listen/bind fails.
    [[nodiscard]] std::optional<IpEndpoint> EnsureDiscoveryListener(IpEndpoint device);

private:
    enum class Role { Discovery, Rest };

    struct Endpoint {
        Role role;
        IpEndpoint device;
        TcpSocket listener;
        Dispatcher::Registration accept_reg;
        std::chrono::steady_clock::time_point last_active;
    };

    enum class Phase { Connecting, Open };

    struct Connection {
        TcpSocket client;
        TcpSocket upstream;
        Dispatcher::Registration client_reg;
        Dispatcher::Registration upstream_reg;
        HttpFraming c2u;
        HttpFraming u2c;
        SendBuffer pending_to_client;
        SendBuffer pending_to_upstream;
        Phase phase;
        std::chrono::steady_clock::time_point deadline;
        IpEndpoint upstream_device;
    };

    // Rest-role variant used by the response-side HeaderRewrite when it rewrites Application-URL/201.
    [[nodiscard]] std::optional<IpEndpoint> EnsureRestListener(IpEndpoint device);
    [[nodiscard]] std::optional<IpEndpoint> EnsureListener(IpEndpoint device, Role role);

    [[nodiscard]] size_t ListenerCount(Role role) const noexcept;
    [[nodiscard]] IpEndpoint Authority(const Endpoint& endpoint) const noexcept;
    [[nodiscard]] std::chrono::milliseconds IdleGrace(Role role) const noexcept;

    // Reactor callbacks.
    void OnListenerReadable(int listener_fd) noexcept;        // a client is waiting on a listener
    void OnConnectionReadable(int fd) noexcept;               // a client/upstream fd has data
    void OnConnectionWritable(int fd) noexcept;               // an fd drained / a connect completed
    void EvictExpired(std::chrono::steady_clock::time_point now) noexcept;

    // Connection mechanics.
    void StartConnection(Endpoint& endpoint, TcpSocket client);
    void CompleteConnect(Connection& connection) noexcept;    // upstream became writable: check SO_ERROR
    void Forward(Connection& connection, bool from_client) noexcept;
    void Flush(Connection& connection, bool to_client) noexcept;
    void DropConnection(int fd) noexcept;

    // Locate the connection owning `fd` and whether `fd` is its client side. nullptr if gone.
    [[nodiscard]] Connection* FindConnection(int fd, bool& is_client) noexcept;
    void ArmEvictionTimer();

    Dispatcher& dispatcher_;
    PacketDispatcher& packet_dispatcher_;
    IpAddress source_if_addr_;
    std::string source_if_name_;
    std::string target_if_name_;
    std::optional<MacAddress> device_mac_;
    Tunables tunables_;
    Logger logger_;
    std::vector<Endpoint> endpoints_;
    std::vector<Connection> connections_;
    Timer eviction_timer_;
};

} // namespace reflector
```

- [ ] **Step 5: Create a `dial_proxy.cpp` stub so the rest of the header links.** The header declares non-`SendBuffer` members the later tasks fill in; create the `.cpp` now with the ctor and stubbed method bodies so this task's build links. (Each later task replaces a stub with its real body via a failing-test-first cycle.) Add the source to the library, then write the stub.

  In `src/reflector/CMakeLists.txt`, add to the `reflector` `add_library` list after the `ssdp_reflector.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_reflector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dial_proxy.cpp
```

  Create `src/reflector/dial_proxy.cpp`:

```cpp
#include "dial_proxy.h"

#include "util/delegate.h"

#include <algorithm>
#include <format>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const std::string& source_if, const std::string& target_if) {
    return std::format("DialProxy:{}->{}", source_if, target_if);
}

} // namespace

DialProxy::DialProxy(PacketDispatcher& packet_dispatcher, IpAddress source_if_addr,
    std::string source_if_name, std::string target_if_name, std::optional<MacAddress> device_mac,
    Tunables tunables)
        : dispatcher_{packet_dispatcher.UnderlyingDispatcher()}
        , packet_dispatcher_{packet_dispatcher}
        , source_if_addr_{source_if_addr}
        , source_if_name_{std::move(source_if_name)}
        , target_if_name_{std::move(target_if_name)}
        , device_mac_{device_mac}
        , tunables_{tunables}
        , logger_{LoggerName(source_if_name_, target_if_name_)}
        , eviction_timer_{dispatcher_} {}

IpEndpoint DialProxy::Authority(const Endpoint& endpoint) const noexcept {
    return IpEndpoint{.addr = source_if_addr_, .port = endpoint.listener.LocalPort()};
}

size_t DialProxy::ListenerCount(Role role) const noexcept {
    return static_cast<size_t>(std::ranges::count_if(endpoints_,
        [role](const Endpoint& endpoint) { return endpoint.role == role; }));
}

std::chrono::milliseconds DialProxy::IdleGrace(Role role) const noexcept {
    return role == Role::Discovery ? tunables_.discovery_idle : tunables_.rest_idle;
}

std::optional<IpEndpoint> DialProxy::EnsureDiscoveryListener(IpEndpoint device) {
    return EnsureListener(device, Role::Discovery);
}

std::optional<IpEndpoint> DialProxy::EnsureRestListener(IpEndpoint device) {
    return EnsureListener(device, Role::Rest);
}

std::optional<IpEndpoint> DialProxy::EnsureListener(IpEndpoint /*device*/, Role /*role*/) {
    return std::nullopt;  // implemented in Task 4.2
}

void DialProxy::ArmEvictionTimer() {}                                  // Task 4.5
void DialProxy::OnListenerReadable(int /*listener_fd*/) noexcept {}    // Task 4.3
void DialProxy::OnConnectionReadable(int /*fd*/) noexcept {}           // Task 4.4
void DialProxy::OnConnectionWritable(int /*fd*/) noexcept {}           // Task 4.4
void DialProxy::EvictExpired(std::chrono::steady_clock::time_point /*now*/) noexcept {}  // Task 4.5
void DialProxy::StartConnection(Endpoint& /*endpoint*/, TcpSocket /*client*/) {}         // Task 4.3
void DialProxy::CompleteConnect(Connection& /*connection*/) noexcept {}                  // Task 4.3
void DialProxy::Forward(Connection& /*connection*/, bool /*from_client*/) noexcept {}    // Task 4.4
void DialProxy::Flush(Connection& /*connection*/, bool /*to_client*/) noexcept {}        // Task 4.4
void DialProxy::DropConnection(int /*fd*/) noexcept {}                                   // Task 4.4

DialProxy::Connection* DialProxy::FindConnection(int /*fd*/, bool& /*is_client*/) noexcept {
    return nullptr;  // Task 4.4
}

} // namespace reflector
```

- [ ] **Step 6: Run the SendBuffer test — expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'DialProxySendBufferTest' --output-on-failure
```
Expected: all five `DialProxySendBufferTest` cases pass.

### Task 4.2: EnsureListener — allocate/reuse, the two caps, authority

`EnsureListener` finds an existing endpoint for `device` (reusing its listener and refreshing `last_active`) or, at first sight, opens a `TcpSocket::Listen` bound to `source_if_addr_`, registers it for accept, and tags it with the role. It returns the reflector authority `source_if_addr_:listener-port`. A device referenced as both roles is promoted to `Rest` (the longer-lived role, §4.4). The two roles count against separate caps; over cap returns `nullopt`. `EnsureDiscoveryListener`/`EnsureRestListener` are thin wrappers (already present from Task 4.1). These cases need no privilege — `TcpSocket::Listen` on a loopback address and `FakeDispatcher::Register` require none.

**Files**
- Modify: `src/reflector/dial_proxy.cpp` (replace the `EnsureListener` stub)
- Modify: `tests/dial_proxy_test.cpp` (add the fixture + listener cases)

- [ ] **Step 1: Write the failing EnsureListener tests.** Append to `tests/dial_proxy_test.cpp`, before the final `} // namespace reflector`. The fixture builds a `DialProxy` over a `FakePacketDispatcher` whose `UnderlyingDispatcher()` is a `FakeDispatcher`, binding listeners to `127.0.0.1` (loopback needs no privilege).

```cpp
namespace {

IpEndpoint Device(uint8_t last_octet, uint16_t port) {
    return IpEndpoint{.addr = IpAddress::FromV4Bytes(10, 1, 3, last_octet), .port = port};
}

} // namespace

class DialProxyTest : public ::testing::Test {
protected:
    FakePacketDispatcher packet_dispatcher;
    DialProxy::Tunables tunables;  // defaults; individual tests shrink caps as needed

    FakeDispatcher& Reactor() { return packet_dispatcher.dispatcher; }

    DialProxy MakeProxy() {
        return DialProxy{packet_dispatcher, IpAddress::LoopbackV4(), std::string{LoopbackInterface()},
            std::string{LoopbackInterface()}, std::nullopt, tunables};
    }
};

TEST_F(DialProxyTest, EnsureDiscoveryListenerAllocatesAndReturnsAuthority) {
    DialProxy proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(Device(80, 1461));
    ASSERT_TRUE(authority.has_value());
    EXPECT_EQ(authority->addr, IpAddress::LoopbackV4());  // bound to source_if's address
    EXPECT_NE(authority->port, 0u);                       // an ephemeral listener port was chosen
    EXPECT_NE(authority->port, 1461u);                    // and it is NOT the device's port
    EXPECT_EQ(Reactor().RegistrationCount(), 1u);         // the listener's accept registration
}

TEST_F(DialProxyTest, EnsureDiscoveryListenerReusesSameDeviceListener) {
    DialProxy proxy = MakeProxy();

    const auto first = proxy.EnsureDiscoveryListener(Device(80, 1461));
    const auto second = proxy.EnsureDiscoveryListener(Device(80, 1461));
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    EXPECT_EQ(*first, *second);                    // same authority -> same listener reused
    EXPECT_EQ(Reactor().RegistrationCount(), 1u);  // not a second listener
}

TEST_F(DialProxyTest, DistinctDeviceEndpointsGetDistinctListeners) {
    DialProxy proxy = MakeProxy();

    const auto a = proxy.EnsureDiscoveryListener(Device(80, 1461));
    const auto b = proxy.EnsureDiscoveryListener(Device(81, 1461));  // different device ip
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    EXPECT_NE(a->port, b->port);
    EXPECT_EQ(Reactor().RegistrationCount(), 2u);
}

TEST_F(DialProxyTest, DiscoveryListenerCapReturnsNulloptBeyondLimit) {
    tunables.max_discovery_listeners = 2;
    DialProxy proxy = MakeProxy();

    EXPECT_TRUE(proxy.EnsureDiscoveryListener(Device(80, 1461)).has_value());
    EXPECT_TRUE(proxy.EnsureDiscoveryListener(Device(81, 1461)).has_value());
    EXPECT_FALSE(proxy.EnsureDiscoveryListener(Device(82, 1461)).has_value());  // 3rd over cap
    EXPECT_EQ(Reactor().RegistrationCount(), 2u);  // no listener for the dropped one
}

TEST_F(DialProxyTest, DiscoveryAndRestCapsAreSeparate) {
    // A device serving description and REST on DIFFERENT ports holds one listener per endpoint, each
    // counting against its own cap — a full discovery cap does not block a REST listener.
    tunables.max_discovery_listeners = 1;
    tunables.max_rest_listeners = 1;
    DialProxy proxy = MakeProxy();

    EXPECT_TRUE(proxy.EnsureDiscoveryListener(Device(80, 1461)).has_value());   // discovery cap full
    EXPECT_FALSE(proxy.EnsureDiscoveryListener(Device(80, 1637)).has_value());  // another discovery: capped
    // A REST endpoint still allocates: separate cap.
    DialProxyRestPeek peek{proxy};
    EXPECT_TRUE(peek.EnsureRest(Device(80, 36866)).has_value());
}
```

  `EnsureRestListener` is private. So the test can reach it, add a tiny friend peek helper. Add this declaration just above `class DialProxy` in `dial_proxy.h`:

```cpp
class DialProxyRestPeek;  // test seam: invokes the private EnsureRestListener
```

  and inside `class DialProxy`, in the `private:` section, befriend it:

```cpp
    friend class DialProxyRestPeek;
```

  Define the peek helper in the test file's anonymous namespace (it forwards to the private method):

```cpp
} // namespace  (close the earlier anon namespace before the class, if needed)

// Test seam: reaches DialProxy's private EnsureRestListener (the response-side HeaderRewrite path).
class DialProxyRestPeek {
public:
    explicit DialProxyRestPeek(DialProxy& proxy) : proxy_{&proxy} {}
    std::optional<IpEndpoint> EnsureRest(IpEndpoint device) { return proxy_->EnsureRestListener(device); }
private:
    DialProxy* proxy_;
};
```

  (`DialProxyRestPeek` must be in namespace `reflector` to match the `friend` declaration; declare it at namespace scope in the test, not the anonymous namespace.)

- [ ] **Step 2: Run — expect FAIL.** `EnsureListener` still returns `nullopt`:

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyTest' --output-on-failure
```
Expected: `EnsureDiscoveryListenerAllocatesAndReturnsAuthority` and the reuse/distinct/cap/separate-cap cases FAIL (authority is `nullopt`, registration count 0).

- [ ] **Step 3: Implement EnsureListener.** Replace the stub in `dial_proxy.cpp`:

```cpp
std::optional<IpEndpoint> DialProxy::EnsureListener(IpEndpoint device, Role role) {
    const auto now = std::chrono::steady_clock::now();

    // Reuse an existing listener for this exact device endpoint. A device seen as both roles is
    // promoted to Rest (the longer-lived role) so it lives as long as either use needs it.
    const auto existing = std::ranges::find_if(endpoints_,
        [&](const Endpoint& endpoint) { return endpoint.device == device; });
    if (existing != endpoints_.end()) {
        if (role == Role::Rest && existing->role == Role::Discovery) {
            existing->role = Role::Rest;
        }
        existing->last_active = now;
        return Authority(*existing);
    }

    if (ListenerCount(role) >= (role == Role::Rest ? tunables_.max_rest_listeners
                                                   : tunables_.max_discovery_listeners)) {
        logger_.Warning("Dropping DIAL listener for {}:{}: {} cap reached", device.addr, device.port,
            role == Role::Rest ? "REST" : "discovery");
        return std::nullopt;
    }

    auto listener = TcpSocket::Listen(source_if_addr_);
    if (!listener.has_value()) {
        logger_.Error("Cannot open DIAL listener for {}:{} on {}", device.addr, device.port,
            source_if_addr_);
        return std::nullopt;
    }
    auto accept_reg = dispatcher_.Register(listener->Fd(),
        CreateDelegate<&DialProxy::OnListenerReadable>(this));
    if (!accept_reg.IsValid()) {
        logger_.Error("Cannot register DIAL listener for {}:{}", device.addr, device.port);
        return std::nullopt;  // listener RAII-closes here
    }

    Endpoint endpoint{
        .role = role,
        .device = device,
        .listener = std::move(*listener),
        .accept_reg = std::move(accept_reg),
        .last_active = now,
    };
    const auto authority = Authority(endpoint);
    endpoints_.push_back(std::move(endpoint));
    ArmEvictionTimer();  // a no-op until Task 4.5; harmless here
    logger_.Debug("Opened DIAL {} listener {}:{} -> device {}:{}",
        role == Role::Rest ? "REST" : "discovery", authority.addr, authority.port, device.addr, device.port);
    return authority;
}
```

- [ ] **Step 4: Run — expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyTest' --output-on-failure
```
Expected: the listener allocate/reuse/distinct/cap/separate-cap cases pass; `DialProxySendBufferTest` still green.

### Task 4.3: Accept → connect → connect-completion (RequiresRoot)

On a listener becoming readable, `OnListenerReadable` `Accept()`s; at `MAX_CONNECTIONS` it closes the child immediately (drop-new); otherwise it builds a `Connection`, `TcpSocket::Connect`s upstream to the listener's device endpoint **pinned to `target_if`** (`EINPROGRESS`), registers both fds with read+write callbacks, `SetWriteInterest(upstream, true)`, sets the connect deadline, and starts in phase `Connecting`. When the upstream becomes writable, `CompleteConnect` checks `SoError()`: on success it disarms upstream write interest and goes `Open`; on failure it tears the pair down. The per-connection `HttpFraming` rewrites are constructed here. Egress-pinned `Connect` needs `CAP_NET_RAW`/root, so this is a `*RequiresRoot*` fixture; `MAX_CONNECTIONS` drop-new is asserted via "no upstream connect was registered" which is observable here too.

**Files**
- Modify: `src/reflector/dial_proxy.cpp` (`OnListenerReadable`, `StartConnection`, `CompleteConnect`, `OnConnectionWritable` dispatch to `CompleteConnect`, `FindConnection`, the per-connection `HttpFraming` rewrite construction)
- Modify: `tests/dial_proxy_test.cpp` (the RequiresRoot fixture + accept/connect/drop-new cases)

- [ ] **Step 1: Write the failing accept/connect tests.** Append to `tests/dial_proxy_test.cpp`. The fixture opens a real loopback "device" listener to stand in for the DIAL device, points `EnsureRestListener` at it, fires the proxy listener readable after a real client connects, and drives connect completion with `FireWritable`.

```cpp
class DialProxyRequiresRootTest : public ::testing::Test {
protected:
    FakePacketDispatcher packet_dispatcher;
    DialProxy::Tunables tunables;
    std::optional<TcpSocket> device_listener;  // stands in for a DIAL device's endpoint
    IpEndpoint device_endpoint{};

    FakeDispatcher& Reactor() { return packet_dispatcher.dispatcher; }

    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "egress-pinned TcpSocket::Connect needs CAP_NET_RAW (Linux) / root (macOS)";
        }
        device_listener = TcpSocket::Listen(IpAddress::LoopbackV4());
        ASSERT_TRUE(device_listener.has_value());
        device_endpoint = IpEndpoint{.addr = IpAddress::LoopbackV4(), .port = device_listener->LocalPort()};
    }

    DialProxy MakeProxy() {
        return DialProxy{packet_dispatcher, IpAddress::LoopbackV4(), std::string{LoopbackInterface()},
            std::string{LoopbackInterface()}, std::nullopt, tunables};
    }

    // Connect a real client to the proxy listener at `authority` and return the client socket.
    static std::optional<TcpSocket> ConnectClient(const IpEndpoint& authority) {
        auto client = TcpSocket::Connect(authority, IpAddress::LoopbackV4(), LoopbackInterface());
        return client;  // EINPROGRESS is fine; the proxy's Accept sees the pending connection
    }

    // Accept the upstream side at the device listener (the proxy's Connect lands here).
    std::optional<TcpSocket> AcceptAtDevice() {
        // Poll briefly: the proxy's non-blocking connect may not have completed instantly.
        for (int i = 0; i < 100; ++i) {
            auto upstream = device_listener->Accept();
            if (upstream.has_value()) {
                return upstream;
            }
            pollfd pfd{.fd = device_listener->Fd(), .events = POLLIN, .revents = 0};
            ::poll(&pfd, 1, 50);
        }
        return std::nullopt;
    }
};

TEST_F(DialProxyRequiresRootTest, AcceptStartsAnUpstreamConnectAndWatchesBothFds) {
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());
    const size_t listeners = Reactor().RegistrationCount();  // the one listener

    auto client = ConnectClient(*authority);
    ASSERT_TRUE(client.has_value());

    // Find the proxy listener fd (the only watched fd so far) and fire it readable.
    // The listener fd is the one the proxy registered; drive it through the fake.
    proxy_fire_listener(proxy, Reactor());  // helper below: fires the single listener fd

    // The proxy accepted, created a connection, and registered both client + upstream fds.
    EXPECT_EQ(Reactor().RegistrationCount(), listeners + 2u);

    // The upstream connect reached the device.
    auto upstream = AcceptAtDevice();
    EXPECT_TRUE(upstream.has_value());
}

TEST_F(DialProxyRequiresRootTest, ConnectCompletionGoesOpenAndDisarmsUpstreamWriteInterest) {
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());

    auto client = ConnectClient(*authority);
    ASSERT_TRUE(client.has_value());
    proxy_fire_listener(proxy, Reactor());
    auto upstream = AcceptAtDevice();
    ASSERT_TRUE(upstream.has_value());

    // The proxy registered the upstream fd with write interest armed (for connect completion).
    const int upstream_fd = proxy_upstream_fd(Reactor());
    ASSERT_GE(upstream_fd, 0);
    EXPECT_TRUE(Reactor().IsWriteArmed(upstream_fd));

    // Loopback connect completes immediately; firing the upstream writable runs CompleteConnect,
    // which disarms upstream write interest and opens the connection.
    Reactor().FireWritable(upstream_fd);
    EXPECT_FALSE(Reactor().IsWriteArmed(upstream_fd));
}

TEST_F(DialProxyRequiresRootTest, MaxConnectionsDropsNew) {
    tunables.max_connections = 1;
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());

    auto first_client = ConnectClient(*authority);
    ASSERT_TRUE(first_client.has_value());
    proxy_fire_listener(proxy, Reactor());
    const size_t after_first = Reactor().RegistrationCount();  // listener + client + upstream = 3
    ASSERT_EQ(after_first, 3u);

    auto second_client = ConnectClient(*authority);
    ASSERT_TRUE(second_client.has_value());
    proxy_fire_listener(proxy, Reactor());

    // At cap: the second accept is closed immediately — no new client/upstream fds watched.
    EXPECT_EQ(Reactor().RegistrationCount(), after_first);
}
```

  The two helpers `proxy_fire_listener` and `proxy_upstream_fd` read the fake's watched-fd set. Add to `FakeDispatcher` (Commit 1 already added `IsReadArmed`/`IsWriteArmed`; this is a tiny test-only accessor) a way to enumerate watched fds, and a way to know which is the listener. Implement the helpers in the test file using a new `FakeDispatcher::WatchedFds()` accessor:

```cpp
// In tests/dial_proxy_test.cpp, namespace reflector, anon namespace:
void proxy_fire_listener(DialProxy& /*proxy*/, FakeDispatcher& reactor) {
    // The listener is the lowest-numbered watched fd present before any connection fds (registered
    // earliest). Fire every currently-watched fd readable that is a listener: in these tests exactly
    // one listener exists, so fire the smallest watched fd.
    const auto fds = reactor.WatchedFds();
    ASSERT_FALSE(fds.empty());
    reactor.FireReadable(*std::ranges::min_element(fds));
}

int proxy_upstream_fd(FakeDispatcher& reactor) {
    // After one accept the watched set is {listener, client, upstream}. The upstream is the only one
    // with write interest armed (StartConnection arms it for connect completion).
    for (const int fd : reactor.WatchedFds()) {
        if (reactor.IsWriteArmed(fd)) {
            return fd;
        }
    }
    return -1;
}
```

  Add `WatchedFds()` to `tests/mocks/fake_dispatcher.h` (a pure test accessor, alongside `IsWatching`):

```cpp
    [[nodiscard]] std::vector<int> WatchedFds() const {
        std::vector<int> fds;
        fds.reserve(callbacks_.size());
        for (const auto& [fd, _] : callbacks_) {
            fds.push_back(fd);
        }
        return fds;
    }
```

  (`<vector>` is already included in `fake_dispatcher.h`.) Note these tests assume Commit 1's `FakeDispatcher` 3-arg `Register` stores the write callback and that `IsWriteArmed`/`SetWriteInterest` are present, per the shared contract.

- [ ] **Step 2: Run — expect FAIL.** `OnListenerReadable` is still a stub, so no connection fds get registered:

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyRequiresRootTest' --output-on-failure
```
Expected (with privilege): `AcceptStartsAnUpstreamConnect...` etc. FAIL (`RegistrationCount` stays at 1; `proxy_upstream_fd` returns -1). On an unprivileged box they SKIP.

- [ ] **Step 3: Implement accept, connect, and connect-completion.** Replace the stubs in `dial_proxy.cpp`. The per-connection `HttpFraming` rewrites: the request side returns the connection's `upstream_device`; the response side returns `EnsureRestListener(found)`. Both are captured by `std::function` closures over `this` and a pointer to the `Connection` — but `connections_` is a `std::vector`, so the `Connection` can move; to keep the closure's pointer stable, capture the `upstream_device` by value for the request side and capture `this` for the response side (which looks up nothing connection-local).

```cpp
namespace {

// The fixed header set the proxy rewrites, expressed as the HeaderRewrite the HttpFraming calls per
// rewritable header. Request side: swap any Host matching the upstream device to that same device
// (identity is fine — the upstream expects its own authority; rewriting Host is a no-op authority swap
// here, kept for symmetry/explicitness). Response side: Application-URL/Location -> a REST listener.

} // namespace

void DialProxy::OnListenerReadable(int listener_fd) noexcept {
    const auto endpoint = std::ranges::find_if(endpoints_,
        [listener_fd](const Endpoint& e) { return e.listener.Fd() == listener_fd; });
    if (endpoint == endpoints_.end()) {
        return;  // listener gone (raced with eviction)
    }
    // Drain every pending client (the listener is level-triggered; accept until EAGAIN).
    while (auto client = endpoint->listener.Accept()) {
        endpoint->last_active = std::chrono::steady_clock::now();
        if (connections_.size() >= tunables_.max_connections) {
            logger_.Warning("Dropping DIAL connection: {} in flight (cap reached)", connections_.size());
            // client RAII-closes here (drop-new)
            continue;
        }
        StartConnection(*endpoint, std::move(*client));
    }
}

void DialProxy::StartConnection(Endpoint& endpoint, TcpSocket client) {
    auto upstream = TcpSocket::Connect(endpoint.device, source_if_addr_, target_if_name_);
    if (!upstream.has_value()) {
        logger_.Error("Cannot connect DIAL upstream to {}:{}", endpoint.device.addr, endpoint.device.port);
        return;  // client RAII-closes
    }

    const int client_fd = client.Fd();
    const int upstream_fd = upstream->Fd();
    const IpEndpoint upstream_device = endpoint.device;

    // Request side: rewrite Host naming the upstream device to the upstream device (identity swap;
    // the device expects its own authority). Returns the device endpoint for any matched authority.
    HttpFraming::HeaderRewrite request_rewrite =
        [upstream_device](HttpFraming::Side, const IpEndpoint&) -> std::optional<IpEndpoint> {
            return upstream_device;
        };
    // Response side: Application-URL / 201 Location naming the upstream device -> a REST listener's
    // reflector authority (spun up on first sight). nullopt (cap/bind) leaves the header unchanged.
    HttpFraming::HeaderRewrite response_rewrite =
        [this](HttpFraming::Side, const IpEndpoint& found) -> std::optional<IpEndpoint> {
            return EnsureRestListener(found);
        };

    auto client_reg = dispatcher_.Register(client_fd,
        CreateDelegate<&DialProxy::OnConnectionReadable>(this),
        CreateDelegate<&DialProxy::OnConnectionWritable>(this));
    auto upstream_reg = dispatcher_.Register(upstream_fd,
        CreateDelegate<&DialProxy::OnConnectionReadable>(this),
        CreateDelegate<&DialProxy::OnConnectionWritable>(this));
    if (!client_reg.IsValid() || !upstream_reg.IsValid()) {
        logger_.Error("Cannot register DIAL connection fds");
        return;  // both sockets + any valid registration RAII-drop
    }
    // Watch upstream writability so connect completion (EINPROGRESS -> writable) wakes us.
    if (!dispatcher_.SetWriteInterest(upstream_fd, true)) {
        logger_.Error("Cannot arm DIAL upstream write interest");
        return;
    }

    connections_.push_back(Connection{
        .client = std::move(client),
        .upstream = std::move(*upstream),
        .client_reg = std::move(client_reg),
        .upstream_reg = std::move(upstream_reg),
        .c2u = HttpFraming{HttpFraming::Side::Request, tunables_.max_header_bytes, std::move(request_rewrite)},
        .u2c = HttpFraming{HttpFraming::Side::Response, tunables_.max_header_bytes, std::move(response_rewrite)},
        .pending_to_client = {},
        .pending_to_upstream = {},
        .phase = Phase::Connecting,
        .deadline = std::chrono::steady_clock::now() + tunables_.connect_timeout,
        .upstream_device = upstream_device,
    });
    ArmEvictionTimer();
    logger_.Debug("Started DIAL connection to {}:{} (connecting)", upstream_device.addr, upstream_device.port);
}

DialProxy::Connection* DialProxy::FindConnection(int fd, bool& is_client) noexcept {
    for (auto& connection : connections_) {
        if (connection.client.Fd() == fd) {
            is_client = true;
            return &connection;
        }
        if (connection.upstream.Fd() == fd) {
            is_client = false;
            return &connection;
        }
    }
    return nullptr;
}

void DialProxy::OnConnectionWritable(int fd) noexcept {
    bool is_client = false;
    Connection* connection = FindConnection(fd, is_client);
    if (connection == nullptr) {
        return;
    }
    if (connection->phase == Phase::Connecting) {
        CompleteConnect(*connection);  // upstream-side writable while connecting == connect result
        return;
    }
    Flush(*connection, is_client);  // Task 4.4
}

void DialProxy::CompleteConnect(Connection& connection) noexcept {
    const int upstream_fd = connection.upstream.Fd();
    const int error = connection.upstream.SoError();
    if (error != 0) {
        logger_.Debug("DIAL upstream connect to {}:{} failed (errno {})",
            connection.upstream_device.addr, connection.upstream_device.port, error);
        DropConnection(upstream_fd);  // Task 4.4
        return;
    }
    // Connected: stop waiting on writability (nothing buffered yet) and start forwarding both ways.
    (void)dispatcher_.SetWriteInterest(upstream_fd, false);
    connection.phase = Phase::Open;
    connection.deadline = std::chrono::steady_clock::now() + IdleGrace(Role::Rest);
    logger_.Debug("DIAL upstream to {}:{} open", connection.upstream_device.addr,
        connection.upstream_device.port);
}
```

  Add `max_header_bytes` to `Tunables` in `dial_proxy.h` (used by the `HttpFraming` ctors above):

```cpp
        size_t max_header_bytes = 64 * 1024;
```

- [ ] **Step 4: Run — expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyRequiresRootTest' --output-on-failure
```
Expected (with privilege): accept-starts-connect, connect-completion-disarms, and max-connections-drop-new pass; the earlier `DialProxyTest`/`DialProxySendBufferTest` cases stay green. (`DropConnection`/`Flush`/`Forward` are still stubs but aren't reached by these three cases on the happy path — `CompleteConnect`'s success branch and drop-new are what they assert.)

### Task 4.4: Forward, flush, drop, and read-interest flow control (RequiresRoot)

This is the corrected core. `OnConnectionReadable` reads into a scratch buffer, feeds the per-direction `HttpFraming`, and writes the forwardable bytes to the peer. A short/`WouldBlock` write appends the remainder to the **peer's** `SendBuffer` and `SetWriteInterest(peer, true)`. **Flow control is kernel read interest:** when the peer's `SendBuffer` reaches `HIGH_WATER`, `SetReadInterest(source, false)` so the kernel stops delivering readable events for the source (no busy-spin on the level-triggered reactor). `Flush` (the peer's writable path) drains the `SendBuffer`; when it falls below `LOW_WATER`, `SetReadInterest(source, true)` to resume — the reactor then delivers the source's next readable event naturally. There is **no** `*_read_paused` bool and **no** read-pause early-return in `OnConnectionReadable`. EOF/error tears the pair down.

**Files**
- Modify: `src/reflector/dial_proxy.cpp` (`OnConnectionReadable`, `Forward`, `Flush`, `DropConnection`)
- Modify: `tests/dial_proxy_test.cpp` (forwarding-with-rewrite + the flow-control case)

- [ ] **Step 1: Write the failing forward + flow-control tests.** Append to `tests/dial_proxy_test.cpp`. The forwarding test sends a real GET through the proxy, has the device reply with an `Application-URL` header, and asserts the client sees a rewritten authority (and a REST listener was spun up). The flow-control test is the load-bearing one: it pushes the peer's `SendBuffer` past `HIGH_WATER` and asserts `IsReadArmed(source)==false` + `IsWriteArmed(peer)==true`, then drains via `FireWritable` and asserts `IsReadArmed(source)==true` + `IsWriteArmed(peer)==false`.

  To make the flow-control assertion deterministic without depending on socket-buffer sizes, the fixture uses tiny water marks and a peer (the device upstream) that never reads — so every forwarded byte backs up into `pending_to_upstream`. A small `HIGH_WATER` is crossed by one client write.

```cpp
TEST_F(DialProxyRequiresRootTest, ForwardsRequestAndRewritesApplicationUrlResponse) {
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());

    auto client = ConnectClient(*authority);
    ASSERT_TRUE(client.has_value());
    proxy_fire_listener(proxy, Reactor());
    auto upstream = AcceptAtDevice();
    ASSERT_TRUE(upstream.has_value());
    const int upstream_fd = proxy_upstream_fd(Reactor());
    ASSERT_GE(upstream_fd, 0);
    const int client_fd = proxy_other_conn_fd(Reactor(), upstream_fd);  // the connection's client side
    ASSERT_GE(client_fd, 0);
    Reactor().FireWritable(upstream_fd);  // complete connect -> Open

    // Client sends a description GET; fire its readable so the proxy forwards it upstream.
    const auto request = Bytes("GET / HTTP/1.1\r\nHost: " + AuthorityText(*authority) + "\r\n\r\n");
    ASSERT_EQ(client->Write(request).status, TcpSocket::IoStatus::Ok);
    Reactor().FireReadable(client_fd);

    // The device receives the forwarded request.
    std::array<std::byte, 512> scratch{};
    const auto got = ReadBlocking(*upstream, scratch);
    EXPECT_NE(ToText(std::span{scratch.data(), got}).find("GET / HTTP/1.1"), std::string::npos);

    // Device replies with an Application-URL pointing at its REST endpoint on a different port.
    const auto rest_authority = std::format("{}:{}", IpAddress::LoopbackV4().ToString(), 36866);
    const auto response = Bytes(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Application-URL: http://" + rest_authority + "/apps\r\n\r\n");
    ASSERT_EQ(upstream->Write(response).status, TcpSocket::IoStatus::Ok);
    Reactor().FireReadable(upstream_fd);  // proxy reads, rewrites, forwards to client

    // The client reads back a response whose Application-URL is now a reflector authority (NOT 36866's
    // device authority): a REST listener was spun up and named.
    const auto seen = ToText(std::span{scratch.data(), ReadBlocking(*client, scratch)});
    EXPECT_NE(seen.find("Application-URL: http://"), std::string::npos) << seen;
    EXPECT_EQ(seen.find(":36866"), std::string::npos) << seen;  // device REST port no longer present
}

TEST_F(DialProxyRequiresRootTest, BackpressurePausesSourceReadAtHighWaterAndResumesOnDrain) {
    tunables.high_water = 8;   // tiny so one client write crosses it
    tunables.low_water = 4;
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());

    auto client = ConnectClient(*authority);
    ASSERT_TRUE(client.has_value());
    proxy_fire_listener(proxy, Reactor());
    auto upstream = AcceptAtDevice();  // the device NEVER reads -> upstream send buffer fills/backs up
    ASSERT_TRUE(upstream.has_value());
    const int upstream_fd = proxy_upstream_fd(Reactor());
    ASSERT_GE(upstream_fd, 0);
    const int client_fd = proxy_other_conn_fd(Reactor(), upstream_fd);
    ASSERT_GE(client_fd, 0);
    Reactor().FireWritable(upstream_fd);  // Open

    // Stuff the kernel upstream send buffer so the proxy's Write to upstream short-writes and the
    // remainder backs up into pending_to_upstream past HIGH_WATER. A large client payload + an
    // unread upstream guarantees the backlog. Fill the device-side recv window first by writing a lot.
    const std::vector<std::byte> big(256 * 1024, std::byte{'x'});
    ASSERT_EQ(client->Write(big).status, TcpSocket::IoStatus::Ok);  // kernel buffers it client-side
    // Drive the proxy: it reads from client_fd, writes toward the (unread, full) upstream, short-writes,
    // and buffers the remainder. Pump until the source read is paused.
    for (int i = 0; i < 200 && Reactor().IsReadArmed(client_fd); ++i) {
        Reactor().FireReadable(client_fd);
    }

    // FLOW CONTROL: past HIGH_WATER the source (client) read is disarmed and the peer (upstream) write
    // is armed so the backlog drains on writability.
    EXPECT_FALSE(Reactor().IsReadArmed(client_fd));
    EXPECT_TRUE(Reactor().IsWriteArmed(upstream_fd));

    // Let the device drain its socket so the proxy's buffered bytes can flush.
    std::array<std::byte, 64 * 1024> sink{};
    for (int i = 0; i < 64; ++i) {
        if (ReadOnce(*upstream, sink) == 0) {
            break;
        }
    }
    // Firing the upstream writable runs Flush, which drains pending_to_upstream below LOW_WATER and
    // re-arms the source read; with the buffer empty it also disarms the peer write.
    for (int i = 0; i < 200 && !Reactor().IsReadArmed(client_fd); ++i) {
        // keep the device draining as we flush
        ReadOnce(*upstream, sink);
        Reactor().FireWritable(upstream_fd);
    }

    EXPECT_TRUE(Reactor().IsReadArmed(client_fd));
    EXPECT_FALSE(Reactor().IsWriteArmed(upstream_fd));
}
```

  Add the small test helpers used above to `tests/dial_proxy_test.cpp` (namespace `reflector`, anon namespace):

```cpp
std::string AuthorityText(const IpEndpoint& endpoint) {
    return std::format("{}:{}", endpoint.addr.ToString(), endpoint.port);
}

// The other side of the single connection: the connection fd that is not `known_fd` and is not a
// listener (listeners are the ones with NO write callback armed AND present from the start). In these
// tests the watched set is {listener, client, upstream}; given the upstream fd, the client is the
// remaining non-listener fd. We identify the listener as the smallest watched fd (registered first).
int proxy_other_conn_fd(FakeDispatcher& reactor, int known_fd) {
    const auto fds = reactor.WatchedFds();
    const int listener = *std::ranges::min_element(fds);
    for (const int fd : fds) {
        if (fd != known_fd && fd != listener) {
            return fd;
        }
    }
    return -1;
}

size_t ReadOnce(TcpSocket& socket, std::span<std::byte> into) {
    const auto result = socket.Read(into);
    return result.n;
}

size_t ReadBlocking(TcpSocket& socket, std::span<std::byte> into) {
    for (int i = 0; i < 200; ++i) {
        const auto result = socket.Read(into);
        if (result.n > 0) {
            return result.n;
        }
        if (result.status == TcpSocket::IoStatus::Closed || result.status == TcpSocket::IoStatus::Error) {
            return 0;
        }
        pollfd pfd{.fd = socket.Fd(), .events = POLLIN, .revents = 0};
        ::poll(&pfd, 1, 50);
    }
    return 0;
}
```

  (`<format>` and `<poll.h>` come in via `test_helpers.h`; add `#include <format>` to the test file's includes to be explicit.)

- [ ] **Step 2: Run — expect FAIL.** `Forward`/`Flush`/`DropConnection` are stubs, so nothing is forwarded and no read interest is toggled:

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyRequiresRootTest' --output-on-failure
```
Expected (with privilege): the forward-rewrite and backpressure cases FAIL (device receives nothing; `IsReadArmed(client_fd)` never goes false). SKIP unprivileged.

- [ ] **Step 3: Implement forward, flush, drop, and read-interest flow control.** Replace the stubs in `dial_proxy.cpp`. Note the direction bookkeeping: forwarding client→upstream fills `pending_to_upstream`; the *source* whose read we pause is the client; the *peer* whose write we arm is the upstream. `Flush(connection, to_client=false)` drains `pending_to_upstream` and re-arms the client read.

```cpp
void DialProxy::OnConnectionReadable(int fd) noexcept {
    bool is_client = false;
    Connection* connection = FindConnection(fd, is_client);
    if (connection == nullptr) {
        return;
    }
    // No read-pause bool and no early-return: the pause IS the disarmed kernel read interest, so if
    // we are invoked the kernel decided this fd is readable and we must drain it.
    Forward(*connection, is_client);
}

void DialProxy::Forward(Connection& connection, bool from_client) noexcept {
    TcpSocket& source = from_client ? connection.client : connection.upstream;
    TcpSocket& peer = from_client ? connection.upstream : connection.client;
    HttpFraming& framing = from_client ? connection.c2u : connection.u2c;
    SendBuffer& peer_buffer = from_client ? connection.pending_to_upstream : connection.pending_to_client;
    const int source_fd = source.Fd();
    const int peer_fd = peer.Fd();

    std::array<std::byte, 32 * 1024> scratch{};
    const auto read = source.Read(scratch);
    if (read.status == TcpSocket::IoStatus::Closed || read.status == TcpSocket::IoStatus::Error) {
        DropConnection(source_fd);
        return;
    }
    if (read.n == 0) {
        return;  // WouldBlock: nothing to do
    }
    connection.deadline = std::chrono::steady_clock::now() + IdleGrace(Role::Rest);

    std::vector<std::byte> forwardable;
    if (framing.Feed(std::span{scratch.data(), read.n}, forwardable) == HttpFraming::Status::Error) {
        logger_.Warning("DIAL header block too large; closing connection");
        DropConnection(source_fd);
        return;
    }

    // If the peer already has a backlog, append and let Flush carry it (preserve byte order).
    std::span<const std::byte> to_write{forwardable};
    if (peer_buffer.Size() == 0 && !to_write.empty()) {
        const auto written = peer.Write(to_write);
        if (written.status == TcpSocket::IoStatus::Closed || written.status == TcpSocket::IoStatus::Error) {
            DropConnection(peer_fd);
            return;
        }
        to_write = to_write.subspan(written.n);
    }
    if (!to_write.empty()) {
        peer_buffer.Append(to_write);
        (void)dispatcher_.SetWriteInterest(peer_fd, true);  // flush on the peer's writability
    }

    // FLOW CONTROL: if the peer's backlog reached HIGH_WATER, stop the kernel delivering readable
    // events for the SOURCE (disarmed read interest, not a userland skip), so a level-triggered
    // reactor can't busy-spin and the backlog can't grow unboundedly.
    if (peer_buffer.Size() >= tunables_.high_water) {
        (void)dispatcher_.SetReadInterest(source_fd, false);
    }
}

void DialProxy::Flush(Connection& connection, bool to_client) noexcept {
    TcpSocket& peer = to_client ? connection.client : connection.upstream;
    SendBuffer& peer_buffer = to_client ? connection.pending_to_client : connection.pending_to_upstream;
    TcpSocket& source = to_client ? connection.upstream : connection.client;
    const int peer_fd = peer.Fd();
    const int source_fd = source.Fd();

    while (peer_buffer.Size() > 0) {
        const auto written = peer.Write(peer_buffer.View());
        if (written.status == TcpSocket::IoStatus::Closed || written.status == TcpSocket::IoStatus::Error) {
            DropConnection(peer_fd);
            return;
        }
        if (written.n == 0) {
            break;  // WouldBlock: stay armed for the next writable
        }
        peer_buffer.Consume(written.n);
    }
    if (peer_buffer.Size() == 0) {
        (void)dispatcher_.SetWriteInterest(peer_fd, false);  // nothing buffered: stop the writable-spin
    }
    // FLOW CONTROL: once the backlog drains below LOW_WATER, resume reading the SOURCE. Re-arming
    // makes the reactor deliver the source's next readable event naturally — do NOT re-pump here.
    if (peer_buffer.Size() < tunables_.low_water) {
        (void)dispatcher_.SetReadInterest(source_fd, true);
    }
}

void DialProxy::DropConnection(int fd) noexcept {
    bool is_client = false;
    if (FindConnection(fd, is_client) == nullptr) {
        return;
    }
    std::erase_if(connections_, [fd](const Connection& connection) {
        return connection.client.Fd() == fd || connection.upstream.Fd() == fd;
    });
    // RAII: erasing the Connection closes both sockets and drops both reactor registrations.
}
```

  Add `<array>` and `<span>` to the `dial_proxy.cpp` includes (`std::array`/`std::span` scratch + spans).

- [ ] **Step 4: Run — expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyRequiresRootTest' --output-on-failure
```
Expected (with privilege): forward-with-rewrite and the backpressure case pass — past `HIGH_WATER` `IsReadArmed(client_fd)==false` and `IsWriteArmed(upstream_fd)==true`; after draining via `FireWritable`, `IsReadArmed(client_fd)==true` and `IsWriteArmed(upstream_fd)==false`. All earlier cases stay green.

### Task 4.5: Eviction Timer — connect-deadline, idle, and role-based endpoint idle

The lazy-start/self-stop eviction `Timer` (mirroring SSDP's) sweeps: `Connection`s past their `Connecting` connect-deadline or their `Open` idle-deadline; and `Endpoint`s whose `last_active` is older than the role's idle grace **and** which no live connection references. `ArmEvictionTimer` starts the timer on first endpoint/connection; `EvictExpired` stops it when both tables are empty. These cases drive `FireTimers` and need no privilege (endpoints alone, and a `Connecting` connection can be created without a real upstream by... actually a connect-deadline test needs a started connection). To keep this task privilege-free, the connect-deadline case is exercised by stuffing a connection through the same loopback path under the RequiresRoot fixture; the endpoint-idle case runs unprivileged with listeners only.

**Files**
- Modify: `src/reflector/dial_proxy.cpp` (`ArmEvictionTimer`, `EvictExpired`)
- Modify: `tests/dial_proxy_test.cpp` (endpoint-idle eviction unprivileged; connect-deadline under RequiresRoot)

- [ ] **Step 1: Write the failing eviction tests.** Append the unprivileged endpoint-idle case to `DialProxyTest` and the connect-deadline case to `DialProxyRequiresRootTest`.

```cpp
// --- in DialProxyTest (unprivileged: listeners only) ---

TEST_F(DialProxyTest, ArmsEvictionTimerOnlyWhenEndpointsExist) {
    DialProxy proxy = MakeProxy();
    EXPECT_EQ(Reactor().TimerCount(), 0u);  // nothing to sweep -> no timer

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(80, 1461)).has_value());
    EXPECT_EQ(Reactor().TimerCount(), 1u);  // armed for the first endpoint
}

TEST_F(DialProxyTest, IdleDiscoveryListenerIsReapedAndTimerDisarmsWhenEmpty) {
    tunables.discovery_idle = std::chrono::milliseconds{1000};
    DialProxy proxy = MakeProxy();
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(80, 1461)).has_value());
    ASSERT_EQ(Reactor().RegistrationCount(), 1u);  // the listener's accept registration
    ASSERT_EQ(Reactor().TimerCount(), 1u);

    // Sweeping before the idle grace keeps the listener and the timer.
    Reactor().FireTimers(std::chrono::steady_clock::now());
    EXPECT_EQ(Reactor().RegistrationCount(), 1u);
    EXPECT_EQ(Reactor().TimerCount(), 1u);

    // Sweeping past the discovery idle grace reaps the listener (releasing its registration); with
    // both tables empty, the sweep disarms its own timer.
    Reactor().FireTimers(std::chrono::steady_clock::now() + std::chrono::seconds{10});
    EXPECT_EQ(Reactor().RegistrationCount(), 0u);
    EXPECT_EQ(Reactor().TimerCount(), 0u);
}

TEST_F(DialProxyTest, RestListenerSurvivesTheShorterDiscoveryGrace) {
    tunables.discovery_idle = std::chrono::milliseconds{1000};
    tunables.rest_idle = std::chrono::hours{1};
    DialProxy proxy = MakeProxy();
    DialProxyRestPeek peek{proxy};
    ASSERT_TRUE(peek.EnsureRest(Device(80, 36866)).has_value());

    // 10s ahead is well past the 1s discovery grace but far inside the 1h REST cooldown: kept.
    Reactor().FireTimers(std::chrono::steady_clock::now() + std::chrono::seconds{10});
    EXPECT_EQ(Reactor().RegistrationCount(), 1u);
}
```

```cpp
// --- in DialProxyRequiresRootTest (a real Connecting connection) ---

TEST_F(DialProxyRequiresRootTest, StuckConnectingConnectionIsReapedAtTheConnectDeadline) {
    tunables.connect_timeout = std::chrono::milliseconds{1000};
    DialProxy proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device_endpoint);
    ASSERT_TRUE(authority.has_value());

    auto client = ConnectClient(*authority);
    ASSERT_TRUE(client.has_value());
    proxy_fire_listener(proxy, Reactor());
    ASSERT_TRUE(AcceptAtDevice().has_value());
    const size_t with_connection = Reactor().RegistrationCount();  // listener + client + upstream = 3
    ASSERT_EQ(with_connection, 3u);

    // We never fire the upstream writable, so the connection stays in Connecting. Sweeping past the
    // connect deadline reaps the pair (RAII drops both connection fds), leaving only the listener.
    Reactor().FireTimers(std::chrono::steady_clock::now() + std::chrono::seconds{10});
    EXPECT_EQ(Reactor().RegistrationCount(), 1u);  // just the listener
}
```

- [ ] **Step 2: Run — expect FAIL.** `ArmEvictionTimer`/`EvictExpired` are no-ops, so the timer never arms and nothing is reaped:

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyTest|DialProxyRequiresRootTest' --output-on-failure
```
Expected: `ArmsEvictionTimerOnlyWhenEndpointsExist` FAILs (`TimerCount` stays 0), the idle/connect-deadline reaps FAIL (registration counts don't drop). Earlier cases stay green; the RequiresRoot case SKIPs unprivileged.

- [ ] **Step 3: Implement ArmEvictionTimer and EvictExpired.** Replace the stubs in `dial_proxy.cpp`. An `Endpoint` is reaped only when no live `Connection` connects upstream to its device (so an active flow keeps its listener warm) and its `last_active` is older than the role's grace.

```cpp
void DialProxy::ArmEvictionTimer() {
    if (!eviction_timer_.IsRunning()) {
        eviction_timer_.Start(tunables_.eviction_interval,
            CreateDelegate<&DialProxy::EvictExpired>(this));
    }
}

void DialProxy::EvictExpired(std::chrono::steady_clock::time_point now) noexcept {
    // 1) Connections past their deadline (connect deadline while Connecting, idle deadline once Open).
    const auto dropped = std::erase_if(connections_, [this, now](const Connection& connection) {
        const bool expired = connection.deadline <= now;
        if (expired) {
            logger_.Debug("Reaping DIAL connection to {}:{} ({})", connection.upstream_device.addr,
                connection.upstream_device.port,
                connection.phase == Phase::Connecting ? "connect timeout" : "idle");
        }
        return expired;
    });

    // 2) Idle endpoints: no live connection references the device endpoint AND last_active is older
    //    than the role's grace. An in-use listener is never reaped (a live connection holds it warm).
    const auto reaped = std::erase_if(endpoints_, [this, now](const Endpoint& endpoint) {
        const bool referenced = std::ranges::any_of(connections_,
            [&](const Connection& connection) { return connection.upstream_device == endpoint.device; });
        if (referenced) {
            return false;
        }
        const bool idle = endpoint.last_active + IdleGrace(endpoint.role) <= now;
        if (idle) {
            logger_.Debug("Reaping idle DIAL {} listener for {}:{}",
                endpoint.role == Role::Rest ? "REST" : "discovery", endpoint.device.addr, endpoint.device.port);
        }
        return idle;
    });

    if (dropped > 0 || reaped > 0) {
        logger_.Debug("Evicted {} connection(s), {} listener(s); {} conns / {} listeners left",
            dropped, reaped, connections_.size(), endpoints_.size());
    }
    if (connections_.empty() && endpoints_.empty()) {
        eviction_timer_.Stop();  // nothing left to sweep; safe self-stop (the merge-walk tolerates it)
    }
}
```

- [ ] **Step 4: Run — expect PASS.**

```sh
cmake --build build
ctest --test-dir build -R 'DialProxyTest|DialProxyRequiresRootTest' --output-on-failure
```
Expected: arm-on-first-endpoint, idle-discovery-reap-and-disarm, rest-survives-discovery-grace, and (with privilege) stuck-connecting-reaped pass; everything in Tasks 4.1–4.4 stays green.

### Task 4.6: Full gate and commit

`dial_proxy` is a data-path component, so the full gate (native unit + docker debug/release + e2e) runs before commit, per the project test policy.

**Files**
- (none — verification + commit only)

- [ ] **Step 1: Confirm the Debug build is sanitized.** The default unit run must be ASan/UBSan-instrumented; a stale cached `OFF` silently disables it:

```sh
grep REFLECTOR_SANITIZE build/CMakeCache.txt
```
Expected: `REFLECTOR_SANITIZE...=ON`. If it shows `OFF`, `rm -rf build` then `./cmake_gen.sh` before proceeding.

- [ ] **Step 2: Run the full native unit suite (Debug, ASan/UBSan).**

```sh
ctest --test-dir build -L unit --output-on-failure
```
Expected: all green, including the unprivileged `DialProxyTest`/`DialProxySendBufferTest` cases and every pre-existing suite. The `DialProxyRequiresRootTest` cases run if privileged, else SKIP.

- [ ] **Step 3: Run the root-labeled cases explicitly (so the connect/forward/flow-control path is actually exercised, not silently skipped).**

```sh
ctest --test-dir build -L root --output-on-failure
```
Expected: the `DialProxyRequiresRootTest` cases pass (or SKIP with a clear privilege message on an under-privileged box — in which case run them in the docker gate below, which has the privileges).

- [ ] **Step 4: Run the docker gate (Debug then Release), where capture/connect privileges exist.**

```sh
./docker_test.sh
./docker_test.sh release
```
Expected: both green; the RequiresRoot DIAL cases run for real inside the container.

- [ ] **Step 5: Run the e2e gate.**

```sh
python3 e2e/run.py
```
Expected: green (the e2e DIAL emulator round-trip lands in Commit 6; the existing e2e suite must stay green now).

- [ ] **Step 6: Commit.** One commit for this section, after the gate is green.

```sh
git add src/reflector/dial_proxy.h src/reflector/dial_proxy.cpp \
        src/reflector/CMakeLists.txt \
        tests/dial_proxy_test.cpp tests/CMakeLists.txt \
        tests/mocks/fake_dispatcher.h
git commit -m "dial_proxy: orchestrate per-endpoint listeners, connection pump, read-interest flow control, and eviction timer"
```

Notes for the integrator: file paths are `/Users/sergii/code/reflector/src/reflector/dial_proxy.h`, `/Users/sergii/code/reflector/src/reflector/dial_proxy.cpp`, `/Users/sergii/code/reflector/tests/dial_proxy_test.cpp`. The flow-control correctness contract is realized entirely in Task 4.4's `Forward` (`SetReadInterest(source_fd, false)` at `HIGH_WATER`) and `Flush` (`SetReadInterest(source_fd, true)` below `LOW_WATER`); there is no `*_read_paused` bool and no read-pause early-return in `OnConnectionReadable`, exactly as the corrected contract requires. The `WatchedFds()` accessor added to `tests/mocks/fake_dispatcher.h` is the only mock change beyond Commit 1's `FireWritable`/`IsReadArmed`/`IsWriteArmed`/`SetReadInterest`/`SetWriteInterest`.

## Commit 5: ssdp_reflector + config: add the `dial` flag, tunables, Verify rules, and the DIAL LOCATION rewrite

This commit wires the (already-built, Commit 4) `DialProxy` into the SSDP path. It adds the `dial` flag and its tunables to `SsdpConfig` (with `Verify` rejections and the formatter), parses them from the `[name]` TOML table, adds two small SSDP-side DIAL helpers (service-type classification + LOCATION-authority parse) to `ssdp_message.{h,cpp}`, and splices a reflector authority into the `LOCATION` of a DIAL `200 OK`/`NOTIFY` before injection. It depends on the contract types `IpEndpoint` (Commit 2), `RewriteAuthority` (Commit 3), and `DialProxy::EnsureDiscoveryListener` (Commit 4).

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
