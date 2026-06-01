# SSDP Unicast M-SEARCH Response Proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make active SSDP discovery work across segments by capturing each device's unicast `HTTP/1.1 200 OK` reply on `target_if` and forwarding it back to the original searcher on `source_if`.

**Architecture:** Per relayed `M-SEARCH`, allocate a reflector-owned ephemeral UDP port `P` (a bound-but-never-read `PortReservation` socket that suppresses the kernel's ICMP port-unreachable), re-emit the M-SEARCH from `P`, and register a raw-capture for the unicast `200 OK` destined to our own interface address on `P`. On capture, look the session up by `P` and raw-inject the reply to the stored searcher. Sessions expire `MX + grace` after creation, swept by a periodic reactor timer. Single-threaded throughout — no worker threads, no locks.

**Tech Stack:** C++23, CMake, GoogleTest, AF_PACKET (Linux) / BPF (macOS) raw sockets, epoll/kqueue reactor, Python stdlib e2e harness over Docker.

**Spec:** `docs/superpowers/specs/2026-05-30-ssdp-unicast-proxy-design.md`

---

## Conventions (read once before starting)

These hold for every task; they are not repeated per step.

- **Build (Debug, ASan+UBSan):** `./cmake_gen.sh` then `cmake --build build`. Before trusting test results, confirm sanitizers are on: `grep REFLECTOR_SANITIZE build/CMakeCache.txt` shows `ON`.
- **Run unit tests:** `ctest --test-dir build -L unit --output-on-failure`. A single test: `ctest --test-dir build -L unit -R '<gtest-name>' --output-on-failure` (names are prefixed `unit.`, e.g. `unit.TimerTest.FiresWhenDue`).
- **Includes:** project headers first (`"reflector/..."` / `"..."`), then a blank line, then system/std headers — match each file's existing block.
- **Comments:** only non-obvious *why*. No restating *what* the code does. Match the density of the file you are editing.
- **RAII over manual cleanup.** Output parameters last. `[[nodiscard]]` on bool/optional returns that callers must check (match neighbours).
- **Commit:** never run `git commit` unless this plan's step says to AND the operator has given per-batch permission. Commits run in-sandbox (do not disable the sandbox for git).
- **Full gate before the data-path commits** (Tasks 5 and 6 touch capture/inject): native `ctest -L unit` + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`. Tasks 1–4 are pure logic/infra; native `ctest -L unit` is the gate for those (plus a Debug build, which compiles the whole tree).
- **New files must be added to CMake** — `src/reflector/CMakeLists.txt` (library `.cpp`s) and `tests/CMakeLists.txt` (the single `reflector_test` exe). A new `.cpp` that isn't listed silently won't compile.

---

## File Structure

**New source files:**
- `src/reflector/port_reservation.h` / `.cpp` — RAII ephemeral-port allocator + ICMP suppressor.
- `src/reflector/timer.h` — RAII handle owning a dispatcher timer registration (header-only, like the fakes' style; trivial enough to inline).

**Modified source files:**
- `src/reflector/dispatcher.h` — add `OnTimerCallback`, `TimerId`, `RegisterTimer`, `UnregisterTimer`.
- `src/reflector/event_loop_dispatcher.h` / `.cpp` — timer storage; `RegisterTimer`/`UnregisterTimer`; public `FireDueTimers(now)` + `NextTimeout(now)`; `Run` drives them; `PollOnce` unchanged.
- `src/reflector/packet_dispatcher.h` — add `UnderlyingDispatcher()`.
- `src/reflector/default_packet_dispatcher.h` / `.cpp` — implement `UnderlyingDispatcher()`.
- `src/reflector/link_socket.h` — add `SendUnicastUdpDatagram(...)` and `SourceAddress(family)`.
- `src/reflector/raw_socket.h` / `.cpp` — implement both new `LinkSocket` methods.
- `src/reflector/ssdp_message.h` / `.cpp` — add `ParseMSearchMx(...)`.
- `src/reflector/ssdp_reflector.h` / `.cpp` — session table, reserved-port relay, `OnUnicastResponse`, eviction.

**Modified test/mock files:**
- `tests/mocks/fake_dispatcher.h` — implement timer API + `FireTimers()` helper.
- `tests/mocks/fake_packet_dispatcher.h` — own a `FakeDispatcher`; implement `UnderlyingDispatcher()`.
- `tests/mocks/fake_link_socket.h` — implement `SendUnicastUdpDatagram` (record) + `SourceAddress` (configurable).
- New test files: `tests/port_reservation_test.cpp`, `tests/timer_test.cpp`. Extend `tests/event_loop_dispatcher_test.cpp`, `tests/ssdp_message_test.cpp`, `tests/ssdp_reflector_test.cpp`.

**Modified e2e/docs:**
- `e2e/probe.py`, `e2e/run.py` — active-search round-trip cases.
- `README.md` — SSDP section: step 2 done; proxy always-on; `mac` scope.

---

## Task 1: `PortReservation` — ephemeral-port allocator + ICMP suppressor

**Files:**
- Create: `src/reflector/port_reservation.h`, `src/reflector/port_reservation.cpp`
- Modify: `src/reflector/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/port_reservation_test.cpp`

**What it is:** a move-only RAII type that opens a UDP socket, binds it to an OS-assigned ephemeral port on the wildcard address, reads the port back via `getsockname`, and (on Linux) attaches a drop-all BPF filter so the bound socket enqueues nothing. The socket is never read; it exists only so the kernel's UDP socket lookup succeeds and no ICMP port-unreachable is emitted for the `200 OK`. Closes the fd on destruction.

- [ ] **Step 1: Add the new source files to CMake (so they compile from the first build)**

In `src/reflector/CMakeLists.txt`, add the `.cpp` to the `add_library(reflector STATIC ...)` list (keep the existing ordering style), after the `mdns_message.cpp` line:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/mdns_message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/port_reservation.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message.cpp
```

In `tests/CMakeLists.txt`, add the test to the `add_executable(reflector_test ...)` list, after `mdns_reflector_test.cpp`:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/port_reservation_test.cpp
```

- [ ] **Step 2: Write the header**

Create `src/reflector/port_reservation.h`:

```cpp
#pragma once

#include "ip_address.h"

#include <cstdint>
#include <optional>

namespace reflector {

// A reservation over a single ephemeral UDP port. SSDP step 2 re-emits a relayed M-SEARCH from this
// port so devices unicast their 200 OK back to it; the port must stay "claimed" for the session's
// lifetime so the kernel's UDP socket lookup succeeds and it does NOT answer the response with an
// ICMP port-unreachable. The bound socket is never read — the real datagram is captured by the raw
// socket. On Linux a drop-all BPF filter makes the socket enqueue nothing; elsewhere it is simply
// never drained. Move-only fd owner.
class PortReservation {
public:
    // Opens and binds a socket to an OS-assigned ephemeral port of `family` on the wildcard address.
    // Returns nullopt (after logging) if the socket/bind/getsockname fails.
    [[nodiscard]] static std::optional<PortReservation> Create(IpAddress::Family family) noexcept;

    PortReservation(PortReservation&& other) noexcept;
    PortReservation& operator=(PortReservation&& other) noexcept;
    ~PortReservation() noexcept;

    [[nodiscard]] uint16_t Port() const noexcept { return port_; }

private:
    PortReservation(int fd, uint16_t port) noexcept : fd_{fd}, port_{port} {}

    int fd_ = -1;
    uint16_t port_ = 0;
};

} // namespace reflector
```

- [ ] **Step 3: Write the failing test**

Create `tests/port_reservation_test.cpp`. (`BindLoopback`/`BoundPort` from `test_helpers.h` are not reused here — `PortReservation` binds the wildcard itself; the ICMP probe uses a connected UDP sender.)

```cpp
#include "reflector/port_reservation.h"

#include "reflector/ip_address.h"

#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace reflector {
namespace {

TEST(PortReservationTest, CreateReturnsANonZeroPort) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_NE(reservation->Port(), 0);
}

TEST(PortReservationTest, TwoReservationsGetDistinctPorts) {
    const auto first = PortReservation::Create(IpAddress::Family::V4);
    const auto second = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->Port(), second->Port());
}

TEST(PortReservationTest, ReservedPortIsClaimed) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());

    // A second plain bind to the same port must fail (EADDRINUSE) while the reservation holds it.
    const int probe = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(reservation->Port());
    EXPECT_NE(::bind(probe, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    EXPECT_EQ(errno, EADDRINUSE);
    ::close(probe);
}

TEST(PortReservationTest, SuppressesIcmpPortUnreachable) {
    // The core guarantee: with the port reserved, a datagram sent to it does NOT bounce an ICMP
    // port-unreachable. A connected UDP sender surfaces that ICMP as ECONNREFUSED on its next recv;
    // we assert the recv times out instead (no ICMP). The mirror "no reservation -> ECONNREFUSED"
    // case is not asserted here: an OS-assigned ephemeral port is not reliably free to re-probe.
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());

    const int sender = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    timeval tv{.tv_sec = 0, .tv_usec = 300000};
    ::setsockopt(sender, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(reservation->Port());
    ASSERT_EQ(::connect(sender, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    const std::byte one{1};
    ASSERT_EQ(::send(sender, &one, 1, 0), 1);

    std::array<std::byte, 8> buffer{};
    const auto received = ::recv(sender, buffer.data(), buffer.size(), 0);
    EXPECT_TRUE(received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "expected timeout (no ICMP), got received=" << received << " errno=" << errno;
    ::close(sender);
}

TEST(PortReservationTest, MoveTransfersOwnershipWithoutDoubleClose) {
    auto first = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(first.has_value());
    const auto port = first->Port();

    PortReservation moved = std::move(*first);
    EXPECT_EQ(moved.Port(), port);
    // No crash / ASan double-close when both `first` (moved-from) and `moved` destruct here.
}

TEST(PortReservationTest, CreateWorksForIpv6) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V6);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_NE(reservation->Port(), 0);
}

} // namespace
} // namespace reflector
```

- [ ] **Step 4: Run the test to verify it fails (link error / not implemented)**

Run: `./cmake_gen.sh && cmake --build build`
Expected: FAIL — `undefined reference to reflector::PortReservation::Create` (or the build stops because `port_reservation.cpp` doesn't exist yet).

- [ ] **Step 5: Write the implementation**

Create `src/reflector/port_reservation.cpp`:

```cpp
#include "port_reservation.h"

#include "error.h"
#include "logger.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#if defined(__linux__)
#include <linux/filter.h>
#endif

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"PortReservation"};
    return logger;
}

} // namespace

std::optional<PortReservation> PortReservation::Create(IpAddress::Family family) noexcept {
    const bool v6 = family == IpAddress::Family::V6;
    const int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        GetLogger().Error("Cannot open reservation socket: {}", Error::FromErrno());
        return std::nullopt;
    }

#if defined(__linux__)
    // Drop every packet at the socket filter: the bind below already suppresses the ICMP NAK, and
    // the real 200 OK is captured by the raw socket — this socket must enqueue nothing.
    sock_filter drop_all[] = {{0x06, 0, 0, 0x00000000}};  // BPF_RET | BPF_K, 0
    sock_fprog program{.len = 1, .filter = drop_all};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) != 0) {
        GetLogger().Error("Cannot attach drop-all filter to reservation socket: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }
#endif

    sockaddr_storage storage{};
    const auto any = v6 ? IpAddress::AnyV6() : IpAddress::AnyV4();
    const socklen_t length = any.ToSockaddr(storage, /*port=*/0);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
        GetLogger().Error("Cannot bind reservation socket: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }

    sockaddr_storage bound{};
    socklen_t bound_length = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
        GetLogger().Error("Cannot read reservation socket port: {}", Error::FromErrno());
        close(fd);
        return std::nullopt;
    }
    const uint16_t port = v6
        ? ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);

    return PortReservation{fd, port};
}

PortReservation::PortReservation(PortReservation&& other) noexcept
        : fd_{std::exchange(other.fd_, -1)}, port_{std::exchange(other.port_, 0)} {}

PortReservation& PortReservation::operator=(PortReservation&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = std::exchange(other.fd_, -1);
        port_ = std::exchange(other.port_, 0);
    }
    return *this;
}

PortReservation::~PortReservation() noexcept {
    if (fd_ >= 0) {
        close(fd_);
    }
}

} // namespace reflector
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cmake --build build && ctest --test-dir build -L unit -R 'PortReservationTest' --output-on-failure`
Expected: PASS (6 tests). The `SuppressesIcmpPortUnreachable` test passes on Linux and macOS (bind alone suppresses the ICMP; the Linux-only filter just additionally prevents enqueue).

- [ ] **Step 7: Full unit-suite check (no regressions)**

Run: `ctest --test-dir build -L unit --output-on-failure`
Expected: PASS (all existing tests still green).

- [ ] **Step 8: Commit (with operator permission)**

```bash
git add src/reflector/port_reservation.h src/reflector/port_reservation.cpp \
        tests/port_reservation_test.cpp src/reflector/CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat(ssdp): add PortReservation (ephemeral port + ICMP suppression)"
```

---

## Task 2: Dispatcher timers + `Timer` RAII + `PacketDispatcher::UnderlyingDispatcher`

This is the largest infra task. It adds a portable reactor timer (the dispatcher owns and fires timers; no `timerfd`/`EVFILT_TIMER`), the RAII `Timer` handle, and the `UnderlyingDispatcher()` getter the reflector uses to reach the reactor. Because two pure-virtual methods are added to interfaces, **the fakes must be updated in the same commit or the whole test binary fails to compile** — that is sequenced below before the build runs.

**Files:**
- Modify: `src/reflector/dispatcher.h`, `src/reflector/event_loop_dispatcher.h`, `src/reflector/event_loop_dispatcher.cpp`, `src/reflector/packet_dispatcher.h`, `src/reflector/default_packet_dispatcher.h`, `src/reflector/default_packet_dispatcher.cpp`
- Modify: `tests/mocks/fake_dispatcher.h`, `tests/mocks/fake_packet_dispatcher.h`
- Create: `src/reflector/timer.h`, `tests/timer_test.cpp`
- Modify: `tests/event_loop_dispatcher_test.cpp`, `src/reflector/CMakeLists.txt` (none — `timer.h` is header-only), `tests/CMakeLists.txt`

- [ ] **Step 1: Add the timer API to the `Dispatcher` interface**

In `src/reflector/dispatcher.h`, add `#include <chrono>` and `#include <cstdint>` to the include block. Add to the `public:` section (after the existing `Register` declaration):

```cpp
    using OnTimerCallback = Delegate<void()>;
    // Strong id so a timer registration is never confused with the fd `int` registration. 0 is the
    // invalid sentinel; real ids start at 1. (RegistrationId/fd-int are still bare types — converging
    // them to strong enums is a tracked follow-up after this step.)
    enum class TimerId : uint64_t {};

    // Registers a periodic timer firing `callback` every `interval` until the returned id is passed
    // to UnregisterTimer. Rejects interval <= 0 and an invalid callback, returning TimerId{} — a
    // non-positive interval would make the timer perpetually due (busy-loop) and an unset Delegate is
    // UB to invoke.
    [[nodiscard]] virtual TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) = 0;
    // Cancels a timer by id; a no-op for an unknown/already-removed id (so a fired callback may
    // cancel its own or another timer safely).
    virtual void UnregisterTimer(TimerId id) noexcept = 0;
```

(No `friend`, no second `Registration<>` instantiation — the named pair is deliberate; see the spec §3.5.)

- [ ] **Step 2: Add the `UnderlyingDispatcher()` getter to `PacketDispatcher`**

In `src/reflector/packet_dispatcher.h`, add a forward declaration `class Dispatcher;` (inside `namespace reflector`, before `class PacketDispatcher`) and this to the `public:` section:

```cpp
    // The reactor this packet dispatcher is layered on — lets a consumer register a Timer on the
    // same single-threaded event loop.
    [[nodiscard]] virtual Dispatcher& UnderlyingDispatcher() noexcept = 0;
```

- [ ] **Step 3: Write the `Timer` RAII handle**

Create `src/reflector/timer.h`:

```cpp
#pragma once

#include "dispatcher.h"

#include <chrono>
#include <utility>

namespace reflector {

// Owns one periodic timer registration on a Dispatcher and cancels it on destruction — the RAII
// counterpart to RegisterTimer/UnregisterTimer (which traffic in a bare TimerId). Move-only.
class Timer {
public:
    Timer() noexcept = default;
    Timer(Dispatcher& dispatcher, std::chrono::milliseconds interval,
        const Dispatcher::OnTimerCallback& callback)
            : dispatcher_{&dispatcher}, id_{dispatcher.RegisterTimer(interval, callback)} {}

    Timer(Timer&& other) noexcept
            : dispatcher_{std::exchange(other.dispatcher_, nullptr)}, id_{other.id_} {}
    Timer& operator=(Timer&& other) noexcept {
        if (this != &other) {
            Reset();
            dispatcher_ = std::exchange(other.dispatcher_, nullptr);
            id_ = other.id_;
        }
        return *this;
    }
    ~Timer() noexcept { Reset(); }

    // Valid once it holds a live registration (RegisterTimer accepted the interval/callback).
    [[nodiscard]] bool IsValid() const noexcept { return dispatcher_ != nullptr && id_ != Dispatcher::TimerId{}; }

private:
    void Reset() noexcept {
        if (dispatcher_ != nullptr) {
            std::exchange(dispatcher_, nullptr)->UnregisterTimer(id_);
        }
    }

    Dispatcher* dispatcher_ = nullptr;
    Dispatcher::TimerId id_{};
};

} // namespace reflector
```

- [ ] **Step 4: Update the fakes so the test binary still links (do this BEFORE building)**

In `tests/mocks/fake_dispatcher.h`: add `#include <chrono>`, `#include <cstdint>`, and `#include <vector>` to the include block, then add the timer API + an on-demand fire helper. Inside `class FakeDispatcher`, in the `public:` section after `FireReadable`:

```cpp
    [[nodiscard]] TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) override {
        if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
            return TimerId{};
        }
        const auto id = static_cast<TimerId>(next_timer_id_++);
        timers_.push_back(TimerEntry{.id = id, .callback = callback});
        return id;
    }

    void UnregisterTimer(TimerId id) noexcept override {
        std::erase_if(timers_, [id](const TimerEntry& entry) { return entry.id == id; });
    }

    // Fires every registered timer once, copying each callback before invoking (a callback may
    // unregister a timer mid-fire), mirroring FireReadable and the production copy-before-invoke.
    void FireTimers() {
        const auto snapshot = timers_;
        for (const auto& entry : snapshot) {
            entry.callback();
        }
    }

    [[nodiscard]] size_t TimerCount() const noexcept { return timers_.size(); }
```

and in the `private:` section, add the storage:

```cpp
    struct TimerEntry {
        TimerId id;
        OnTimerCallback callback;
    };
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
```

In `tests/mocks/fake_packet_dispatcher.h`: add `#include "mocks/fake_dispatcher.h"` to the includes, give it an owned `FakeDispatcher`, and implement the getter. In the `public:` section after the `Deliver` overloads:

```cpp
    [[nodiscard]] Dispatcher& UnderlyingDispatcher() noexcept override { return dispatcher; }

    // Direct access so a test can drive the timers a subscriber registered (e.g. eviction sweeps).
    FakeDispatcher dispatcher;
```

(Place the `FakeDispatcher dispatcher;` as a public member — tests reach it as `packet_dispatcher.dispatcher.FireTimers()`. It is default-constructed; all existing sites construct `FakePacketDispatcher packet_dispatcher;`, so there is no name clash.)

**Also fix an iterator-invalidation hazard in the same file (required before Task 5).** Task 5's `OnSourcePacket` calls `packet_dispatcher_.Register(...)` from *inside* a `Deliver` callback — that `Register` does `entries_.push_back(...)`, which can reallocate the vector `Deliver` is currently iterating. The existing `Deliver` overloads use a range-`for` over `entries_`, which is then undefined behavior (an ASan crash in every proxy test). Change **both** `Deliver` overloads to iterate by an index snapshot and copy the entry before invoking, mirroring what production `DefaultPacketDispatcher::DispatchPacket` does for the same reason:

```cpp
    // Dispatches `packet` to every registration whose filter matches, regardless of socket.
    void Deliver(const Packet& packet) {
        for (size_t i = 0, n = entries_.size(); i < n; ++i) {
            const Entry entry = entries_[i];  // copy: a callback may Register and reallocate entries_
            if (entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
    }

    // Dispatches `packet` as if captured on `socket`: only registrations made on that socket whose
    // filter matches. Models the per-socket capture path a bidirectional reflector depends on.
    void Deliver(const LinkSocket& socket, const Packet& packet) {
        for (size_t i = 0, n = entries_.size(); i < n; ++i) {
            const Entry entry = entries_[i];  // copy: a callback may Register and reallocate entries_
            if (entry.socket == &socket && entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
    }
```

(`n` is sampled once so a registration added mid-dispatch is not itself dispatched for the current packet — matching production, where the new capture is on a different socket/port and would not match anyway.)

- [ ] **Step 5: Write the failing tests**

Create `tests/timer_test.cpp`:

```cpp
#include "reflector/timer.h"

#include "reflector/util/delegate.h"
#include "mocks/fake_dispatcher.h"

#include <gtest/gtest.h>

#include <chrono>

namespace reflector {
namespace {

struct Counter {
    int count = 0;
    void Tick() { ++count; }
};

using namespace std::chrono_literals;

TEST(TimerTest, RegistersOneTimerAndIsValid) {
    FakeDispatcher dispatcher;
    Counter counter;
    const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
    EXPECT_TRUE(timer.IsValid());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);
}

TEST(TimerTest, UnregistersOnDestruction) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
        ASSERT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, MoveDoesNotDoubleUnregister) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        Timer first{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
        Timer second = std::move(first);
        EXPECT_TRUE(second.IsValid());
        EXPECT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // exactly one unregister, from `second`
}

TEST(TimerTest, FiringInvokesTheCallback) {
    FakeDispatcher dispatcher;
    Counter counter;
    const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
    dispatcher.FireTimers();
    EXPECT_EQ(counter.count, 1);
}

} // namespace
} // namespace reflector
```

Append to `tests/event_loop_dispatcher_test.cpp` (before the final `} // namespace reflector`), reusing the existing `ReadableCounter`/`ReadablePipe` fixtures already in that file. Add `#include "reflector/timer.h"` near the top includes if not transitively available. A new `TimerCounter` and tests against the real reactor through public methods only:

```cpp
struct TimerCounter {
    int count = 0;
    void Tick() { ++count; }
};

TEST_F(EventLoopDispatcherTest, NextTimeoutReturnsCapWhenNoTimers) {
    const auto now = std::chrono::steady_clock::now();
    EXPECT_EQ(dispatcher.NextTimeout(now), std::chrono::milliseconds{1000});
}

TEST_F(EventLoopDispatcherTest, FireDueTimersInvokesAndReschedulesDueTimer) {
    TimerCounter counter;
    const auto id = dispatcher.RegisterTimer(
        std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter));
    ASSERT_NE(id, EventLoopDispatcher::TimerId{});
    const auto t0 = std::chrono::steady_clock::now();

    // Not yet due at t0: no fire.
    dispatcher.FireDueTimers(t0);
    EXPECT_EQ(counter.count, 0);

    // Due at t0 + interval: fires once, then reschedules — a second call at the same instant does not refire.
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(counter.count, 1);
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(counter.count, 1);

    // Due again a full interval later.
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{100});
    EXPECT_EQ(counter.count, 2);

    dispatcher.UnregisterTimer(id);
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{1000});
    EXPECT_EQ(counter.count, 2);  // unregistered: no further fires
}

TEST_F(EventLoopDispatcherTest, NextTimeoutClampsToSoonestDeadlineAndFloorsAtZero) {
    TimerCounter counter;
    dispatcher.RegisterTimer(
        std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter));
    const auto t0 = std::chrono::steady_clock::now();

    // Halfway to the deadline: ~25ms remain, clamped under the 1000ms cap.
    const auto remaining = dispatcher.NextTimeout(t0 + std::chrono::milliseconds{25});
    EXPECT_GT(remaining, std::chrono::milliseconds{0});
    EXPECT_LE(remaining, std::chrono::milliseconds{50});

    // Past due: floored at 0 (never a negative timeout to the kernel).
    EXPECT_EQ(dispatcher.NextTimeout(t0 + std::chrono::milliseconds{100}), std::chrono::milliseconds{0});
}

TEST_F(EventLoopDispatcherTest, RegisterTimerRejectsNonPositiveInterval) {
    TimerCounter counter;
    EXPECT_EQ(dispatcher.RegisterTimer(std::chrono::milliseconds{0},
        CreateDelegate<&TimerCounter::Tick>(&counter)), EventLoopDispatcher::TimerId{});
}
```

- [ ] **Step 6: Run the build to verify the tests fail (methods not yet on EventLoopDispatcher)**

Run: `cmake --build build`
Expected: FAIL — `EventLoopDispatcher` has no `RegisterTimer`/`UnregisterTimer`/`FireDueTimers`/`NextTimeout`, and it is abstract (the two new `Dispatcher` pure virtuals are unimplemented), so it won't compile.

- [ ] **Step 7: Implement timers in `EventLoopDispatcher`**

In `src/reflector/event_loop_dispatcher.h`: add `#include <chrono>` (already present) and `#include <cstdint>`, `#include <vector>`. Add to the `public:` section:

```cpp
    [[nodiscard]] TimerId RegisterTimer(
        std::chrono::milliseconds interval, const OnTimerCallback& callback) override;
    void UnregisterTimer(TimerId id) noexcept override;

    // Fires (and reschedules to now + interval) every timer whose deadline is <= now. Public so the
    // timer path is driven directly in tests with an injected `now` — no clock-seam member, no friend.
    void FireDueTimers(std::chrono::steady_clock::time_point now);
    // The wait to pass to PollOnce so the loop wakes by the soonest timer deadline, capped at
    // MAX_POLL_INTERVAL. Pure; public for the same test reason.
    [[nodiscard]] std::chrono::milliseconds NextTimeout(std::chrono::steady_clock::time_point now) const;
```

Add to the `private:` section:

```cpp
    static constexpr std::chrono::milliseconds MAX_POLL_INTERVAL{1000};

    struct TimerEntry {
        TimerId id;
        std::chrono::milliseconds interval;
        std::chrono::steady_clock::time_point next;
        OnTimerCallback callback;
    };
    std::vector<TimerEntry> timers_;
    uint64_t next_timer_id_ = 1;
```

In `src/reflector/event_loop_dispatcher.cpp`: add `#include <algorithm>` and `#include <vector>`. Change `Run` to drive the timers, and add the four methods. Replace the body of `Run`:

```cpp
void EventLoopDispatcher::Run(const volatile std::sig_atomic_t& stop_requested) {
    GetLogger().Info("Starting dispatcher event loop");
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot run dispatcher: event queue is invalid");
        return;
    }
    while (stop_requested == 0) {
        const auto now = std::chrono::steady_clock::now();
        PollOnce(NextTimeout(now));
        FireDueTimers(std::chrono::steady_clock::now());
    }
    GetLogger().Info("Stopped dispatcher event loop");
}
```

Add the new methods (place them after `PollOnce`, before `AddReadEvent`):

```cpp
EventLoopDispatcher::TimerId EventLoopDispatcher::RegisterTimer(
    std::chrono::milliseconds interval, const OnTimerCallback& callback) {
    if (interval <= std::chrono::milliseconds{0} || !callback.IsValid()) {
        GetLogger().Error("Cannot register timer: non-positive interval or invalid callback");
        return TimerId{};
    }
    const auto id = static_cast<TimerId>(next_timer_id_++);
    timers_.push_back(TimerEntry{
        .id = id,
        .interval = interval,
        .next = std::chrono::steady_clock::now() + interval,
        .callback = callback,
    });
    return id;
}

void EventLoopDispatcher::UnregisterTimer(TimerId id) noexcept {
    std::erase_if(timers_, [id](const TimerEntry& entry) { return entry.id == id; });
}

void EventLoopDispatcher::FireDueTimers(std::chrono::steady_clock::time_point now) {
    // Snapshot the due {id, callback} and reschedule the live entries BEFORE invoking, so a callback
    // that calls RegisterTimer/UnregisterTimer (reallocating/erasing timers_) cannot invalidate what
    // we iterate. Generalizes PollOnce's single copy-before-invoke to N callbacks.
    std::vector<OnTimerCallback> due;
    for (auto& entry : timers_) {
        if (entry.next <= now) {
            due.push_back(entry.callback);
            entry.next = now + entry.interval;  // forward from now; never += interval (no backlog spin)
        }
    }
    for (const auto& callback : due) {
        callback();
    }
}

std::chrono::milliseconds EventLoopDispatcher::NextTimeout(std::chrono::steady_clock::time_point now) const {
    auto timeout = MAX_POLL_INTERVAL;
    for (const auto& entry : timers_) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(entry.next - now);
        timeout = std::min(timeout, remaining);
    }
    return std::max(timeout, std::chrono::milliseconds{0});
}
```

Also add the leftover-timers warning to the destructor, symmetric to the existing `callbacks_` one. In `~EventLoopDispatcher`, after the existing `callbacks_` check:

```cpp
    if (!timers_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} timer registration(s) still active", timers_.size());
    }
```

- [ ] **Step 8: Implement `UnderlyingDispatcher()` in `DefaultPacketDispatcher`**

In `src/reflector/default_packet_dispatcher.h`, add to the `public:` section:

```cpp
    [[nodiscard]] Dispatcher& UnderlyingDispatcher() noexcept override { return *dispatcher_; }
```

(`dispatcher_` is a `Dispatcher*` member, so dereference. This is inline; no `.cpp` change needed. Ensure `dispatcher.h` is included — it is, transitively via the existing members.)

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -L unit -R 'TimerTest|EventLoopDispatcherTest' --output-on-failure`
Expected: PASS — the 4 `TimerTest` cases and the existing + 4 new `EventLoopDispatcherTest` cases.

- [ ] **Step 10: Full unit-suite check**

Run: `ctest --test-dir build -L unit --output-on-failure`
Expected: PASS. (This confirms the fake updates didn't break any reflector/application test that constructs the fakes.)

- [ ] **Step 11: Add `timer_test.cpp` to CMake** (only if not added in Step earlier)

In `tests/CMakeLists.txt`, after `event_loop_dispatcher_test.cpp`:

```cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/timer_test.cpp
```

Re-run Step 9 to confirm `timer_test.cpp` is now compiled and green.

- [ ] **Step 12: Commit (with operator permission)**

```bash
git add src/reflector/dispatcher.h src/reflector/event_loop_dispatcher.h src/reflector/event_loop_dispatcher.cpp \
        src/reflector/packet_dispatcher.h src/reflector/default_packet_dispatcher.h \
        src/reflector/timer.h tests/mocks/fake_dispatcher.h tests/mocks/fake_packet_dispatcher.h \
        tests/timer_test.cpp tests/event_loop_dispatcher_test.cpp tests/CMakeLists.txt
git commit -m "feat(dispatcher): add portable reactor timers + Timer RAII + UnderlyingDispatcher"
```

---

## Task 3: `LinkSocket::SendUnicastUdpDatagram` + `SourceAddress`

**Files:**
- Modify: `src/reflector/link_socket.h`, `src/reflector/raw_socket.h`, `src/reflector/raw_socket.cpp`, `tests/mocks/fake_link_socket.h`
- Test: `tests/raw_socket_test.cpp` (extend; `SourceAddress` via the existing `SetSource` friend seam)

- [ ] **Step 1: Add the two methods to the `LinkSocket` interface**

In `src/reflector/link_socket.h`, add `#include "mac_address.h"` (needed for the `MacAddress` parameter) and add to the send-side section after `SendUdpDatagram`:

```cpp
    // Injects a unicast UDP datagram to an explicit L2 destination (the searcher's MAC), to deliver
    // a proxied SSDP 200 OK back across segments. Like SendUdpDatagram it originates from this
    // interface's own source address and MAC; it differs only in taking an explicit unicast dst_mac
    // instead of deriving a multicast MAC from dst_ip. Returns false (after logging) on failure.
    // Gate with CanSend(dst_ip.AddressFamily()).
    [[nodiscard]] virtual bool SendUnicastUdpDatagram(MacAddress dst_mac, IpAddress dst_ip,
        uint16_t dst_port, uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept = 0;
```

and add to the bookkeeping/query section:

```cpp
    // The interface's source address for `family` — the address SendUdpDatagram originates from, and
    // the destination a unicast reply to a relayed datagram of that family is sent to. nullopt if the
    // interface has none (then CanSend(family) is also false). IPv6 returns the link-local address.
    [[nodiscard]] virtual std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept = 0;
```

- [ ] **Step 2: Update the `FakeLinkSocket` mock (before building)**

In `tests/mocks/fake_link_socket.h`, extend the `Sent` record so unicast sends are inspectable, add the `SendUnicastUdpDatagram` override, the `SourceAddress` override, and the configurable fields. Add a distinct record vector so unicast and multicast sends don't intermix in assertions:

```cpp
    struct UnicastSent {
        std::vector<std::byte> payload;
        MacAddress dst_mac;
        IpAddress dst_ip;
        uint16_t dst_port;
        uint16_t src_port;
        uint8_t ttl;
    };
```

Add the overrides (in the same `public`/struct body):

```cpp
    [[nodiscard]] bool SendUnicastUdpDatagram(MacAddress dst_mac, IpAddress dst_ip, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        if (fail_send) {
            return false;
        }
        unicast_sent.push_back(UnicastSent{
            .payload = std::vector<std::byte>{payload.begin(), payload.end()},
            .dst_mac = dst_mac,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .src_port = src_port,
            .ttl = ttl,
        });
        return true;
    }

    [[nodiscard]] std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept override {
        return family == IpAddress::Family::V4 ? source_v4 : source_v6;
    }
```

and the fields (near the other config fields):

```cpp
    std::optional<IpAddress> source_v4 = IpAddress::LoopbackV4();
    std::optional<IpAddress> source_v6 = IpAddress::LoopbackV6();
    std::vector<UnicastSent> unicast_sent;
```

- [ ] **Step 3: Add the declarations + a failing test for `SourceAddress`**

In `src/reflector/raw_socket.h`, add the two `override` declarations mirroring `SendUdpDatagram`'s doc-comment style (place `SendUnicastUdpDatagram` after `SendUdpDatagram`, and `SourceAddress` after `CanSend`):

```cpp
    [[nodiscard]] bool SendUnicastUdpDatagram(MacAddress dst_mac, IpAddress dst_ip, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept override;
```

```cpp
    [[nodiscard]] std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept override;
```

Append a test to `tests/raw_socket_test.cpp` in the `RawSocketTest` fixture region (it already has the `SetSource` friend seam):

```cpp
TEST_F(RawSocketTest, SourceAddressReturnsTheResolvedPerFamilyAddress) {
    const auto v4 = IpAddress::FromV4Bytes(192, 0, 2, 7);
    const auto v6 = IpAddress::LoopbackV6();
    SetSource(v4, v6);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V4), v4);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V6), v6);

    SetSource(v4, std::nullopt);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V6), std::nullopt);
}
```

- [ ] **Step 4: Run the build to verify it fails**

Run: `cmake --build build`
Expected: FAIL — `RawSocket` is abstract (new pure virtuals unimplemented) / `undefined reference` to the two new methods.

- [ ] **Step 5: Implement both methods in `raw_socket.cpp`**

Add to `src/reflector/raw_socket.cpp`. `SourceAddress` mirrors `CanSend`'s `addresses_` access but returns the optional itself; place it next to `CanSend`:

```cpp
std::optional<IpAddress> RawSocket::SourceAddress(IpAddress::Family family) const noexcept {
    return family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6;
}
```

`SendUnicastUdpDatagram` is `SendUdpDatagram` with the caller's `dst_mac` instead of `MulticastMacFor(dst_ip)`. Place it after `SendUdpDatagram`:

```cpp
bool RawSocket::SendUnicastUdpDatagram(MacAddress dst_mac, IpAddress dst_ip, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept {
    const auto family = dst_ip.AddressFamily();
    const auto& source = family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6;
    if (!source.has_value()) {
        logger_.Error("Cannot send unicast to {}: interface has no source address for that family",
            dst_ip.ToString());
        return false;
    }

    std::array<std::byte, SEND_BUFFER_SIZE> frame{};
#if defined(__linux__)
    const size_t length = BuildUdpFrame(dst_mac, addresses_.mac, *source, dst_ip,
        src_port, dst_port, payload, ttl, frame);
#elif defined(__APPLE__)
    const size_t length = link_type_ == LinkType::Loopback
        ? BuildLoopbackUdpFrame(*source, dst_ip, src_port, dst_port, payload, ttl, frame)
        : BuildUdpFrame(dst_mac, addresses_.mac, *source, dst_ip, src_port, dst_port, payload, ttl, frame);
#endif
    if (length == 0) {
        logger_.Error("Cannot build unicast egress frame for {} ({}-byte payload)", dst_ip.ToString(),
            payload.size());
        return false;
    }

#if defined(__linux__)
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = static_cast<int>(interface_index_);
    const auto sent = sendto(fd_, frame.data(), length, 0,
        reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
#elif defined(__APPLE__)
    const auto sent = write(fd_, frame.data(), length);
#endif
    if (sent < 0 || static_cast<size_t>(sent) != length) {
        logger_.Error("Cannot inject unicast datagram to {}: {}", dst_ip.ToString(), Error::FromErrno());
        return false;
    }
    return true;
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -L unit -R 'RawSocketTest' --output-on-failure`
Expected: PASS — including the new `SourceAddressReturnsTheResolvedPerFamilyAddress`. (Actually injecting a unicast frame needs a real interface; that path is exercised end-to-end by the e2e round-trip in Task 6, consistent with how `SendUdpDatagram`'s injection is only covered by the `RequiresRoot`/e2e tests.)

- [ ] **Step 7: Full unit-suite check**

Run: `ctest --test-dir build -L unit --output-on-failure`
Expected: PASS.

- [ ] **Step 8: Commit (with operator permission)**

```bash
git add src/reflector/link_socket.h src/reflector/raw_socket.h src/reflector/raw_socket.cpp \
        tests/mocks/fake_link_socket.h tests/raw_socket_test.cpp
git commit -m "feat(socket): add SendUnicastUdpDatagram + SourceAddress to LinkSocket"
```

---

## Task 4: `ParseMSearchMx` — MX header parsing

**Files:**
- Modify: `src/reflector/ssdp_message.h`, `src/reflector/ssdp_message.cpp`
- Test: `tests/ssdp_message_test.cpp`

The session lifetime derives from the M-SEARCH's `MX` header (max response wait, seconds), clamped to `[1, 5]` per UDA 2.0, defaulting to 3 when absent/unparseable.

- [ ] **Step 1: Add the declaration**

In `src/reflector/ssdp_message.h`, after `ClassifySsdpMessage`:

```cpp
// Parses the MX header of an M-SEARCH (the searcher's max response wait, in seconds), clamped to
// [1, 5] per UPnP Device Architecture 2.0. Returns 3 when MX is absent or unparseable (an M-SEARCH
// should always carry it). Scans only the header block; case-insensitive on the field name.
[[nodiscard]] uint8_t ParseMSearchMx(std::span<const std::byte> payload) noexcept;
```

Add `#include <cstdint>` to the header's include block if not already present.

- [ ] **Step 2: Write the failing test**

Append to `tests/ssdp_message_test.cpp` (it already has the `Bytes()` helper):

```cpp
TEST(SsdpMessageTest, ParsesMxHeaderValue) {
    const auto payload = Bytes(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMX: 4\r\nST: ssdp:all\r\n\r\n");
    EXPECT_EQ(ParseMSearchMx(payload), 4);
}

TEST(SsdpMessageTest, ClampsMxToOneToFive) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: 0\r\n\r\n")), 1);
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: 9\r\n\r\n")), 5);
}

TEST(SsdpMessageTest, DefaultsMxWhenAbsentOrUnparseable) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")), 3);
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nMX: abc\r\n\r\n")), 3);
}

TEST(SsdpMessageTest, ParsesMxHeaderNameCaseInsensitively) {
    EXPECT_EQ(ParseMSearchMx(Bytes("M-SEARCH * HTTP/1.1\r\nmx: 2\r\n\r\n")), 2);
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cmake --build build`
Expected: FAIL — `undefined reference to reflector::ParseMSearchMx`.

- [ ] **Step 4: Write the implementation**

Add to `src/reflector/ssdp_message.cpp`. Add `#include <algorithm>` (for `std::clamp`), `#include <cctype>`, and `#include <charconv>`. (`<string_view>` is already included; `<cstdint>` comes via the header.) Implement a small line-scanner over the payload:

```cpp
namespace {

constexpr uint8_t MX_DEFAULT = 3;
constexpr uint8_t MX_MIN = 1;
constexpr uint8_t MX_MAX = 5;

// Case-insensitive prefix match of an ASCII header name.
bool HeaderNameMatches(std::string_view line, std::string_view name) noexcept {
    if (line.size() < name.size()) {
        return false;
    }
    for (size_t i = 0; i < name.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(line[i])) != std::tolower(static_cast<unsigned char>(name[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace

uint8_t ParseMSearchMx(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    size_t pos = 0;
    while (pos < text.size()) {
        const auto end = text.find("\r\n", pos);
        const auto line = text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
        if (HeaderNameMatches(line, "MX:")) {
            auto value = line.substr(3);
            const auto first = value.find_first_not_of(" \t");
            if (first != std::string_view::npos) {
                value = value.substr(first);
                unsigned parsed = 0;
                const auto* begin = value.data();
                const auto* stop = value.data() + value.size();
                if (std::from_chars(begin, stop, parsed).ec == std::errc{}) {
                    return static_cast<uint8_t>(std::clamp<unsigned>(parsed, MX_MIN, MX_MAX));
                }
            }
            return MX_DEFAULT;  // MX present but unparseable
        }
        if (end == std::string_view::npos) {
            break;
        }
        pos = end + 2;
    }
    return MX_DEFAULT;
}
```

(`<algorithm>` for `std::clamp` was already added to the include list in this step.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cmake --build build && ctest --test-dir build -L unit -R 'SsdpMessageTest' --output-on-failure`
Expected: PASS (existing classification tests + 4 new MX tests).

- [ ] **Step 6: Commit (with operator permission)**

```bash
git add src/reflector/ssdp_message.h src/reflector/ssdp_message.cpp tests/ssdp_message_test.cpp
git commit -m "feat(ssdp): parse M-SEARCH MX header (clamped [1,5], default 3)"
```

---

## Task 5: `SsdpReflector` — session table, reserved-port relay, response proxy, eviction

This wires Tasks 1–4 into the reflector. **This is a data-path commit — the full gate (native + docker debug/release + e2e) runs before the commit.**

**Files:**
- Modify: `src/reflector/ssdp_reflector.h`, `src/reflector/ssdp_reflector.cpp`
- Test: `tests/ssdp_reflector_test.cpp`

### Design recap (what changes vs. current step-1 behavior)

- `OnSourcePacket` (M-SEARCH): instead of relaying from port 1900, it allocates a `PortReservation` for the captured family, registers a response capture on `target_socket_` filtered `{dest_ip = *target_socket_.SourceAddress(family), dest_port = P, source_mac = config.mac}`, relays the M-SEARCH from `P`, and stores a `Session` keyed by `(family, P)`.
- New `OnUnicastResponse` (the `200 OK`): looks up the session by `(family, dest_port)` and raw-injects to the searcher via `source_socket_.SendUnicastUdpDatagram(searcher_mac, searcher_ip, searcher_port, response_src_port, payload, SSDP_TTL)`.
- A `Timer` (created on the success path) fires every `EVICTION_INTERVAL` → `SweepExpired()` → `EvictExpired(now)`, dropping sessions past `expiry = created + clamp(MX,1,5)s + SESSION_GRACE`.
- `NOTIFY` path (`OnTargetPacket`) and classification are unchanged.

- [ ] **Step 1: Add members + method declarations to `ssdp_reflector.h`**

Add includes: `"port_reservation.h"`, `"timer.h"`, `<chrono>`, `<cstdint>`, `<optional>`, `<unordered_map>`. Add the constants and members. New constants next to the existing `SSDP_PORT`/`SSDP_TTL`:

```cpp
    static constexpr size_t MAX_SESSIONS = 32;
    static constexpr std::chrono::seconds SESSION_GRACE{2};
    static constexpr std::chrono::seconds EVICTION_INTERVAL{1};
```

Add the session type and table (private):

```cpp
    struct SessionKey {
        IpAddress::Family family;
        uint16_t port;
        [[nodiscard]] bool operator==(const SessionKey&) const noexcept = default;
    };
    struct SessionKeyHash {
        [[nodiscard]] size_t operator()(const SessionKey& key) const noexcept {
            return (static_cast<size_t>(key.port) << 1) ^ static_cast<size_t>(key.family);
        }
    };

    // One in-flight M-SEARCH awaiting unicast 200 OK replies. Move-only (its members are): inserted
    // with try_emplace, never copied.
    struct Session {
        IpAddress searcher_ip;
        uint16_t searcher_port;
        MacAddress searcher_mac;
        std::chrono::steady_clock::time_point expiry;
        PortReservation reservation;
        PacketDispatcher::Registration capture;
    };
```

Add the method declarations:

```cpp
    void OnUnicastResponse(const Packet& packet) noexcept;  // target: a captured 200 OK -> searcher
    // Drops sessions past their expiry. Public (takes `now` as a parameter) so it is directly
    // testable with an injected time point — no test-only friend.
    void EvictExpired(std::chrono::steady_clock::time_point now) noexcept;
    void SweepExpired() noexcept;  // timer callback: EvictExpired(steady_clock::now())
```

(`EvictExpired` goes in the **public** section — its `now` parameter is the test seam; `SweepExpired`, `OnUnicastResponse`, and the session types stay private.)

**Member declaration order is load-bearing — pin it exactly to avoid `-Wreorder` (the build is `-Werror`) and to get the right destruction order.** The base `Reflector` already holds `logger_` and `registrations_`; `SsdpReflector` currently declares `source_socket_` then `target_socket_`. Add the new members **after** those, in this order, with `eviction_timer_` **last** so it unregisters from the dispatcher first during destruction:

```cpp
    LinkSocket& source_socket_;   // (existing)
    LinkSocket& target_socket_;   // (existing)
    PacketDispatcher& packet_dispatcher_;  // retained so OnSourcePacket can register response captures
    std::optional<MacAddress> config_mac_;  // the device-scoping filter, reused by the response capture
    std::unordered_map<SessionKey, Session, SessionKeyHash> sessions_;
    std::optional<Timer> eviction_timer_;  // declared last → destroyed first
```

Write the constructor init list in the **same order** as the declarations (the compiler initializes in declaration order regardless; matching the init list silences `-Wreorder`):

```cpp
        : Reflector{LoggerName(config)}
        , source_socket_{source_socket}
        , target_socket_{target_socket}
        , packet_dispatcher_{packet_dispatcher}
        , config_mac_{config.mac}
```

`packet_dispatcher_` and `config_mac_` are new — the real ctor today initializes only `source_socket_`/`target_socket_`. `packet_dispatcher_` is a reference, so it *must* be set in the init list (not assigned). `config_mac_` is captured as a member so `OnSourcePacket` can reuse the device-scoping MAC on the response capture without holding the whole config. (`sessions_` and `eviction_timer_` default-construct; `eviction_timer_` is emplaced later in `Initialize` — Step 4.2.)

- [ ] **Step 2: Write the failing tests**

Append to `tests/ssdp_reflector_test.cpp`. These use the existing `SsdpReflectorTest`/`SsdpReflectorTestBase` fixtures, plus the `target.unicast_sent` and `packet_dispatcher.dispatcher` (the owned `FakeDispatcher`) added in Tasks 2–3. Add a helper to build a `200 OK` captured on `target` destined to our source address on port `P`:

```cpp
TEST_F(SsdpReflectorTest, MSearchRelayOriginatesFromAReservedPortAndCreatesSession) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t before = RegistrationCount();

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(target.sent.size(), 1u);
    const auto& sent = target.sent.back();
    EXPECT_EQ(sent.dst_ip, IpAddress::SsdpGroupV4());
    EXPECT_EQ(sent.dst_port, 1900u);
    EXPECT_NE(sent.src_port, 1900u);   // relayed from the reserved ephemeral port, not 1900
    EXPECT_NE(sent.src_port, 0u);
    EXPECT_EQ(sent.ttl, 2);
    // A response-capture registration was added for the session.
    EXPECT_EQ(RegistrationCount(), before + 1);
}

TEST_F(SsdpReflectorTest, ProxiesUnicastResponseBackToSearcher) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // 1) An M-SEARCH establishes the session and reveals the reserved port P.
    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    // 2) A device unicasts a 200 OK to our interface address on P (captured on target).
    const auto response = Bytes("HTTP/1.1 200 OK\r\nST: ssdp:all\r\nLOCATION: http://x/d.xml\r\n\r\n");
    const auto device_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:01");
    Packet reply{
        .header = PacketHeader{
            .source_ip = IpAddress::FromV4Bytes(10, 0, 0, 5),     // the device
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),  // our target_if address
            .source_port = 1900,
            .dest_port = reserved_port,
            .ttl = 4,
            .source_mac = device_mac,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    // 3) It is injected to the original searcher on source, from our own address (no spoofing).
    ASSERT_EQ(source.unicast_sent.size(), 1u);
    const auto& out = source.unicast_sent.back();
    EXPECT_EQ(out.dst_ip, LoopbackFor(IpAddress::Family::V4));  // the M-SEARCH's source_ip (searcher)
    EXPECT_EQ(out.dst_port, 1900u);                              // the M-SEARCH's source_port
    EXPECT_EQ(out.payload, response);
    EXPECT_EQ(out.ttl, 2);
}

TEST_F(SsdpReflectorTest, IgnoresUnicastResponseWithNoMatchingSession) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A stray 200 OK to a port we never reserved: nothing is forwarded. Deliver(packet) bypasses the
    // per-session filter to confirm the handler itself drops an unknown port.
    const auto response = Bytes("HTTP/1.1 200 OK\r\n\r\n");
    Packet reply{
        .header = PacketHeader{
            .source_ip = IpAddress::FromV4Bytes(10, 0, 0, 5),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = 1900,
            .dest_port = 55555,
            .ttl = 4,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(reply);
    EXPECT_TRUE(source.unicast_sent.empty());
}

TEST_F(SsdpReflectorTest, EvictionTimerReleasesExpiredSessions) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();  // multicast registrations only

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(RegistrationCount(), base + 1);  // + the session's response capture

    // The real time-based expiry (MX=2 + 2s grace) hasn't elapsed, so firing the timer now keeps it.
    packet_dispatcher.dispatcher.FireTimers();
    EXPECT_EQ(RegistrationCount(), base + 1);
}

TEST_F(SsdpReflectorTest, ValidReflectorRegistersAnEvictionTimer) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(packet_dispatcher.dispatcher.TimerCount(), 1u);
}

TEST_F(SsdpReflectorTest, CapDropsSessionsBeyondTheLimit) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // 32 distinct searchers fill the table; the 33rd is dropped (no relay). Distinct source ports
    // make distinct sessions.
    for (uint16_t i = 0; i < 33; ++i) {
        Packet search = MakePacket(MakeSearch(), IpAddress::SsdpGroupV4());
        search.header.source_port = static_cast<uint16_t>(20000 + i);
        packet_dispatcher.Deliver(source, search);
    }
    EXPECT_EQ(target.sent.size(), 32u);  // 33rd search not relayed
}
```

**Note on `EvictionTimerReleasesExpiredSessions`:** because `EvictExpired` reads `steady_clock::now()` via `SweepExpired`, the test above only verifies a *not-yet-expired* session survives a sweep. The actual drop-on-expiry is unit-tested directly through the `EvictExpired(now)` seam — add a fixture accessor for it (the reflector test fixture can call a public-for-test method, or expose `EvictExpired` and add a friend). To avoid a test-only friend (consistent with the spec), make `SweepExpired` call `EvictExpired(steady_clock::now())` and add **one** direct test by constructing a session and calling a small public helper. Simplest approach that needs no friend: add a test that drives expiry by making `EVICTION` observable via registration count after manipulating the system clock is not portable — so instead assert the survive-path here (done above) and rely on the e2e round-trip + the `EvictExpired(now)` logic being exercised by a dedicated test that calls it through `SweepExpired` is insufficient. **Resolution:** expose `EvictExpired(now)` as a public method on `SsdpReflector` (it takes `now`, so it is harmless to call and needs no friend), and add:

```cpp
TEST_F(SsdpReflectorTest, EvictExpiredDropsSessionsPastExpiry) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(RegistrationCount(), base + 1);

    // MX=2 + 2s grace = 4s lifetime; a sweep 10s in the future drops it.
    reflector.EvictExpired(std::chrono::steady_clock::now() + std::chrono::seconds{10});
    EXPECT_EQ(RegistrationCount(), base);  // session's capture released

    // A fresh sweep does not under-run.
    reflector.EvictExpired(std::chrono::steady_clock::now() + std::chrono::seconds{20});
    EXPECT_EQ(RegistrationCount(), base);
}
```

So in `ssdp_reflector.h`, declare `EvictExpired` in the **public** section (with a comment that `now` is a parameter so it is directly testable), and keep `SweepExpired` private.

- [ ] **Step 3: Run the build to verify the tests fail**

Run: `cmake --build build`
Expected: FAIL — `OnUnicastResponse`/`EvictExpired`/session members don't exist; `target.unicast_sent` etc. compile (from Task 3) but the reflector behavior is unimplemented, so the new assertions fail at runtime (after you stub enough to compile, they fail).

- [ ] **Step 4: Implement the reflector changes**

In `src/reflector/ssdp_reflector.cpp`:

1. Store `packet_dispatcher_` and `config_mac_` in the ctor init list (Step 1 above gives the full ordered list).

2. Place the eviction-timer creation at the **end of the success path** of `Initialize`. In the real `ssdp_reflector.cpp`, `Initialize` has a `SetUpGroup`-failure path that does `registrations_.clear(); return;` and a success path ending with the `logger_.Info("Created ssdp reflector ...")` call. Add this **after** the family/group setup loop and immediately before (or after) that final `Info` log — i.e. on the success path only, gated on the same `!registrations_.empty()` condition `IsValid()` uses, so an invalid reflector never holds a live timer:

```cpp
    if (!registrations_.empty()) {
        eviction_timer_.emplace(packet_dispatcher.UnderlyingDispatcher(), EVICTION_INTERVAL,
            CreateDelegate<&SsdpReflector::SweepExpired>(this));
    }
```

(`Initialize` already returns early / clears `registrations_` on every failure path, so reaching here with a non-empty `registrations_` is exactly the valid case. `Initialize` takes `packet_dispatcher` by reference, so `UnderlyingDispatcher()` is reachable from it.)

3. Replace `OnSourcePacket` with the session-creating version:

```cpp
void SsdpReflector::OnSourcePacket(const Packet& packet) noexcept {
    if (!ShouldRelay(packet, SsdpMessageKind::Search)) {  // only searches flow source -> target
        return;
    }

    if (sessions_.size() >= MAX_SESSIONS) {
        logger_.Warning("Dropping M-SEARCH from {}: {} sessions in flight (cap reached)",
            packet.header.source_ip, sessions_.size());
        return;
    }

    const auto family = packet.header.dest_ip.AddressFamily();
    const auto our_address = target_socket_.SourceAddress(family);
    if (!our_address.has_value()) {
        logger_.Error("Cannot proxy M-SEARCH: target interface has no source address for the family");
        return;
    }

    auto reservation = PortReservation::Create(family);
    if (!reservation.has_value()) {
        return;  // Create logged the cause
    }
    const uint16_t port = reservation->Port();

    auto capture = packet_dispatcher_.Register(target_socket_,
        PacketFilter{.dest_ip = our_address, .dest_port = port, .source_mac = config_mac_},
        CreateDelegate<&SsdpReflector::OnUnicastResponse>(this));
    if (!capture.IsValid()) {
        logger_.Error("Cannot proxy M-SEARCH: response capture registration failed");
        return;  // reservation drops here (RAII), freeing the port
    }

    // Relay the search from the reserved port so devices unicast their 200 OK to it.
    if (!target_socket_.SendUdpDatagram(packet.header.dest_ip, SSDP_PORT, port, packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot relay M-SEARCH from {} to {}", packet.header.source_ip, packet.header.dest_ip);
        return;  // reservation + capture drop here (RAII)
    }

    const auto mx = ParseMSearchMx(packet.payload);
    sessions_.try_emplace(SessionKey{.family = family, .port = port}, Session{
        .searcher_ip = packet.header.source_ip,
        .searcher_port = packet.header.source_port,
        .searcher_mac = packet.header.source_mac,
        .expiry = std::chrono::steady_clock::now() + std::chrono::seconds{mx} + SESSION_GRACE,
        .reservation = std::move(*reservation),
        .capture = std::move(capture),
    });
}
```

This needs `config_mac_` — store the config's `mac` in the reflector. Add `std::optional<MacAddress> config_mac_;` as a member and set it in the ctor init list (`, config_mac_{config.mac}`). (The current code uses `config.mac` only inline during `SetUpGroup`; capturing it as a member lets `OnSourcePacket` reuse it without holding the whole config.)

4. Add `OnUnicastResponse`:

```cpp
void SsdpReflector::OnUnicastResponse(const Packet& packet) noexcept {
    const SessionKey key{
        .family = packet.header.dest_ip.AddressFamily(),
        .port = packet.header.dest_port,
    };
    const auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        return;  // late/unknown response; the reservation already suppressed the ICMP
    }
    const auto& session = it->second;
    if (!source_socket_.SendUnicastUdpDatagram(session.searcher_mac, session.searcher_ip,
            session.searcher_port, packet.header.source_port, packet.payload, SSDP_TTL)) {
        logger_.Error("Cannot proxy SSDP response to searcher {}", session.searcher_ip);
        return;
    }
    logger_.Debug("Proxied SSDP response from {} to searcher {}", packet.header.source_ip,
        session.searcher_ip);
}
```

5. Add eviction:

```cpp
void SsdpReflector::EvictExpired(std::chrono::steady_clock::time_point now) noexcept {
    std::erase_if(sessions_, [now](const auto& entry) { return entry.second.expiry <= now; });
}

void SsdpReflector::SweepExpired() noexcept {
    EvictExpired(std::chrono::steady_clock::now());
}
```

Add includes to `ssdp_reflector.cpp`: `"port_reservation.h"`, `"ssdp_message.h"` (already), `<chrono>`, `<utility>` (already). `std::erase_if` on the `sessions_` `std::unordered_map` comes from `<unordered_map>` (included via the header), not `<algorithm>` — no `<algorithm>` needed here.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -L unit -R 'SsdpReflector' --output-on-failure`
Expected: PASS — all existing step-1 SSDP tests still green (NOTIFY path, MAC filter, direction drops, registration counts for the multicast registrations) plus the 6 new proxy/eviction/cap tests.

**Watch:** the existing `RegistersBothDirectionsPerGroup` asserts `RegistrationCount() == 2 * Groups().size()` immediately after construction (no M-SEARCH delivered yet), so the eviction timer (which is a `Dispatcher` timer, not a `PacketDispatcher` registration) does not change that count — confirm it still passes. If any existing count assertion now includes a stray registration, that's a bug in the implementation, not the test.

- [ ] **Step 6: Full unit-suite check**

Run: `ctest --test-dir build -L unit --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Full gate (data-path commit)**

Run each; all must pass:
```bash
ctest --test-dir build -L unit --output-on-failure
./docker_test.sh
./docker_test.sh release
python3 e2e/run.py
```
Expected: all green. (e2e still passes with the existing cases; the new round-trip cases come in Task 6.)

- [ ] **Step 8: Commit (with operator permission)**

```bash
git add src/reflector/ssdp_reflector.h src/reflector/ssdp_reflector.cpp tests/ssdp_reflector_test.cpp
git commit -m "feat(ssdp): proxy unicast M-SEARCH responses with timed session eviction"
```

---

## Task 6: e2e — active-search round trip

**Files:**
- Modify: `e2e/probe.py`, `e2e/run.py`

The existing harness (`run.py`) is a frozen `TestCase` dataclass + a `DockerE2E` class that, per case, creates three **one-shot** containers — reflector, receiver (`docker run -d` running `probe.py receive`), sender (`docker run` running `probe.py send`) — then `docker wait`s the receiver for the verdict. `probe.py` has exactly two subcommands, `send` and `receive` (argparse subparsers with `set_defaults(func=...)`). None of `listen`/`respond`/`make_listen_socket`/`make_send_socket`/`start_in`/`exec_in` exist, and `send` has no source-port bind.

The active-search round trip needs **two new probe roles** and a **new orchestration path** (the one-shot send-then-wait-receiver flow can't express "responder must be listening before the searcher sends, and the searcher both sends and receives"):

- a **searcher** (source side): binds a known source port, sends the M-SEARCH to the group, then receives the proxied `200 OK` on that same socket and checks it — one process, send+receive fused;
- a **responder** (target side): joins the SSDP group, receives the relayed M-SEARCH, and unicasts a `200 OK` back to *whoever sent it* (the reflector's `target_if`:P), which the reflector then proxies to the real searcher.

The responder replies to the datagram's sender, so it never needs to know the original searcher's address — the reflector's session mapping does that bridging.

- [ ] **Step 1: Add a `respond` subcommand to `probe.py`**

Mirror the existing `receive` structure (subparser + `set_defaults(func=...)`; reuse `parse_payload_hex`, `join_group`, the `family` int 4/6 convention, and a `print(... "ready" ...)` marker so `run.py` can wait for readiness). Add to `main()`'s subparsers:

```python
    respond_parser = subparsers.add_parser("respond", help="receive one datagram, then unicast a reply to its sender")
    respond_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    respond_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait for the datagram")
    respond_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")
    respond_parser.add_argument("--join-group", help="multicast group to join on --interface")
    respond_parser.add_argument("--interface", help="interface to join the multicast group on")
    respond_parser.add_argument("--reply-hex", required=True, type=parse_payload_hex, help="UDP payload to unicast back")
    respond_parser.set_defaults(func=respond)
```

(`main()` already dispatches via `return args.func(args)` — do **not** add an `args.mode` branch; there is none.) Add the handler (alongside `receive`):

```python
def respond(args: argparse.Namespace) -> int:
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.port))
        if args.join_group is not None:
            join_group(sock, family, args.join_group, args.interface)
        # Readiness marker so run.py can sequence the searcher after the responder is listening.
        print(f"responder ready: UDP socket bound on port {args.port}", flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"responder: no datagram for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"responder received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
        # Reply straight back to the sender (the reflector's target_if:P); it proxies to the searcher.
        # peer is the full tuple recvfrom returned (4-tuple for IPv6), preserving the link-local scope.
        sock.sendto(args.reply_hex, peer)
        print(f"responder replied {len(args.reply_hex)} bytes to {peer[0]}:{peer[1]}", flush=True)
        return 0
```

- [ ] **Step 2: Add a `search` subcommand to `probe.py`**

The searcher binds a known source port, sends the M-SEARCH to the group (reusing `send`'s multicast egress logic), then receives the proxied reply on the same socket. Add the subparser:

```python
    search_parser = subparsers.add_parser("search", help="send an M-SEARCH from a bound port, then await the proxied reply")
    search_parser.add_argument("--source-port", required=True, type=int, help="UDP port to bind and send from")
    search_parser.add_argument("--port", required=True, type=int, help="destination UDP port (1900)")
    search_parser.add_argument("--address", required=True, help="multicast group to send to")
    search_parser.add_argument("--interface", help="egress interface for multicast")
    search_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    search_parser.add_argument("--payload-hex", required=True, type=parse_payload_hex, help="M-SEARCH payload")
    search_parser.add_argument("--expect-payload-hex", required=True, type=parse_payload_hex, help="expected 200 OK payload")
    search_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the reply")
    search_parser.set_defaults(func=search)
```

and the handler (the multicast-egress setup mirrors the existing `send`):

```python
def search(args: argparse.Namespace) -> int:
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.source_port))  # the searcher's known source port

        scope_id = 0
        if family == socket.AF_INET6:
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope_id)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if args.interface:
                ifindex = socket.if_nametoindex(args.interface)
                mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)

        print(f"searcher ready: bound source port {args.source_port}", flush=True)
        sock.sendto(args.payload_hex, dest)
        print(f"searcher sent {len(args.payload_hex)} bytes to {args.address}:{args.port}", flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"searcher: no reply for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"searcher received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)
        if payload == args.expect_payload_hex:
            return 0
        print("searcher: reply payload does not match expected 200 OK", file=sys.stderr, flush=True)
        return 1
```

- [ ] **Step 3: Add a round-trip case + runner to `run.py`**

The one-shot `TestCase`/`DockerE2E` flow doesn't fit (it does send-then-`wait(receiver)`, with no responder-before-searcher ordering), so add a parallel `RoundTripCase` + a `DockerRoundTrip` subclass of `DockerE2E` that **reuses the base's network/reflector setup and cleanup verbatim** and swaps the actor methods. Add the SSDP `200 OK` payload constant near the other SSDP constants (around line 76):

```python
SSDP_OK_HEX = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "ST: ssdp:all\r\n"
    "USN: uuid:device::ssdp:all\r\n"
    "LOCATION: http://device.invalid/desc.xml\r\n\r\n"
).encode().hex()
SEARCHER_SOURCE_PORT = 49152
```

Add the case model and list (after `TEST_CASES`, around line 337):

```python
@dataclasses.dataclass(frozen=True)
class RoundTripCase:
    name: str
    family: int          # 4 or 6
    group: str
    timeout_seconds: float = 8.0


ROUNDTRIP_CASES = [
    RoundTripCase(name="ssdp_msearch_roundtrip", family=4, group=SSDP_GROUP_V4),
    RoundTripCase(name="ssdp_msearch_roundtrip_ipv6", family=6, group=SSDP_GROUP_V6),
]
```

Add the runner as a `DockerE2E` subclass. `DockerE2E.__init__` only reads `case.name`/`case.direction` for resource naming, so a `TestCase` shim lets us reuse `setup_networks`/`start_reflector`/`wait_for_container_log`/`cleanup`/`print_diagnostics` unchanged. The searcher runs on the **source** network (`REFLECTOR_SOURCE_IFNAME`, forward direction), the responder on the **target** network (`RECEIVER_IFNAME`); use the real ifnames from `run.py` (`REFLECTOR_SOURCE_IFNAME = "wol_src"`, `REFLECTOR_TARGET_IFNAME = "wol_dst"`, `RECEIVER_IFNAME = "probe0"`), never `lan`/`iot`:

```python
class DockerRoundTrip(DockerE2E):
    def __init__(self, args: argparse.Namespace, case: RoundTripCase) -> None:
        # The base __init__ only reads case.name and case.direction; a TestCase shim reuses all its
        # network/reflector setup + cleanup with no duplication.
        shim = TestCase(name=case.name, send_port=SSDP_PORT, receive_port=SSDP_PORT,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward")
        super().__init__(args, shim)
        self.rt = case
        self.responder_container = f"{self.prefix}-responder"
        self.searcher_container = f"{self.prefix}-searcher"
        self.containers = [self.searcher_container, self.responder_container, self.reflector_container]

    def start_responder(self) -> None:
        docker([
            "run", "-d", "--name", self.responder_container,
            "--network", f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={RECEIVER_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "respond",
            "--port", str(SSDP_PORT), "--timeout", str(self.rt.timeout_seconds),
            "--family", str(self.rt.family), "--join-group", self.rt.group,
            "--interface", RECEIVER_IFNAME, "--reply-hex", SSDP_OK_HEX,
        ])
        self.wait_for_container_log(self.responder_container, "responder ready", "responder")

    def run_searcher(self) -> None:
        docker([
            "run", "-d", "--name", self.searcher_container,
            "--network", f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "search",
            "--source-port", str(SEARCHER_SOURCE_PORT), "--port", str(SSDP_PORT),
            "--address", self.rt.group, "--interface", REFLECTOR_SOURCE_IFNAME,
            "--family", str(self.rt.family), "--payload-hex", SSDP_MSEARCH_HEX,
            "--expect-payload-hex", SSDP_OK_HEX, "--timeout", str(self.rt.timeout_seconds),
        ])

    def wait_for_searcher(self) -> None:
        exit_code = docker(["wait", self.searcher_container]).stdout.strip()
        logs = docker(["logs", self.searcher_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if exit_code != "0":
            raise RuntimeError(f"searcher failed with exit code {exit_code}")

    def run(self) -> None:
        print(f"\n=== {self.rt.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        self.start_responder()   # must be listening before the search goes out
        self.run_searcher()
        self.wait_for_searcher()
        print(f"PASS {self.rt.name}", flush=True)
```

Wire it into `main()` after the existing `for case in cases:` loop:

```python
    for case in ROUNDTRIP_CASES:
        with DockerRoundTrip(args, case) as runner:
            runner.run()
```

(The base `DockerE2E.__exit__`/`cleanup` tear down `self.containers` — which the subclass overrode to include responder + searcher — and `self.networks`, so no extra cleanup code is needed. Responder-before-searcher ordering is the deterministic `wait_for_container_log(..., "responder ready", ...)`, not a `sleep`. The `--case` selection stays scoped to `TestCase`; the round trips run unconditionally, like the existing full-suite default.)

- [ ] **Step 4: Run the e2e suite**

Run: `python3 e2e/run.py`
Expected: all existing cases PASS, plus `ssdp_msearch_roundtrip` and `ssdp_msearch_roundtrip_ipv6` PASS. The round trip exercises capture → reserve → relay-from-P → capture-response → unicast-inject end to end on real Linux network namespaces, reusing the `[discovery]` entry in `e2e/config.toml` (already `ssdp = true` on `wol_src`→`wol_dst`; **no config change needed**).

If the v6 twin is flaky on the Docker bridge (link-local scope quirks), keep it but say so explicitly in the run output; the v4 case is load-bearing. Do not silently drop it.

- [ ] **Step 5: Commit (with operator permission)**

```bash
git add e2e/probe.py e2e/run.py
git commit -m "test(e2e): add SSDP M-SEARCH unicast-response round-trip (v4 + v6)"
```

---

## Task 7: Documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite the SSDP bullet (README.md lines 134–137)**

The real SSDP bullet currently reads (lines 134–137):

```markdown
  - **SSDP / UPnP (UDP 1900):** reflects SSDP discovery between the two interfaces. `M-SEARCH`
    searches flow source → target, `NOTIFY` advertisements target → source. The unicast `HTTP/1.1
    200 OK` reply to an `M-SEARCH` is **not yet carried across segments** — passive discovery
    (`NOTIFY`) works fully; active search responses are planned for a later step.
```

Replace it with (drop the "not yet carried" limitation; state active discovery works):

```markdown
  - **SSDP / UPnP (UDP 1900):** reflects SSDP discovery between the two interfaces. `M-SEARCH`
    searches flow source → target, `NOTIFY` advertisements target → source. A device's unicast
    `HTTP/1.1 200 OK` reply to an `M-SEARCH` is proxied back to the searcher across segments, so
    active discovery works end to end; the proxy is always on whenever `ssdp` is enabled. (Reaching
    a device's `LOCATION` URL or driving DIAL across segments is out of scope.)
```

- [ ] **Step 2: Extend the `mac` bullet for SSDP response scoping (README.md lines 138–140)**

The real `mac` bullet currently reads (lines 138–140):

```markdown
  - **`mac` field (optional):** restricts which device's traffic is reflected, by source MAC. For
    WoL it filters the magic packet's target; for mDNS/SSDP it filters which device's
    advertisements are relayed (target → source).
```

Append to the SSDP clause that the filter now also scopes proxied responses:

```markdown
  - **`mac` field (optional):** restricts which device's traffic is reflected, by source MAC. For
    WoL it filters the magic packet's target; for mDNS/SSDP it filters which device's
    advertisements are relayed (target → source), and for SSDP it additionally scopes which
    devices' unicast `200 OK` responses are proxied back.
```

Match the surrounding README tone and formatting (no new headings).

- [ ] **Step 3: Verify no stale limitation wording remains**

Run: `grep -n 'not yet carried across segments\|planned for a later step' README.md`
Expected: no matches.

- [ ] **Step 3: Commit (with operator permission)**

```bash
git add README.md
git commit -m "docs: SSDP unicast response proxy is implemented and always-on"
```

---

## Self-Review (completed by plan author)

**Spec coverage** — every spec section maps to a task:
- §3.1 PortReservation → Task 1. §3.2 SendUnicastUdpDatagram + SourceAddress → Task 3. §3.3 ParseMSearchMx → Task 4. §3.4 session table / OnSourcePacket / OnUnicastResponse → Task 5. §3.5 Dispatcher timers + Timer + UnderlyingDispatcher → Task 2. §4 eviction → Task 5 (timer) + Task 2 (mechanism). §5 reply fields → Task 5 (OnUnicastResponse, no spoofing). §6 loop prevention / mid-dispatch safety → preserved by the existing dispatcher; Task 5 registers/erases through it. §7 testing → tests in every task. §8 config (no schema change) → nothing to do (verified: `SsdpConfig` unchanged). §9 commit breakdown → Tasks 1–7. §10 decisions → embedded. §11 out of scope (DIAL) → noted in Task 7 docs.

**Placeholder scan** — every code step shows complete code; commands have expected output. The one judgement-call area (the `EvictExpired` test seam) is resolved explicitly in Task 5 Step 2 by making `EvictExpired(now)` public (no test-only friend), consistent with the spec's "no friend" stance.

**Type consistency** — names used consistently across tasks: `PortReservation::Create`/`Port`; `Dispatcher::TimerId`/`RegisterTimer`/`UnregisterTimer`; `EventLoopDispatcher::FireDueTimers`/`NextTimeout`/`MAX_POLL_INTERVAL`; `PacketDispatcher::UnderlyingDispatcher`; `LinkSocket::SendUnicastUdpDatagram`/`SourceAddress`; `FakeLinkSocket::unicast_sent`/`source_v4`/`source_v6`; `FakeDispatcher::FireTimers`/`TimerCount`/`dispatcher` (owned on `FakePacketDispatcher`); `SsdpReflector::OnUnicastResponse`/`EvictExpired(now)`/`SweepExpired`/`SessionKey`/`Session`/`MAX_SESSIONS`/`SESSION_GRACE`/`EVICTION_INTERVAL`/`config_mac_`/`packet_dispatcher_`; `ParseMSearchMx`. The reflector ctor signature is unchanged (still `{packet_dispatcher, source, target, config}`), so `Application::ConfigureReflectors<SsdpReflector>` needs no change — confirmed against the template.
