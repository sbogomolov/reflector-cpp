#include "reflector/dial_proxy.h"
#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "reflector/tcp_socket.h"
#include "reflector/util/stream_buffer.h"
#include "mocks/fake_dispatcher.h"
#include "mocks/fake_interface.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using namespace reflector;

// Distinct device endpoints on the (notional) target subnet; only their identity matters here —
// EnsureListener keys on them; nothing actually connects to these (fake) addresses.
IpEndpoint Device(uint8_t last_octet, uint16_t port = 8008) {
    return {IpAddress::FromString(std::format("10.0.0.{}", last_octet)).value(), port};
}

// A loopback "device": a listening TcpSocket the proxy will Connect() to. Its LocalEndpoint is the
// device endpoint handed to EnsureDiscoveryListener.
struct FakeDevice {
    TcpSocket listener;
    IpEndpoint endpoint;

    // nullopt when the loopback listen fails (no such environment is expected, but dereferencing
    // the disengaged optional here turned that into a bad-free instead of a test failure).
    static std::optional<FakeDevice> Make() {
        const FakeInterface loopback;  // defaults: v4 source 127.0.0.1; only read during the call
        auto listener = TcpSocket::Listen(loopback, IpAddress::Family::V4);
        EXPECT_TRUE(listener.has_value());
        if (!listener) {
            return std::nullopt;
        }
        const auto endpoint = listener->LocalEndpoint();
        return FakeDevice{std::move(*listener), endpoint};
    }
};

// A raw blocking client socket that connects to the reflector listener at `authority`, so the
// listener's accept() yields a real client fd. Returned as the connected fd (or -1 on failure); the
// caller closes it.
int ConnectRawClient(const IpEndpoint& authority) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_storage storage{};
    const auto len = authority.ToSockaddr(storage);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&storage), len) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Block until the non-blocking upstream connect on `fd` settles (writable or error), so a manually-fired
// writable edge sees the real completed state instead of racing the loopback handshake.
void WaitConnectComplete(int fd) {
    pollfd pfd{.fd = fd, .events = POLLOUT, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "upstream connect did not settle within 5s";
}

// Read exactly `want` bytes from the device-side socket as the forwarded request arrives (loopback
// delivery is asynchronous from the proxy's send, so poll+read in a loop rather than racing one Read).
std::string ReadExactly(TcpSocket& sock, size_t want) {
    std::string out;
    while (out.size() < want) {
        pollfd pfd{.fd = sock.Fd(), .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 5000) <= 0) {
            break;
        }
        std::byte buf[256];
        const auto got = sock.Read(std::span<std::byte>{buf, sizeof(buf)});
        if (got.status != IoStatus::Ok) {
            break;
        }
        out.append(reinterpret_cast<const char*>(buf), got.bytes);
    }
    return out;
}

// Write all of `data` to a blocking raw fd; returns false if any write short-fails.
bool WriteAllFd(int fd, std::string_view data) {
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

// Read exactly `want` bytes from a blocking raw fd (poll+read so loopback delivery latency doesn't race a
// single read). Returns fewer bytes only on EOF/error/timeout.
std::string ReadExactlyFd(int fd, size_t want) {
    std::string out;
    while (out.size() < want) {
        pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 5000) <= 0) {
            break;
        }
        char buf[256];
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

// A device REST authority on the (notional) device subnet, distinct from a loopback device-listener
// endpoint: a cross-boundary "http://host:port" the proxy must replace with a reflector authority.
IpEndpoint DeviceRest(uint8_t last_octet, uint16_t port) {
    return {IpAddress::FromString(std::format("10.0.0.{}", last_octet)).value(), port};
}

// Extract the "http://host:port" authority from the FIRST occurrence of `header_name` (e.g.
// "Application-URL:" / "Location:") in `message`, parsed back into an IpEndpoint — so a test can compare the
// rewritten authority against the reflector listener rather than string-matching a port it computed by hand.
// Mirrors the framer's own parse (scheme, then host:port up to '/'/space). nullopt if absent/unparseable.
std::optional<IpEndpoint> ExtractUrlAuthority(std::string_view message, std::string_view header_name) {
    const size_t name_at = message.find(header_name);
    if (name_at == std::string_view::npos) {
        return std::nullopt;
    }
    const size_t line_end = message.find("\r\n", name_at);
    const std::string_view line =
        message.substr(name_at, (line_end == std::string_view::npos ? message.size() : line_end) - name_at);
    constexpr std::string_view SCHEME = "http://";
    const size_t scheme_at = line.find(SCHEME);
    if (scheme_at == std::string_view::npos) {
        return std::nullopt;
    }
    const size_t auth_start = scheme_at + SCHEME.size();
    size_t auth_end = line.find_first_of("/ \t", auth_start);
    if (auth_end == std::string_view::npos) {
        auth_end = line.size();
    }
    const std::string_view authority = line.substr(auth_start, auth_end - auth_start);
    const size_t colon = authority.rfind(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const auto addr = IpAddress::FromString(std::string{authority.substr(0, colon)});
    if (!addr) {
        return std::nullopt;
    }
    uint16_t port = 0;
    const std::string_view port_text = authority.substr(colon + 1);
    if (std::from_chars(port_text.data(), port_text.data() + port_text.size(), port).ec != std::errc{}) {
        return std::nullopt;
    }
    return IpEndpoint{*addr, port};
}

} // namespace

namespace reflector {


// Friend fixture (the project idiom, e.g. RawSocketTest): reaches the internal EnsureRestListener, whose
// only production funnel is the u2c rewrite.
class DialProxyTest : public ::testing::Test {
protected:
    FakeDispatcher dispatcher;
    FakeInterface source_if;  // the v4 source defaults to 127.0.0.1, so listeners bind loopback
    FakeInterface target_if;

    DialProxy MakeProxy() { return DialProxy{dispatcher, source_if, target_if, "DialProxy:test"}; }

    static std::optional<IpEndpoint> EnsureRest(DialProxy& proxy, const IpEndpoint& device) {
        return proxy.EnsureRestListener(device);
    }

    // The listener fd minted for `device` (-1 if none), so a test can tie a registration to the actual
    // listener via FakeDispatcher::IsWatching rather than trusting the registration count alone.
    static int ListenerFd(DialProxy& proxy, const IpEndpoint& device) {
        const auto it = proxy.endpoints_.find(device);
        return it == proxy.endpoints_.end() ? -1 : it->second.listener.Fd();
    }

    // The reflector authority (source_if-addr:minted-port) of the listener minted for `device` — what a u2c
    // rewrite hands the client. nullopt if no listener exists for `device`. Returns the listener's cached
    // local endpoint, so a test can compare the rewritten Application-URL/Location against the real listener.
    static std::optional<IpEndpoint> ListenerAuthority(DialProxy& proxy, const IpEndpoint& device) {
        const auto it = proxy.endpoints_.find(device);
        if (it == proxy.endpoints_.end()) {
            return std::nullopt;
        }
        return it->second.listener.LocalEndpoint();
    }

    // The number of endpoints currently in the Rest role — the invariant MAX_REST_LISTENERS bounds.
    static size_t CountRest(DialProxy& proxy) {
        return proxy.CountInRole(DialProxy::Endpoint::Role::Rest);
    }

    // Whether `device` has a registered Endpoint in the Rest role (false if absent or still Discovery), so a
    // u2c mint/promotion test can assert the role flipped without reaching into the Endpoint struct directly.
    static bool IsRestEndpoint(DialProxy& proxy, const IpEndpoint& device) {
        const auto it = proxy.endpoints_.find(device);
        return it != proxy.endpoints_.end() && it->second.role == DialProxy::Endpoint::Role::Rest;
    }
    static bool HasEndpoint(DialProxy& proxy, const IpEndpoint& device) {
        return proxy.endpoints_.contains(device);
    }

    // Seams into the Connection state. Connections live in an id-keyed node-stable map; a test
    // reaches one by its id (the next id minted at accept time is next_connection_id_).
    static size_t ConnectionCount(DialProxy& proxy) { return proxy.connections_.size(); }
    static uint64_t NextConnectionId(DialProxy& proxy) { return proxy.next_connection_id_; }

    static DialProxy::Connection* FindConnection(DialProxy& proxy, uint64_t id) {
        const auto it = proxy.connections_.find(id);
        return it == proxy.connections_.end() ? nullptr : &it->second;
    }

    static int ConnUpstreamFd(DialProxy::Connection& conn) { return conn.upstream.Fd(); }
    static int ConnClientFd(DialProxy::Connection& conn) { return conn.client.Fd(); }
    static bool ConnIsOpen(DialProxy::Connection& conn) {
        return !conn.upstream.IsConnecting();
    }
    static bool ConnIsConnectingUpstream(DialProxy::Connection& conn) {
        return conn.upstream.IsConnecting();
    }
    static bool ConnClosed(DialProxy::Connection& conn) { return conn.closed; }
    static void AbortConn(DialProxy::Connection& conn) { conn.Abort(); }
    static TcpSocket& ConnUpstream(DialProxy::Connection& conn) { return conn.upstream; }
    static TcpSocket& ConnClient(DialProxy::Connection& conn) { return conn.client; }
    static StreamBuffer& ConnC2uRx(DialProxy::Connection& conn) { return conn.c2u_rx; }
    static StreamBuffer& ConnU2cRx(DialProxy::Connection& conn) { return conn.u2c_rx; }

    // The repurposed deadline field (connect deadline while Connecting, idle deadline once Open). The real
    // clock sets it at accept / connect-completion / forward; a test sets it directly so the eviction sweep
    // (driven by FireTimers with an explicit `now`) is fully deterministic without racing wall time.
    static std::chrono::steady_clock::time_point ConnDeadline(DialProxy::Connection& conn) {
        return conn.deadline;
    }
    static void SetConnDeadline(DialProxy::Connection& conn, std::chrono::steady_clock::time_point t) {
        conn.deadline = t;
    }
    // The Endpoint's last_active, refreshed at every mint/reuse/accept; the eviction sweep compares it
    // against the role grace. Set directly so the grace test is deterministic.
    static void SetEndpointLastActive(
        DialProxy& proxy, const IpEndpoint& device, std::chrono::steady_clock::time_point t) {
        const auto it = proxy.endpoints_.find(device);
        ASSERT_NE(it, proxy.endpoints_.end());
        it->second.last_active = t;
    }
    static size_t EndpointCount(DialProxy& proxy) { return proxy.endpoints_.size(); }
    // The Endpoint's active_connections refcount (0 if no such endpoint) — what EvictExpired checks instead of
    // scanning connections_. Tests assert the Connection ctor ++ / dtor -- pairing through it.
    static size_t EndpointActiveConnections(DialProxy& proxy, const IpEndpoint& device) {
        const auto it = proxy.endpoints_.find(device);
        return it == proxy.endpoints_.end() ? 0 : it->second.active_connections;
    }
    // Drive the eviction sweep at simulated time `now` (the timer's fire-cycle clock), as the reactor would.
    void Evict(std::chrono::steady_clock::time_point now) {
        dispatcher.FireTimers(now);  // the proxy registered the timer; the dispatcher fires it
    }

    // Wait for the listener to report a pending connection (POLLIN), then fire its readable edge to
    // accept it. A loopback connect() returns after the handshake, but the listener's accept queue can
    // lag it by a beat, so poll for readability -- bounded by a wall-clock deadline -- rather than
    // busy-firing a fixed number of times, which could exhaust its count before the queue updates under
    // a slow emulator (qemu-arm-static). Returns the Connection keyed by the next id, or nullptr after
    // the deadline. Shared by the accept-and-check tests.
    DialProxy::Connection* AcceptOne(DialProxy& proxy, int listener_fd) {
        const uint64_t id = NextConnectionId(proxy);
        DialProxy::Connection* conn = FindConnection(proxy, id);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (conn == nullptr && std::chrono::steady_clock::now() < deadline) {
            pollfd pfd{.fd = listener_fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 1000) > 0) {
                dispatcher.FireReadable(listener_fd);
                conn = FindConnection(proxy, id);
            }
        }
        return conn;
    }
};

TEST_F(DialProxyTest, EnsureDiscoveryListenerAllocatesAReflectorAuthority) {
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(Device(2));

    ASSERT_TRUE(authority.has_value());
    EXPECT_EQ(authority->addr, IpAddress::LoopbackV4());  // bound to the source_if address
    EXPECT_NE(authority->port, 0);                        // an ephemeral port was assigned
    EXPECT_EQ(dispatcher.RegistrationCount(), 1u);        // the listener fd is watched for accept
}

TEST_F(DialProxyTest, ReuseSameDeviceReturnsSameListenerAndOneRegistration) {
    auto proxy = MakeProxy();
    const auto device = Device(2);

    const auto first = proxy.EnsureDiscoveryListener(device);
    const auto second = proxy.EnsureDiscoveryListener(device);

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(*first, *second);                     // same listener, same authority
    EXPECT_EQ(dispatcher.RegistrationCount(), 1u);  // no second listener minted
}

TEST_F(DialProxyTest, DistinctDevicesGetDistinctListeners) {
    auto proxy = MakeProxy();

    const auto first = proxy.EnsureDiscoveryListener(Device(2));
    const auto second = proxy.EnsureDiscoveryListener(Device(3));

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->port, second->port);           // separate ephemeral listeners
    EXPECT_EQ(dispatcher.RegistrationCount(), 2u);
}

TEST_F(DialProxyTest, NulloptSourceAddressYieldsNoListener) {
    source_if.SetV4(std::nullopt);  // the source interface has no IPv4 address to bind
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(Device(2));

    EXPECT_FALSE(authority.has_value());
    EXPECT_EQ(dispatcher.RegistrationCount(), 0u);  // nothing minted, nothing registered
}

TEST_F(DialProxyTest, DiscoveryCapReturnsNulloptWithoutANewRegistration) {
    auto proxy = MakeProxy();
    for (size_t i = 0; i < DialProxy::MAX_DISCOVERY_LISTENERS; ++i) {
        ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(static_cast<uint8_t>(i + 1))).has_value());
    }
    ASSERT_EQ(dispatcher.RegistrationCount(), DialProxy::MAX_DISCOVERY_LISTENERS);

    const auto over_cap = proxy.EnsureDiscoveryListener(
        Device(static_cast<uint8_t>(DialProxy::MAX_DISCOVERY_LISTENERS + 1)));

    EXPECT_FALSE(over_cap.has_value());
    EXPECT_EQ(dispatcher.RegistrationCount(), DialProxy::MAX_DISCOVERY_LISTENERS);  // no listener leaked
}

TEST_F(DialProxyTest, RestCapReturnsNulloptWithoutANewRegistration) {
    auto proxy = MakeProxy();
    for (size_t i = 0; i < DialProxy::MAX_REST_LISTENERS; ++i) {
        ASSERT_TRUE(EnsureRest(proxy, Device(static_cast<uint8_t>(i + 1))).has_value());
    }
    ASSERT_EQ(dispatcher.RegistrationCount(), DialProxy::MAX_REST_LISTENERS);

    const auto over_cap = EnsureRest(proxy, Device(static_cast<uint8_t>(DialProxy::MAX_REST_LISTENERS + 1)));

    EXPECT_FALSE(over_cap.has_value());
    EXPECT_EQ(dispatcher.RegistrationCount(), DialProxy::MAX_REST_LISTENERS);  // no listener leaked
}

TEST_F(DialProxyTest, DiscoveryThenRestPromotesAndReusesTheListener) {
    auto proxy = MakeProxy();
    const auto device = Device(2);

    const auto discovery = proxy.EnsureDiscoveryListener(device);
    ASSERT_TRUE(discovery.has_value());
    const int discovery_fd = ListenerFd(proxy, device);
    ASSERT_GE(discovery_fd, 0);
    ASSERT_TRUE(dispatcher.IsWatching(discovery_fd));

    const auto rest = EnsureRest(proxy, device);

    ASSERT_TRUE(rest.has_value());
    EXPECT_EQ(*discovery, *rest);                          // promotion reuses the same authority...
    EXPECT_EQ(ListenerFd(proxy, device), discovery_fd);   // ...the same listener fd, not an erase+re-mint
    EXPECT_TRUE(dispatcher.IsWatching(discovery_fd));      // still the watched fd
    EXPECT_EQ(dispatcher.RegistrationCount(), 1u);         // no second listener minted
}

// A device promoted Discovery -> Rest counts against the Rest cap (its role is now Rest), so it no
// longer occupies a Discovery slot — a fresh Discovery device can still be minted alongside it.
TEST_F(DialProxyTest, PromotedDeviceCountsAgainstTheRestCap) {
    auto proxy = MakeProxy();
    // Fill the Rest cap minus one, then promote one extra device into Rest to fill it exactly.
    for (size_t i = 0; i < DialProxy::MAX_REST_LISTENERS - 1; ++i) {
        ASSERT_TRUE(EnsureRest(proxy, Device(static_cast<uint8_t>(i + 1))).has_value());
    }
    const auto promoted = Device(static_cast<uint8_t>(DialProxy::MAX_REST_LISTENERS));
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(promoted).has_value());  // a Discovery device...
    ASSERT_TRUE(EnsureRest(proxy, promoted).has_value());              // ...promoted to Rest fills the cap

    const auto over_rest = EnsureRest(proxy, Device(static_cast<uint8_t>(DialProxy::MAX_REST_LISTENERS + 1)));

    EXPECT_FALSE(over_rest.has_value());  // the promoted device occupies a Rest slot

    // ...and it vacated its Discovery slot: a full set of fresh Discovery listeners still mints alongside.
    for (size_t i = 0; i < DialProxy::MAX_DISCOVERY_LISTENERS; ++i) {
        EXPECT_TRUE(proxy.EnsureDiscoveryListener(Device(static_cast<uint8_t>(100 + i))).has_value());
    }
}

TEST_F(DialProxyTest, RegistersTheListenersOwnFdForAccept) {
    auto proxy = MakeProxy();
    const auto device = Device(2);

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());

    const int fd = ListenerFd(proxy, device);  // the real listener socket, via the friend seam
    EXPECT_GE(fd, 0);
    EXPECT_TRUE(dispatcher.IsWatching(fd));  // the accept registration watches that exact fd
}

TEST_F(DialProxyTest, BindAddressFlowsFromTheSourceInterface) {
    // The listener must bind the source_if address, not a hard-coded loopback. A distinct loopback address
    // (127.0.0.2) catches a LoopbackV4-hardcoded mint. Not every platform routes all of 127/8 to lo (macOS
    // assigns only 127.0.0.1), so skip where it can't bind — the docker (Linux) gate still exercises this.
    const auto alt = IpAddress::FromString("127.0.0.2").value();
    FakeInterface alt_if;
    alt_if.SetV4(alt);
    if (!TcpSocket::Listen(alt_if, IpAddress::Family::V4)) {
        GTEST_SKIP() << "127.0.0.2 is not bindable on this platform";
    }
    source_if.SetV4(alt);
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(Device(2));

    ASSERT_TRUE(authority.has_value());
    EXPECT_EQ(authority->addr, alt);  // bound to the source_if address, not a hard-coded loopback
}

// A source-interface address change leaves every minted listener bound to a now-dead address. The proxy
// drops the stale listeners (and stops its reaper once both maps empty) so the next rewrite re-mints against
// the fresh address. Without this, each rewrite refreshes the endpoint's last_active, so a chatty device
// would keep the stale listener alive past the eviction grace indefinitely.
TEST_F(DialProxyTest, OnInterfaceChangedDropsListenersBoundToAChangedSourceAddress) {
    auto proxy = MakeProxy();
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(2)).has_value());
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(3)).has_value());
    ASSERT_EQ(EndpointCount(proxy), 2u);
    const int fd = ListenerFd(proxy, Device(2));
    ASSERT_TRUE(dispatcher.IsWatching(fd));

    source_if.SetV4(std::nullopt);  // source_if lost its IPv4 source: every listener's bind is now stale
    proxy.OnInterfaceChanged();

    EXPECT_EQ(EndpointCount(proxy), 0u);         // both stale listeners dropped
    EXPECT_FALSE(HasEndpoint(proxy, Device(2)));
    EXPECT_FALSE(dispatcher.IsWatching(fd));      // the accept registration went with the endpoint
    EXPECT_EQ(dispatcher.TimerCount(), 0u);       // nothing left to sweep -> the reaper stopped
}

// An OnInterfaceChanged that does not actually change source_if's V4 source leaves the listeners untouched —
// no needless re-mint churn, no dropped in-flight discovery.
TEST_F(DialProxyTest, OnInterfaceChangedKeepsListenersWhenSourceAddressUnchanged) {
    auto proxy = MakeProxy();
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(2)).has_value());
    const int fd = ListenerFd(proxy, Device(2));

    proxy.OnInterfaceChanged();  // source_if still has its default 127.0.0.1 source

    EXPECT_EQ(EndpointCount(proxy), 1u);
    EXPECT_TRUE(HasEndpoint(proxy, Device(2)));
    EXPECT_TRUE(dispatcher.IsWatching(fd));
}

// A source address that CHANGES to a different live address (rather than disappearing outright) must also
// stale the old listeners -- is_stale's `current != old_addr` branch, not just its `current == nullopt`
// branch. Mirrors OnInterfaceChangedDropsListenersBoundToAChangedSourceAddress with a live replacement
// address instead of none, and additionally proves the next advertisement re-mints against the new address
// rather than reusing the stale listener.
TEST_F(DialProxyTest, OnInterfaceChangedDropsListenersWhenSourceAddressChangesToADifferentLiveAddress) {
    // Not every platform routes all of 127/8 to lo (macOS assigns only 127.0.0.1); skip where 127.0.0.2
    // isn't bindable, as BindAddressFlowsFromTheSourceInterface does -- the docker (Linux) gate still
    // exercises this.
    const auto alt = IpAddress::FromString("127.0.0.2").value();
    FakeInterface alt_if;
    alt_if.SetV4(alt);
    if (!TcpSocket::Listen(alt_if, IpAddress::Family::V4)) {
        GTEST_SKIP() << "127.0.0.2 is not bindable on this platform";
    }

    auto proxy = MakeProxy();
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(2)).has_value());
    ASSERT_EQ(EndpointCount(proxy), 1u);
    const int old_fd = ListenerFd(proxy, Device(2));
    ASSERT_TRUE(dispatcher.IsWatching(old_fd));

    source_if.SetV4(alt);  // the source address CHANGED, not nulled
    proxy.OnInterfaceChanged();

    EXPECT_EQ(EndpointCount(proxy), 0u);          // the old-address listener went too
    EXPECT_FALSE(HasEndpoint(proxy, Device(2)));
    EXPECT_FALSE(dispatcher.IsWatching(old_fd));   // its accept registration went with it
    EXPECT_EQ(dispatcher.TimerCount(), 0u);        // nothing left to sweep -> the reaper stopped

    // The next advertisement re-mints against the NEW address, not a reuse of the stale listener.
    const auto authority = proxy.EnsureDiscoveryListener(Device(2));
    ASSERT_TRUE(authority.has_value());
    EXPECT_EQ(authority->addr, alt);  // bound to the NEW address -- a reused stale listener would still carry 127.0.0.1
}

TEST_F(DialProxyTest, DiscoveryAndRestCapsAreIndependent) {
    auto proxy = MakeProxy();
    // Fill the Discovery cap entirely...
    for (size_t i = 0; i < DialProxy::MAX_DISCOVERY_LISTENERS; ++i) {
        ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(static_cast<uint8_t>(i + 1))).has_value());
    }

    // ...a fresh Rest device still mints: Discovery slots don't count against the Rest cap.
    EXPECT_TRUE(EnsureRest(proxy, Device(100)).has_value());
}

// Regression for the cap-bypass: a Discovery device cannot be promoted to Rest while the Rest cap is
// already full — the reuse branch must enforce the cap, not silently overrun it (would reach cap + 1).
TEST_F(DialProxyTest, PromotionRefusedWhenRestCapIsFull) {
    auto proxy = MakeProxy();
    for (size_t i = 0; i < DialProxy::MAX_REST_LISTENERS; ++i) {
        ASSERT_TRUE(EnsureRest(proxy, Device(static_cast<uint8_t>(i + 1))).has_value());
    }
    // A separate device with a live Discovery listener, while Rest is at cap.
    const auto device = Device(static_cast<uint8_t>(DialProxy::MAX_REST_LISTENERS + 1));
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());
    const int discovery_fd = ListenerFd(proxy, device);
    const auto registrations = dispatcher.RegistrationCount();
    ASSERT_EQ(CountRest(proxy), DialProxy::MAX_REST_LISTENERS);

    const auto promoted = EnsureRest(proxy, device);

    EXPECT_FALSE(promoted.has_value());                               // refused, not promoted over cap
    EXPECT_EQ(CountRest(proxy), DialProxy::MAX_REST_LISTENERS);       // still exactly at cap, not cap + 1
    EXPECT_EQ(dispatcher.RegistrationCount(), registrations);         // no registration added or dropped
    EXPECT_TRUE(dispatcher.IsWatching(discovery_fd));                 // the Discovery listener is untouched
}

// --- accept -> egress-pinned connect -> the unified write handler ---
//
// These cases run UNPRIVILEGED: target_if's index stays 0 so Connect adds no egress pin
// (loopback needs none), and source_if/target_if default their v4 source to 127.0.0.1. A real loopback
// TcpSocket plays the device upstream; readiness edges are driven by hand through the FakeDispatcher
// (there is no real reactor here).


// 1. Accept mints a Connection and registers both fds; upstream is write-armed (connecting), the
//    established client is not.
TEST_F(DialProxyTest, AcceptCreatesConnectionAndRegistersBothFds) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    ASSERT_GE(listener_fd, 0);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(ConnectionCount(proxy), 1u);

    const int accepted_client_fd = ConnClientFd(*conn);
    const int upstream_fd = ConnUpstreamFd(*conn);
    EXPECT_TRUE(dispatcher.IsWatching(accepted_client_fd));
    EXPECT_TRUE(dispatcher.IsWatching(upstream_fd));
    EXPECT_TRUE(dispatcher.IsWriteArmed(upstream_fd));   // connecting -> armed for connect-completion
    EXPECT_FALSE(dispatcher.IsWriteArmed(accepted_client_fd));  // established at accept -> not armed

    ::close(client_fd);
}

// Abort sends the client a FIN immediately (not deferred to the 5s eviction), yet still leaves the node in
// place for the UAF-safe deferred reap.
TEST_F(DialProxyTest, AbortShutsDownTheClientPromptlyButLeavesTheNodeForEviction) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    ASSERT_EQ(ConnectionCount(proxy), 1u);

    AbortConn(*conn);

    // The FIN reaches the client at once: a blocking recv returns an orderly EOF (0 bytes) now, not after a
    // 5s eviction stall.
    pollfd pfd{.fd = client_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "client did not see the FIN from Abort";
    char buf[16];
    EXPECT_EQ(::recv(client_fd, buf, sizeof(buf), 0), 0);

    // The node still exists (deferred erasure keeps the on-stack handler safe); only eviction reaps it.
    EXPECT_EQ(ConnectionCount(proxy), 1u);
    Evict(std::chrono::steady_clock::now() + std::chrono::hours{1});
    EXPECT_EQ(ConnectionCount(proxy), 0u);

    ::close(client_fd);
}

// 2. The egress-pinned connect completes on the upstream writable edge: phase flips to Open.
TEST_F(DialProxyTest, EgressPinnedConnectCompletesOnWritableEdge) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(ConnIsConnectingUpstream(*conn));

    const int upstream_fd = ConnUpstreamFd(*conn);
    WaitConnectComplete(upstream_fd);  // let the loopback handshake land before firing the edge
    dispatcher.FireWritable(upstream_fd);

    EXPECT_TRUE(ConnIsOpen(*conn));
    EXPECT_FALSE(ConnIsConnectingUpstream(*conn));

    ::close(client_fd);
}

// 3. A request queued into the still-connecting upstream's send buffer is delivered by the write handler's
//    Flush on the single connect-completion edge. Send-while-Connecting buffers uniformly now (Linux EAGAIN
//    and macOS ENOTCONN-while-connecting both map to WouldBlock), so a deleted Flush would leave the tail
//    pending and the device empty on both platforms.
TEST_F(DialProxyTest, QueuedRequestFlushesOnConnectCompletion) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);

    const char request[] = "GET / HTTP/1.1\r\n\r\n";
    const std::span<const std::byte> bytes{reinterpret_cast<const std::byte*>(request), sizeof(request) - 1};

    // A connecting socket can take nothing now, so Send buffers the whole tail (WouldBlock on both platforms).
    ASSERT_EQ(ConnUpstream(*conn).Send(bytes), SendStatus::Ok);

    const int upstream_fd = ConnUpstreamFd(*conn);
    WaitConnectComplete(upstream_fd);  // let the loopback handshake land before firing the edge
    dispatcher.FireWritable(upstream_fd);  // one edge: FinishConnect -> Open, then Flush drains the request

    EXPECT_TRUE(ConnIsOpen(*conn));
    EXPECT_FALSE(ConnUpstream(*conn).WantsWrite());  // the buffered request drained on that single edge

    // Accept the device-side socket (poll the listener: accept readiness can lag the connect) and read
    // the forwarded request as it arrives.
    pollfd lpoll{.fd = device->listener.Fd(), .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&lpoll, 1, 5000), 0) << "device listener never became acceptable";
    auto device_side = device->listener.Accept();
    ASSERT_TRUE(device_side.has_value());
    EXPECT_EQ(ReadExactly(*device_side, sizeof(request) - 1),
        std::string_view(request, sizeof(request) - 1));

    ::close(client_fd);
}

// 4. A refused connect (no listener at the device port) surfaces on the writable edge and tears down:
//    both regs dropped, the Connection marked closed (it lingers until the eviction reaper).
TEST_F(DialProxyTest, ConnectFailureTearsDownTheConnection) {
    // Bind a loopback port then drop the listener so the port has nothing listening: the proxy's
    // connect to it is refused, surfacing on the writable edge (FinishConnect -> Error).
    const auto dead_endpoint = [] {
        const FakeInterface loopback;
        auto probe = TcpSocket::Listen(loopback, IpAddress::Family::V4);
        EXPECT_TRUE(probe.has_value());
        return probe->LocalEndpoint();
    }();  // probe closed: the port is now refusing

    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(dead_endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, dead_endpoint);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    const int accepted_client_fd = ConnClientFd(*conn);
    const int upstream_fd = ConnUpstreamFd(*conn);

    // The loopback connect's refusal (RST -> SO_ERROR) is asynchronous. Poll for POLLOUT and inspect
    // revents for POLLERR/POLLHUP -- the failed connect is writable, with the error riding alongside,
    // and revents (unlike getsockopt) does not consume SO_ERROR, which FinishConnect must still read.
    // POLLOUT must be requested: macOS does not surface POLLERR for a bare events == 0 poll. The
    // writable edge can briefly precede the RST, so bound the wait by a wall-clock deadline (not a
    // fixed iteration count) and sleep between checks: the original count-bounded loop busy-spun on the
    // immediately-ready POLLOUT, exhausting its budget in microseconds of wall-clock -- and the spin
    // also starved the RST's delivery -- before the error surfaced under qemu-arm-static.
    pollfd pfd{.fd = upstream_fd, .events = POLLOUT, .revents = 0};
    bool errored = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!errored && std::chrono::steady_clock::now() < deadline) {
        ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "upstream connect neither completed nor failed within 5s";
        errored = (pfd.revents & (POLLERR | POLLHUP)) != 0;
        if (!errored) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // writable but no error yet: let the RST land
        }
    }
    ASSERT_TRUE(errored) << "expected the refused connect to surface as an error";

    dispatcher.FireWritable(upstream_fd);  // connect refused -> FinishConnect Error -> Abort

    EXPECT_TRUE(ConnClosed(*conn));                          // marked closed (lingers until the reaper)
    EXPECT_FALSE(dispatcher.IsWatching(accepted_client_fd)); // both regs dropped immediately
    EXPECT_FALSE(dispatcher.IsWatching(upstream_fd));

    ::close(client_fd);
}

// 5. At MAX_CONNECTIONS a further accept is dropped: no new Connection, the surplus client closed.
TEST_F(DialProxyTest, DropsNewAcceptAtMaxConnections) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);

    std::vector<int> client_fds;
    for (size_t i = 0; i < DialProxy::MAX_CONNECTIONS; ++i) {
        const int fd = ConnectRawClient(*authority);
        ASSERT_GE(fd, 0);
        client_fds.push_back(fd);
        // OnAccept accepts exactly one pending client per readable edge (the level-triggered reactor
        // re-fires while the backlog is non-empty). A loopback connect() returns only after the
        // handshake, but the accept queue update can still lag the connect by a beat, so re-fire until
        // this client is accepted rather than racing a single edge.
        const size_t want = i + 1;
        for (int attempt = 0; attempt < 100 && ConnectionCount(proxy) < want; ++attempt) {
            dispatcher.FireReadable(listener_fd);
        }
    }
    ASSERT_EQ(ConnectionCount(proxy), DialProxy::MAX_CONNECTIONS);
    const auto registrations_at_cap = dispatcher.RegistrationCount();

    // One more accept past the cap: the client connects, but the proxy drops it (no Connection, no
    // new registration; the surplus client TcpSocket is closed by RAII).
    const int surplus_fd = ConnectRawClient(*authority);
    ASSERT_GE(surplus_fd, 0);
    dispatcher.FireReadable(listener_fd);

    EXPECT_EQ(ConnectionCount(proxy), DialProxy::MAX_CONNECTIONS);          // no new Connection
    EXPECT_EQ(dispatcher.RegistrationCount(), registrations_at_cap);       // no new registration

    for (const int fd : client_fds) {
        ::close(fd);
    }
    ::close(surplus_fd);
}

// 6. A target interface with no IPv4 address drops the accept: the client is taken off the listener, but
//    no egress-pinned connect is possible, so no Connection is created and nothing new is registered.
//    Reachable in production via a transient target-interface address change.
TEST_F(DialProxyTest, TargetInterfaceWithoutIpv4DropsTheAccept) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();

    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const auto registrations_before = dispatcher.RegistrationCount();  // just the listener fd

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);

    target_if.SetV4(std::nullopt);  // the target interface lost its IPv4 address
    dispatcher.FireReadable(listener_fd);

    EXPECT_EQ(ConnectionCount(proxy), 0u);                            // no Connection minted
    EXPECT_EQ(dispatcher.RegistrationCount(), registrations_before);  // only the listener still watched

    ::close(client_fd);
}

// --- the forward loop (read handlers), drop-and-close backpressure, read as the error sink ---
//
// These drive a full connection to Open first, then exercise forwarding in each direction. The c2u Host
// rewrite always rewrites a request's Host to the pinned device authority; bodies and non-authority headers
// forward verbatim. The u2c rewrites are exercised by DialProxyRewriteTest below.


// Stands up an Open connection and exposes both ends: the raw client fd (caller writes requests there), the
// accepted device-side TcpSocket (caller writes responses there), the Connection id, and its client/upstream
// fds (for firing readable edges). The device's listener is kept alive by `device`. Members are optional
// because FakeDevice / TcpSocket are not default-constructible and the helper builds them step by step.
struct OpenConnection {
    std::optional<FakeDevice> device;
    int client_fd = -1;                  // raw blocking client; write requests here
    std::optional<TcpSocket> device_side;  // the device end of the upstream connect; write responses here
    uint64_t id = 0;
    int conn_client_fd = -1;             // the proxy's accepted client fd (FireReadable -> OnClientReadable)
    int conn_upstream_fd = -1;           // the proxy's upstream fd (FireReadable -> OnUpstreamReadable)

    ~OpenConnection() {
        if (client_fd >= 0) {
            ::close(client_fd);
        }
    }
    OpenConnection() = default;
    OpenConnection(OpenConnection&& other) noexcept
        : device{std::move(other.device)},
          client_fd{std::exchange(other.client_fd, -1)},
          device_side{std::move(other.device_side)},
          id{other.id},
          conn_client_fd{other.conn_client_fd},
          conn_upstream_fd{other.conn_upstream_fd} {}
    OpenConnection& operator=(OpenConnection&&) = delete;
    OpenConnection(const OpenConnection&) = delete;
    OpenConnection& operator=(const OpenConnection&) = delete;

    TcpSocket& DeviceSide() { return *device_side; }  // the device end; write/read responses here
};

class DialProxyForwardTest : public DialProxyTest {
protected:
    // Fire a readable edge on a proxy fd only once data has actually landed: the write into the peer fd and
    // the FakeDispatcher edge are decoupled, so loopback delivery can lag the manual fire (a single edge
    // would then Read WouldBlock, forward nothing, and never re-fire). Poll the proxy fd for POLLIN first so
    // the fired edge deterministically sees readable bytes. Returns true once fired; false on timeout.
    bool FireReadableWhenReady(int proxy_fd) {
        pollfd pfd{.fd = proxy_fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 5000) <= 0) {
            return false;
        }
        dispatcher.FireReadable(proxy_fd);
        return true;
    }

    // Mints a discovery listener, connects a raw client, fires the accept, lets the upstream connect settle,
    // fires the connect-completion edge, and accepts the device side — leaving an Open connection. Returns
    // the assembled ends, or asserts/returns a half-built struct on failure (the caller ASSERTs id != 0).
    OpenConnection OpenOne(DialProxy& proxy) {
        OpenConnection oc;
        oc.device = FakeDevice::Make();
        EXPECT_TRUE(oc.device.has_value());
        if (!oc.device) {
            return oc;
        }

        const auto authority = proxy.EnsureDiscoveryListener(oc.device->endpoint);
        EXPECT_TRUE(authority.has_value());
        if (!authority) {
            return oc;
        }
        const int listener_fd = ListenerFd(proxy, oc.device->endpoint);

        oc.client_fd = ConnectRawClient(*authority);
        EXPECT_GE(oc.client_fd, 0);

        const uint64_t id = NextConnectionId(proxy);  // the id AcceptOne will mint (a peek, not consumed)
        auto* conn = AcceptOne(proxy, listener_fd);
        EXPECT_NE(conn, nullptr);
        if (conn == nullptr) {
            return oc;
        }
        oc.conn_client_fd = ConnClientFd(*conn);
        oc.conn_upstream_fd = ConnUpstreamFd(*conn);

        WaitConnectComplete(oc.conn_upstream_fd);
        dispatcher.FireWritable(oc.conn_upstream_fd);
        EXPECT_TRUE(ConnIsOpen(*conn));

        // Accept the device end of the upstream connect (accept readiness can lag the connect on loopback).
        pollfd lpoll{.fd = oc.device->listener.Fd(), .events = POLLIN, .revents = 0};
        EXPECT_GT(::poll(&lpoll, 1, 5000), 0) << "device listener never became acceptable";
        auto device_side = oc.device->listener.Accept();
        EXPECT_TRUE(device_side.has_value());
        if (device_side) {
            oc.device_side.emplace(std::move(*device_side));
        }
        oc.id = id;
        return oc;
    }
};

// 1. A client request's Host is rewritten reflector -> device while the body stays byte-identical. The
//    client reached the reflector listener, so it sends Host: <reflector-authority>; the upstream must see
//    Host: <device-authority>. This is also the two-Send structure proof: the header comes from the framer's
//    rewritten scratch (so it DIFFERS from the input) while the body comes from the zero-copy rx slice (so it
//    is byte-identical) — a mutant merging the two Sends into one raw forward would deliver the input Host.
TEST_F(DialProxyForwardTest, RequestHostRewritesReflectorToDevice) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    // The pinned device authority the rewrite must substitute into the request's Host. The client's own Host
    // is a deliberately wrong value (not the device), proving the rewrite overwrites whatever the client sent
    // rather than passing an already-correct value through.
    const auto device_authority = std::format("{}", oc.device->endpoint);
    const std::string_view body = "hello";
    const std::string source = std::format(
        "POST /apps/Netflix HTTP/1.1\r\nHost: 192.0.2.7:9999\r\nContent-Length: {}\r\n\r\n{}",
        body.size(), body);
    const std::string expected = std::format(
        "POST /apps/Netflix HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
        device_authority, body.size(), body);
    ASSERT_NE(source, expected) << "the rewrite must change the Host line, or this test proves nothing";

    ASSERT_TRUE(WriteAllFd(oc.client_fd, source));

    // Pump readable edges until the whole rewritten request has been forwarded: loopback can deliver the
    // source in fragments, and each edge reads only what is buffered then (one ReserveTail per edge), so
    // re-fire (each time waiting for fresh readable bytes) and accumulate until the device side has it all.
    std::string got;
    while (got.size() < expected.size() && FireReadableWhenReady(oc.conn_client_fd)) {
        got += ReadExactly(oc.DeviceSide(), expected.size() - got.size());
    }
    EXPECT_EQ(got, expected);                                  // Host rewritten to the device authority
    EXPECT_NE(got.find("Host: " + device_authority), std::string::npos);
    EXPECT_EQ(got.find("192.0.2.7:9999"), std::string::npos);  // the client's original Host is gone
    ASSERT_GE(got.size(), body.size());
    EXPECT_EQ(got.substr(got.size() - body.size()), body);     // the body tail is byte-identical to the source
}

// 2. A device response forwards verbatim upstream -> client, header plus a Content-Length body.
TEST_F(DialProxyForwardTest, ResponseForwardsVerbatimUpstreamToClient) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    const std::string_view response =
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(response.data()), response.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    std::string got;
    while (got.size() < response.size() && FireReadableWhenReady(oc.conn_upstream_fd)) {
        got += ReadExactlyFd(oc.client_fd, response.size() - got.size());
    }
    EXPECT_EQ(got, response);
}

// 3. Two messages back-to-back in one read drain in order — proving the Feed loop plus the Send/Send/Consume
//    barrier. A Content-Length response immediately followed by a second complete response.
TEST_F(DialProxyForwardTest, TwoMessagesBackToBackDrainInOrder) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    const std::string_view first = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo";
    // A second bodied response — a normal 200, not a 204: a 204/304 is bodyless regardless of Content-Length
    // (RFC 7230 §3.3.3 rule 1), so framing a body on one would be invalid (see the framer's status handling).
    const std::string_view second = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbeef";
    std::string both;
    both.append(first);
    both.append(second);
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(both.data()), both.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    std::string got;
    while (got.size() < both.size() && FireReadableWhenReady(oc.conn_upstream_fd)) {
        got += ReadExactlyFd(oc.client_fd, both.size() - got.size());
    }
    EXPECT_EQ(got, both);  // both messages, in order, across however many edges loopback fragmented them into
}

// 4. Drop-and-close on send Overflow: stall `to` (the raw client never reads) and push a body large enough
//    to fill its kernel send buffer AND the 8KB StreamBuffer, so the next Send returns Overflow and Forward
//    aborts the connection (closed set, both regs dropped).
TEST_F(DialProxyForwardTest, SendOverflowDropsAndCloses) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // The raw client never reads, so the proxy's client socket stalls: its kernel send buffer plus the raw
    // client's kernel receive buffer fill, then the 8KB client-side StreamBuffer, and the next forwarded
    // Send exceeds MAX_SEND_BUFFER -> Overflow -> Abort. We stream a body far larger than the whole
    // loopback pipe (two ~128KB kernel buffers + 8KB each side), pushing it edge by edge: each edge the
    // proxy reads <=4KB off conn.upstream and forwards to the stalled client. Retry-don't-advance on a
    // device_side Overflow (its own 8KB buffer filling just means the proxy hasn't drained upstream yet) so
    // the full body eventually flows into the client path and forces the abort there.
    constexpr size_t body_len = 4 * 1024 * 1024;
    std::string response = std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body_len);
    response.append(body_len, 'x');

    size_t off = 0;
    bool aborted = false;
    // Feeding the oversized body into the harness device-side socket (8KB cap) Overflows it every round:
    // expected backpressure, not the abort under test (the proxy's CLIENT-side Overflow). Capture stdout so
    // those expected ERROR logs (hundreds of lines) don't flood the output.
    CaptureStdout([&] {
        for (int round = 0; round < 2000000 && !aborted; ++round) {
            if (off < response.size()) {
                const std::span<const std::byte> chunk{
                    reinterpret_cast<const std::byte*>(response.data() + off),
                    std::min<size_t>(64 * 1024, response.size() - off)};
                const SendStatus st = oc.DeviceSide().Send(chunk);
                if (st == SendStatus::Ok) {
                    off += chunk.size();  // accepted (sent now or buffered in device_side's StreamBuffer)
                } else if (st == SendStatus::Error) {
                    break;
                }
                // On Overflow: leave `off` put and retry after an edge frees space. Always try to flush.
                (void)oc.DeviceSide().Flush();
            }
            dispatcher.FireReadable(oc.conn_upstream_fd);  // proxy reads <=4KB off upstream, forwards to client
            aborted = ConnClosed(*conn);
        }
    });

    EXPECT_TRUE(aborted) << "expected a stalled client to drive the forwarded response into send Overflow";
    EXPECT_TRUE(ConnClosed(*conn));
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
}

// 5. Peer EOF tears down (deferred): close the device side, fire the upstream readable edge -> Read returns
//    Closed -> Abort. closed is set and both regs are dropped, but the node lingers (NOT map-emptiness)
//    until the eviction reaper — mirroring ConnectFailureTearsDownTheConnection.
TEST_F(DialProxyForwardTest, UpstreamEofTearsDownDeferred) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    oc.DeviceSide().Close();  // device closes its write half -> the proxy's upstream Read sees EOF

    // The EOF is asynchronous on loopback; poll the upstream fd until readable (POLLIN fires on EOF too) so
    // the fired edge deterministically sees Read -> Closed.
    pollfd pfd{.fd = oc.conn_upstream_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "upstream never became readable after the device closed";

    dispatcher.FireReadable(oc.conn_upstream_fd);

    EXPECT_TRUE(ConnClosed(*conn));                            // marked closed (lingers until the reaper)
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));    // both regs dropped immediately
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
    EXPECT_EQ(ConnectionCount(proxy), 1u);                    // the node still lingers (no reaper fired here)
}

// 6. A header in the 1.5-2KB band (just under MAX_HEADER_BYTES, under the 4KB recv buffer) accumulates
//    across reads and forwards intact — no livelock, no over-cap refusal.
TEST_F(DialProxyForwardTest, LargeHeaderUnderCapForwardsIntact) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    // Build a ~1.8KB request: a real request line + one fat padding header value, terminated normally. The
    // Host (a deliberately wrong authority) is rewritten to the device authority; the fat X-Pad header rides
    // through unchanged, proving a large header accumulates across reads and forwards (rewrite and all) intact.
    const auto device_authority = std::format("{}", oc.device->endpoint);
    std::string pad(1800, 'p');
    const std::string source =
        std::format("GET /apps HTTP/1.1\r\nHost: 192.0.2.7:9999\r\nX-Pad: {}\r\n\r\n", pad);
    const std::string expected =
        std::format("GET /apps HTTP/1.1\r\nHost: {}\r\nX-Pad: {}\r\n\r\n", device_authority, pad);
    ASSERT_LT(source.size(), HttpFraming::MAX_HEADER_BYTES + 256u);  // header block in the target band

    ASSERT_TRUE(WriteAllFd(oc.client_fd, source));

    // The recv buffer is 4KB and the header < 2KB, so one (or a couple, if loopback fragments) edges suffice.
    // Re-fire until the device side has the whole rewritten request, proving accumulation + forward, not a spin.
    std::string got;
    for (int attempt = 0; attempt < 50 && got.size() < expected.size(); ++attempt) {
        dispatcher.FireReadable(oc.conn_client_fd);
        pollfd pfd{.fd = oc.DeviceSide().Fd(), .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 1000) > 0) {
            std::byte buf[512];
            const auto r = oc.DeviceSide().Read(std::span<std::byte>{buf, sizeof(buf)});
            if (r.status == IoStatus::Ok) {
                got.append(reinterpret_cast<const char*>(buf), r.bytes);
            }
        }
    }
    EXPECT_EQ(got, expected);
}

// 6b. A header EXCEEDING MAX_HEADER_BYTES with no terminator is refused (Feed -> nullopt) -> Abort, not spun.
//     The recv buffer (4KB) exceeds the header cap (2KB), so the framer's over-cap refusal fires first.
TEST_F(DialProxyForwardTest, OverCapHeaderAbortsNotSpun) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // A header block past MAX_HEADER_BYTES with no terminating blank line: Feed sees input.size() >
    // MAX_HEADER_BYTES with no "\r\n\r\n" and returns nullopt. Sized under the 4KB recv buffer so a single
    // read holds it all (the over-cap refusal must fire before the recv buffer fills).
    std::string request = "GET / HTTP/1.1\r\nX-Pad: ";
    request.append(HttpFraming::MAX_HEADER_BYTES + 200, 'p');  // still no terminator
    ASSERT_LT(request.size(), DialProxy::MAX_RECV_BUFFER);
    ASSERT_TRUE(WriteAllFd(oc.client_fd, request));

    pollfd pfd{.fd = oc.conn_client_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "client bytes never reached the proxy";
    dispatcher.FireReadable(oc.conn_client_fd);

    EXPECT_TRUE(ConnClosed(*conn));
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
}

// --- the real rewrites — c2u Host -> device, u2c Application-URL/Location -> a minted Rest
// listener (or close-don't-forward on a mint failure), plus the forward-loop coverage gaps. ---


class DialProxyRewriteTest : public DialProxyForwardTest {
protected:
    // Send `response` from the device side and pump upstream-readable edges until the accumulated client
    // bytes satisfy `done` (e.g. "the rewritten message is complete"), or the pump stalls. The rewrite
    // changes the message length, so a byte-count wait would be fragile — pump on a content predicate
    // instead. Returns what the raw client received. Loopback fragments and each edge reads one chunk, so
    // re-fire (waiting for fresh readable bytes) and accumulate.
    std::string ForwardResponseUntil(
        OpenConnection& oc, std::string_view response, const std::function<bool(const std::string&)>& done) {
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(response.data()), response.size()};
        EXPECT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);
        std::string got;
        while (!done(got) && FireReadableWhenReady(oc.conn_upstream_fd)) {
            // Drain whatever this edge forwarded (one chunk, possibly several reads on loopback) without
            // racing a fixed count: read until the proxy->client pipe is momentarily empty.
            while (true) {
                pollfd pfd{.fd = oc.client_fd, .events = POLLIN, .revents = 0};
                if (::poll(&pfd, 1, 100) <= 0) {
                    break;
                }
                char buf[4096];
                const ssize_t n = ::read(oc.client_fd, buf, sizeof(buf));
                if (n <= 0) {
                    break;
                }
                got.append(buf, static_cast<size_t>(n));
            }
        }
        return got;
    }
};

// 2. A description response's Application-URL names the device's OWN REST authority; the u2c rewrite mints a
//    reflector Rest listener for it and rewrites the header to that listener's authority. The client never
//    sees the device's (unroutable) authority.
TEST_F(DialProxyRewriteTest, ApplicationUrlMintsRestListenerAndRewrites) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    ASSERT_EQ(CountRest(proxy), 0u);

    const auto device_rest = DeviceRest(99, 8009);
    const std::string body = "<root/>";
    const std::string response = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nContent-Length: {}\r\n\r\n{}",
        device_rest, body.size(), body);
    // Pump until the body's trailing bytes have arrived (the message is complete) — the rewrite changes the
    // length, so wait on content, not a byte count.
    const std::string got = ForwardResponseUntil(oc, response, [&](const std::string& g) {
        return g.ends_with(body);
    });

    // (a) a new Rest endpoint exists for the device REST authority, its listener watched for accept.
    EXPECT_EQ(CountRest(proxy), 1u);
    EXPECT_TRUE(IsRestEndpoint(proxy, device_rest));
    const int rest_fd = ListenerFd(proxy, device_rest);
    ASSERT_GE(rest_fd, 0);
    EXPECT_TRUE(dispatcher.IsWatching(rest_fd));

    // (b) the client's Application-URL was rewritten to that listener's reflector authority, NOT the device's.
    const auto reflector_rest = ListenerAuthority(proxy, device_rest);
    ASSERT_TRUE(reflector_rest.has_value());
    const auto seen = ExtractUrlAuthority(got, "Application-URL:");
    ASSERT_TRUE(seen.has_value()) << "client never received a parseable Application-URL; got: " << got;
    EXPECT_EQ(*seen, *reflector_rest);                 // reflector authority (source_if-addr:minted-port)
    EXPECT_EQ(seen->addr, IpAddress::LoopbackV4());     // source_if address, not the device's 10.0.0.99
    EXPECT_NE(*seen, device_rest);
    EXPECT_EQ(got.find(std::format("{}", device_rest)), std::string::npos);  // device authority never leaks
    EXPECT_NE(got.find(body), std::string::npos);       // the body rode through intact
}

// 3. A launch 201's Location naming the SAME device REST authority reuses the existing listener: it rewrites
//    to the same reflector authority and mints NO new listener.
TEST_F(DialProxyRewriteTest, LocationReusesExistingRestListener) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    const auto device_rest = DeviceRest(99, 8009);
    const std::string first = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nContent-Length: 0\r\n\r\n", device_rest);
    const auto complete = [](const std::string& g) { return g.ends_with("\r\n\r\n"); };  // CL:0 -> ends at the blank line
    ASSERT_FALSE(ForwardResponseUntil(oc, first, complete).empty());
    ASSERT_EQ(CountRest(proxy), 1u);
    const int rest_fd = ListenerFd(proxy, device_rest);
    const auto reflector_rest = ListenerAuthority(proxy, device_rest);
    ASSERT_TRUE(reflector_rest.has_value());

    // A second response (a launch 201) carrying Location to the same device REST authority.
    const std::string second = std::format(
        "HTTP/1.1 201 Created\r\nLocation: http://{}/apps/Netflix/run\r\nContent-Length: 0\r\n\r\n",
        device_rest);
    const std::string got = ForwardResponseUntil(oc, second, complete);

    EXPECT_EQ(CountRest(proxy), 1u);                       // no new listener minted
    EXPECT_EQ(ListenerFd(proxy, device_rest), rest_fd);    // same listener fd reused
    const auto seen = ExtractUrlAuthority(got, "Location:");
    ASSERT_TRUE(seen.has_value()) << "client never received a parseable Location; got: " << got;
    EXPECT_EQ(*seen, *reflector_rest);                     // same reflector authority as the first rewrite
}

// 4. A single-port device names its description endpoint as its REST authority: the rewrite promotes that
//    existing Discovery endpoint to Rest and reuses its listener — one listener, role now Rest, same authority.
TEST_F(DialProxyRewriteTest, SinglePortDeviceCollapsesBothRolesOntoOneListener) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    // The device's REST authority IS its description endpoint (the one OpenOne used for discovery).
    const auto device_desc = oc.device->endpoint;
    ASSERT_TRUE(HasEndpoint(proxy, device_desc));
    ASSERT_FALSE(IsRestEndpoint(proxy, device_desc));      // currently Discovery
    const int discovery_fd = ListenerFd(proxy, device_desc);
    const auto discovery_authority = ListenerAuthority(proxy, device_desc);
    ASSERT_TRUE(discovery_authority.has_value());
    const size_t endpoints_before = CountRest(proxy);
    ASSERT_EQ(endpoints_before, 0u);

    const std::string response = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nContent-Length: 0\r\n\r\n", device_desc);
    const std::string got = ForwardResponseUntil(oc, response,
        [](const std::string& g) { return g.ends_with("\r\n\r\n"); });

    EXPECT_EQ(CountRest(proxy), 1u);                       // exactly one Rest endpoint now (the promotion)
    EXPECT_TRUE(IsRestEndpoint(proxy, device_desc));       // the Discovery endpoint was promoted, not re-minted
    EXPECT_EQ(ListenerFd(proxy, device_desc), discovery_fd);  // same listener, no second mint
    const auto seen = ExtractUrlAuthority(got, "Application-URL:");
    ASSERT_TRUE(seen.has_value()) << "client never received a parseable Application-URL; got: " << got;
    EXPECT_EQ(*seen, *discovery_authority);                // the same reflector authority handed back
}

// 5. REST-cap exhaustion drops the connection (close-don't-forward): pre-fill the Rest cap, then a response
//    whose Application-URL points at a NEW device REST authority can't mint a listener -> the rewrite Aborts
//    the connection and returns nullopt, Forward bails BEFORE the Send, and the device's real authority is
//    NEVER delivered to the client.
TEST_F(DialProxyRewriteTest, RestCapExhaustionDropsTheConnection) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // Fill the Rest cap with unrelated devices, so a fresh mint for a new device REST authority is refused.
    for (size_t i = 0; i < DialProxy::MAX_REST_LISTENERS; ++i) {
        ASSERT_TRUE(EnsureRest(proxy, DeviceRest(static_cast<uint8_t>(i + 1), 9000)).has_value());
    }
    ASSERT_EQ(CountRest(proxy), DialProxy::MAX_REST_LISTENERS);

    const auto unminted = DeviceRest(200, 8009);  // a NEW device REST authority, not yet an endpoint
    ASSERT_FALSE(HasEndpoint(proxy, unminted));
    const std::string response = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nContent-Length: 0\r\n\r\n", unminted);
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(response.data()), response.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    ASSERT_TRUE(FireReadableWhenReady(oc.conn_upstream_fd));  // the proxy reads the response and tries to mint

    EXPECT_TRUE(ConnClosed(*conn));                           // close-don't-forward: the mint failed -> Abort
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));   // both regs dropped
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
    EXPECT_FALSE(HasEndpoint(proxy, unminted));               // no listener leaked for the unminted device

    // The abort fired before the Send, so NOTHING was forwarded. Make that a deterministic, hard
    // "zero bytes" check rather than a best-effort poll for the authority substring: reap the lingering
    // closed Connection (the eviction sweep erases the node -> RAII closes the proxy's client socket),
    // which lets the raw client see a real EOF. Then drain the raw client to EOF and assert it read
    // exactly zero bytes — a mutant that Sends the header before bailing would leave bytes in flight that
    // this surfaces, whereas a 200ms poll could race them.
    Evict(std::chrono::steady_clock::now());  // reap the closed node -> proxy client socket closes
    ASSERT_EQ(ConnectionCount(proxy), 0u);

    std::string leaked;
    while (true) {
        pollfd pfd{.fd = oc.client_fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 5000) <= 0) {
            break;  // no EOF within the bound: surfaced as a short read below, fails the zero-byte assert
        }
        char buf[512];
        const ssize_t n = ::read(oc.client_fd, buf, sizeof(buf));
        if (n <= 0) {
            break;  // 0 = clean EOF (the expected outcome); <0 = error, also ends the drain
        }
        leaked.append(buf, static_cast<size_t>(n));
    }
    EXPECT_TRUE(leaked.empty())
        << "the proxy forwarded " << leaked.size() << " byte(s) before aborting: " << leaked;
}

// 5b. Two URL headers in ONE response, the SECOND overflowing the Rest cap (partial-rewrite-then-Abort). The
//     Rest cap is pre-filled to exactly one free slot: the first Application-URL mints that last slot (OK,
//     spliced into the framer's scratch), then the second Location to a DIFFERENT device authority can't mint
//     -> Abort() inside Feed -> Forward bails BEFORE the Send. The client must receive NOTHING — neither the
//     successfully-rewritten first header nor either device authority (the whole message is dropped, since the
//     rewrite happens inside the same Feed that builds the single forwardable header block).
TEST_F(DialProxyRewriteTest, SecondUrlHeaderOverflowingTheCapDropsTheWholeResponse) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // Fill the Rest cap to exactly one free slot. OpenOne already minted a Discovery listener for oc's device
    // (not counted in Rest), so fill MAX_REST_LISTENERS - 1 unrelated Rest devices.
    for (size_t i = 0; i < DialProxy::MAX_REST_LISTENERS - 1; ++i) {
        ASSERT_TRUE(EnsureRest(proxy, DeviceRest(static_cast<uint8_t>(i + 1), 9000)).has_value());
    }
    ASSERT_EQ(CountRest(proxy), DialProxy::MAX_REST_LISTENERS - 1);

    const auto first_dev = DeviceRest(150, 8009);   // mints the last free Rest slot -> OK
    const auto second_dev = DeviceRest(151, 8010);  // a DIFFERENT authority -> overflows the cap
    ASSERT_FALSE(HasEndpoint(proxy, first_dev));
    ASSERT_FALSE(HasEndpoint(proxy, second_dev));
    const std::string response = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nLocation: http://{}/run\r\n"
        "Content-Length: 0\r\n\r\n",
        first_dev, second_dev);
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(response.data()), response.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    ASSERT_TRUE(FireReadableWhenReady(oc.conn_upstream_fd));

    EXPECT_TRUE(ConnClosed(*conn));                           // close-don't-forward: the second mint failed -> Abort
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));   // both regs dropped
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));

    // Reap the lingering closed node so the proxy's client socket closes and the raw client sees a real EOF,
    // then drain to EOF and assert ZERO bytes: NOTHING was forwarded — not the rewritten first header, not
    // the first device authority, not the second.
    Evict(std::chrono::steady_clock::now());
    ASSERT_EQ(ConnectionCount(proxy), 0u);

    std::string leaked;
    while (true) {
        pollfd pfd{.fd = oc.client_fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 5000) <= 0) {
            break;
        }
        char buf[512];
        const ssize_t n = ::read(oc.client_fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        leaked.append(buf, static_cast<size_t>(n));
    }
    EXPECT_TRUE(leaked.empty())
        << "the proxy forwarded " << leaked.size() << " byte(s) before aborting: " << leaked;
    // The first device minted its slot before the second overflowed; that listener is a real, watched endpoint
    // (it is not rolled back — only the connection is dropped).
    EXPECT_TRUE(HasEndpoint(proxy, first_dev));
    EXPECT_FALSE(HasEndpoint(proxy, second_dev));  // the overflowing second was never minted
}

// 5c. RewriteRestAuthority's closed-guard (dial_proxy.cpp:260-264): once a PRIOR header in this same message
//     already Aborted the connection, a LATER header must not re-enter EnsureRestListener at all. Pre-mint the
//     first device's REST listener so the response's first Application-URL hits the cheap reuse branch (no
//     Register call) -- that leaves the seam's single Register failure to land on the SECOND header (a fresh
//     device), which Aborts. The THIRD header names a brand-new device that WOULD mint successfully if
//     RewriteRestAuthority re-entered EnsureRestListener for it (the seam is spent by then, and nothing else
//     blocks it) -- so a removed guard leaves a real endpoint for it; the guard in place must not.
TEST_F(DialProxyRewriteTest, ClosedGuardStopsMintingForAHeaderAfterAPriorHeaderAborted) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    const auto first_dev = DeviceRest(170, 8009);
    ASSERT_TRUE(EnsureRest(proxy, first_dev).has_value());  // pre-minted: the response's first header reuses it
    ASSERT_TRUE(HasEndpoint(proxy, first_dev));

    const auto second_dev = DeviceRest(171, 8010);  // fresh device: its mint is the first Register call in Feed
    const auto third_dev = DeviceRest(172, 8011);   // fresh device: would mint fine if the guard didn't stop Feed
    ASSERT_FALSE(HasEndpoint(proxy, second_dev));
    ASSERT_FALSE(HasEndpoint(proxy, third_dev));

    const std::string response = std::format(
        "HTTP/1.1 200 OK\r\nApplication-URL: http://{}/apps\r\nLocation: http://{}/run\r\n"
        "Location: http://{}/run2\r\nContent-Length: 0\r\n\r\n",
        first_dev, second_dev, third_dev);
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(response.data()), response.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    dispatcher.fail_registers_remaining = 1;  // the SECOND header's Register call is the first one Feed makes
    ASSERT_TRUE(FireReadableWhenReady(oc.conn_upstream_fd));

    EXPECT_TRUE(ConnClosed(*conn));                 // the second header's mint failed -> Abort
    EXPECT_TRUE(HasEndpoint(proxy, first_dev));     // the pre-minted, reused listener is untouched
    EXPECT_FALSE(HasEndpoint(proxy, second_dev));   // its failed Register rolled the endpoint back
    EXPECT_FALSE(HasEndpoint(proxy, third_dev));    // the closed-guard stopped Feed before a third mint attempt
}

// 6. Back-pressure DRAIN path (Sync -> Flush): stall the raw client so the proxy's client socket buffers a
//    partial (non-overflowing) tail; Sync must arm write interest on it. Then drain the client and fire the
//    writable edge: Flush drains the tail. A deleted/incorrect Sync(to) would leave the tail unarmed and
//    unflushed.
TEST_F(DialProxyRewriteTest, BackpressureDrainPathFlushesBufferedTail) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // Stream a response (no Host/URL header -> verbatim body) and DON'T read the raw client, so the loopback
    // pipe to it fills and the proxy's client send_buffer_ starts buffering a tail. Push edge by edge until a
    // tail buffers (WantsWrite true) but the connection has NOT overflowed/closed. The buffer is 8KB and each
    // edge forwards <=4KB, so once the pipe is full it buffers within a couple edges, well before Overflow.
    // The body is sized far larger than the loopback pipe (two big kernel buffers + 8KB each side) so the
    // stall is reached long before the body is exhausted, on both Linux and macOS (whose loopback recv
    // buffer is generous).
    constexpr size_t body_len = 16 * 1024 * 1024;
    std::string response = std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body_len);
    response.append(body_len, 'y');

    size_t off = 0;
    bool buffered = false;
    // As in SendOverflowDropsAndCloses, feeding the oversized body Overflows the harness device-side socket
    // every round (expected backpressure, not what's under test). Capture stdout so the expected ERROR logs
    // don't flood the output.
    CaptureStdout([&] {
        for (int round = 0; round < 100000 && !buffered && !ConnClosed(*conn); ++round) {
            if (off < response.size()) {
                const std::span<const std::byte> chunk{
                    reinterpret_cast<const std::byte*>(response.data() + off),
                    std::min<size_t>(64 * 1024, response.size() - off)};
                const SendStatus st = oc.DeviceSide().Send(chunk);
                if (st == SendStatus::Ok) {
                    off += chunk.size();
                } else if (st == SendStatus::Error) {
                    break;
                }
                (void)oc.DeviceSide().Flush();
            }
            dispatcher.FireReadable(oc.conn_upstream_fd);
            buffered = ConnClient(*conn).WantsWrite();
        }
    });

    ASSERT_TRUE(buffered) << "the stalled client never buffered a tail";
    ASSERT_FALSE(ConnClosed(*conn)) << "the connection overflowed before a partial tail could be observed";
    EXPECT_TRUE(ConnClient(*conn).WantsWrite());                  // a tail is buffered
    EXPECT_TRUE(dispatcher.IsWriteArmed(oc.conn_client_fd));      // Sync armed the client's write interest

    // Drain everything the raw client has pending, freeing the pipe, then fire the writable edge: Flush drains
    // the buffered tail and Sync disarms write interest.
    std::string drained;
    while (true) {
        pollfd pfd{.fd = oc.client_fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 200) <= 0) {
            break;
        }
        char buf[64 * 1024];
        const ssize_t n = ::read(oc.client_fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        drained.append(buf, static_cast<size_t>(n));
        if (!ConnClient(*conn).WantsWrite()) {
            break;  // safety: already drained (shouldn't happen before the writable edge fires)
        }
        dispatcher.FireWritable(oc.conn_client_fd);  // each drain frees pipe space; Flush pushes more out
    }
    // One last writable edge after the pipe is fully drained, to flush any final tail.
    dispatcher.FireWritable(oc.conn_client_fd);
    drained += ReadExactlyFd(oc.client_fd, 1);  // pull any straggler the edge just pushed

    EXPECT_FALSE(ConnClient(*conn).WantsWrite());                 // the tail flushed
    EXPECT_FALSE(dispatcher.IsWriteArmed(oc.conn_client_fd));     // Sync disarmed write interest
}

// 7. Multiple complete messages drain on a SINGLE readable edge (no pump loop) — proving the Feed loop drains
//    more than one message per edge. A variant carries an HTTP-looking BODY to prove bodies are relayed
//    opaquely, not re-parsed as the next message.
TEST_F(DialProxyRewriteTest, MultiMessageDrainOnSingleEdge) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);

    // The first body deliberately contains a complete-looking HTTP message; the Content-Length frames it as
    // opaque body, so it must NOT be re-parsed (which would mis-split the stream).
    const std::string_view tricky_body = "HTTP/1.1 200 OK\r\n\r\n";
    const std::string first = std::format(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", tricky_body.size(), tricky_body);
    const std::string_view second_body = "beef";
    // A normal 200, not a 204: a bodyless status (RFC 7230 §3.3.3 rule 1) can't carry a Content-Length body.
    const std::string second = std::format(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", second_body.size(), second_body);
    const std::string both = first + second;

    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(both.data()), both.size()};
    ASSERT_EQ(oc.DeviceSide().Send(bytes), SendStatus::Ok);

    // Poll until BOTH messages are buffered at the proxy fd, so the single edge reads them together.
    for (int attempt = 0; attempt < 200; ++attempt) {
        pollfd pfd{.fd = oc.conn_upstream_fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 50) <= 0) {
            continue;
        }
        int pending = 0;
        if (::ioctl(oc.conn_upstream_fd, FIONREAD, &pending) == 0 &&
            static_cast<size_t>(pending) >= both.size()) {
            break;
        }
    }

    dispatcher.FireReadable(oc.conn_upstream_fd);  // EXACTLY ONCE — no pump loop

    const std::string got = ReadExactlyFd(oc.client_fd, both.size());
    EXPECT_EQ(got, both);  // both messages, in order, off a single edge; the tricky body relayed opaquely
}

// 8. Livelock geometry: an unterminated header of ~3.5KB sits BETWEEN MAX_HEADER_BYTES (2KB) and
//    MAX_RECV_BUFFER (4KB). One edge must Abort — the framer's 2KB over-cap refusal fires before the 4KB recv
//    buffer fills. (OverCapHeaderAbortsNotSpun sizes well under 4KB; this pins the geometry between the caps.)
TEST_F(DialProxyRewriteTest, UnterminatedHeaderBetweenCapsAborts) {
    static_assert(DialProxy::MAX_RECV_BUFFER > HttpFraming::MAX_HEADER_BYTES);
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    // Target ~3.5KB: above the 2KB header cap, below the 4KB recv buffer. No terminating blank line.
    constexpr size_t target = 3 * 1024 + 512;
    static_assert(target > HttpFraming::MAX_HEADER_BYTES && target < DialProxy::MAX_RECV_BUFFER);
    std::string request = "GET / HTTP/1.1\r\nX-Pad: ";
    request.append(target - request.size(), 'p');  // still no "\r\n\r\n"

    ASSERT_TRUE(WriteAllFd(oc.client_fd, request));
    pollfd pfd{.fd = oc.conn_client_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "client bytes never reached the proxy";
    dispatcher.FireReadable(oc.conn_client_fd);  // ONE edge

    EXPECT_TRUE(ConnClosed(*conn));                          // over-cap refusal fired before the recv buffer filled
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
}

// 9. Client-EOF symmetry (the mirror of UpstreamEofTearsDownDeferred): close the raw client, fire the client
//    readable edge -> Read returns Closed -> Abort. closed set, both regs dropped, the node lingers.
TEST_F(DialProxyRewriteTest, ClientEofTearsDownDeferred) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    ::close(oc.client_fd);     // the client closes -> the proxy's client Read sees EOF
    oc.client_fd = -1;         // don't double-close in the destructor

    pollfd pfd{.fd = oc.conn_client_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0) << "client fd never became readable after the client closed";
    dispatcher.FireReadable(oc.conn_client_fd);

    EXPECT_TRUE(ConnClosed(*conn));                            // marked closed (lingers until the reaper)
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_client_fd));    // both regs dropped immediately
    EXPECT_FALSE(dispatcher.IsWatching(oc.conn_upstream_fd));
    EXPECT_EQ(ConnectionCount(proxy), 1u);                    // the node still lingers (no reaper fired here)
}

// --- the eviction timer (reaps closed/timed-out connections and idle listeners). The sweep is
// driven by FireTimers with an explicit `now`, and deadlines/last_active are set via the test seams, so
// every case below is fully deterministic — no wall-clock sleeps. ---

// 1. A connection driven to `closed` (deferred teardown) lingers in connections_ until the sweep reaps it.
//    Its fds were already unwatched at Abort; the sweep just erases the inert node.
TEST_F(DialProxyForwardTest, EvictionReapsClosedConnectionNode) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    oc.DeviceSide().Close();  // peer EOF -> Abort -> closed set, both regs dropped, node lingers
    pollfd pfd{.fd = oc.conn_upstream_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0);
    dispatcher.FireReadable(oc.conn_upstream_fd);
    ASSERT_TRUE(ConnClosed(*conn));
    ASSERT_EQ(ConnectionCount(proxy), 1u);  // the lingering closed node

    Evict(std::chrono::steady_clock::now());

    EXPECT_EQ(ConnectionCount(proxy), 0u);  // the closed node was reaped
}

// 2. A Connecting pair that never completes is reaped once its connect deadline passes.
TEST_F(DialProxyForwardTest, EvictionReapsTimedOutConnectingPair) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);
    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    ASSERT_FALSE(ConnIsOpen(*conn));  // still Connecting: deadline is the connect deadline

    const auto deadline = ConnDeadline(*conn);
    Evict(deadline - std::chrono::milliseconds{1});  // just before: not yet reaped
    EXPECT_EQ(ConnectionCount(proxy), 1u);

    Evict(deadline + std::chrono::milliseconds{1});  // just after: connect timeout reaps it
    EXPECT_EQ(ConnectionCount(proxy), 0u);

    ::close(client_fd);
}

// 3. An Open pair idle past IDLE_TIMEOUT is reaped; a second pair whose deadline was refreshed (a forwarded
//    byte) just before the sweep is NOT — the per-byte idle refresh keeps an active pair alive.
TEST_F(DialProxyForwardTest, EvictionReapsIdleOpenButNotRefreshed) {
    auto proxy = MakeProxy();
    OpenConnection idle = OpenOne(proxy);
    ASSERT_NE(idle.id, 0u);
    OpenConnection active = OpenOne(proxy);
    ASSERT_NE(active.id, 0u);
    auto* idle_conn = FindConnection(proxy, idle.id);
    auto* active_conn = FindConnection(proxy, active.id);
    ASSERT_NE(idle_conn, nullptr);
    ASSERT_NE(active_conn, nullptr);
    ASSERT_TRUE(ConnIsOpen(*idle_conn));
    ASSERT_TRUE(ConnIsOpen(*active_conn));

    // Pin both idle deadlines to a known instant; the active one is "refreshed" to one IDLE_TIMEOUT later.
    const auto base = std::chrono::steady_clock::now();
    SetConnDeadline(*idle_conn, base);
    SetConnDeadline(*active_conn, base + DialProxy::IDLE_TIMEOUT);

    Evict(base + std::chrono::milliseconds{1});  // past the idle deadline, before the refreshed one

    EXPECT_EQ(FindConnection(proxy, idle.id), nullptr);     // idle reaped
    EXPECT_NE(FindConnection(proxy, active.id), nullptr);   // refreshed survives
    EXPECT_EQ(ConnectionCount(proxy), 1u);
}

// 4. Endpoint role grace: an unreferenced Discovery endpoint is reaped after DISCOVERY_ENDPOINT_GRACE; a
//    Rest endpoint survives until the longer REST_ENDPOINT_GRACE; a referenced endpoint (an active
//    Connection to its device) is NOT reaped even when idle past the grace.
TEST_F(DialProxyForwardTest, EvictionReapsIdleListenersByRoleGraceButNotReferenced) {
    auto proxy = MakeProxy();

    // An unreferenced Discovery endpoint (no Connection pinned to it).
    const auto discovery_dev = Device(50);
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(discovery_dev).has_value());
    // An unreferenced Rest endpoint.
    const auto rest_dev = DeviceRest(60, 9000);
    ASSERT_TRUE(EnsureRest(proxy, rest_dev).has_value());
    // A referenced endpoint: OpenOne mints a Discovery listener AND an active Connection pinned to it.
    OpenConnection referenced = OpenOne(proxy);
    ASSERT_NE(referenced.id, 0u);
    const auto referenced_dev = referenced.device->endpoint;

    const auto base = std::chrono::steady_clock::now();
    SetEndpointLastActive(proxy, discovery_dev, base);
    SetEndpointLastActive(proxy, rest_dev, base);
    SetEndpointLastActive(proxy, referenced_dev, base);
    // Keep the referencing connection out of the connection reap (its own deadline far ahead).
    SetConnDeadline(*FindConnection(proxy, referenced.id), base + std::chrono::hours{1});

    // Just past the discovery grace, before the rest grace: only the unreferenced Discovery endpoint goes.
    Evict(base + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_FALSE(HasEndpoint(proxy, discovery_dev));   // Discovery grace elapsed -> reaped
    EXPECT_TRUE(HasEndpoint(proxy, rest_dev));          // Rest grace not yet elapsed -> survives
    EXPECT_TRUE(HasEndpoint(proxy, referenced_dev));    // referenced -> survives regardless of grace

    // Past the rest grace too: the unreferenced Rest endpoint goes; the referenced one still survives because
    // its Connection keeps it alive (idle past grace but referenced).
    Evict(base + DialProxy::REST_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_FALSE(HasEndpoint(proxy, rest_dev));         // Rest grace elapsed -> reaped
    EXPECT_TRUE(HasEndpoint(proxy, referenced_dev));    // still referenced by the live Connection -> survives
}

// ---- last_active refresh: the two production writes that keep an active endpoint out of the grace reap.
// Both are stamped from the LIVE clock (not the Evict `now` seam), so unlike the deadline-based tests above,
// these can't set last_active directly -- they bracket each real write with steady_clock::now() and separate
// mint from refresh with a real (short) sleep, wide enough that an Evict `now` lands strictly between "past
// the original mint's deadline" and "before the refreshed deadline". Deleting either refresh collapses that
// window, so the endpoint is reaped and the test fails. ----

// EnsureListener's reuse-branch refresh (dial_proxy.cpp:67): re-advertising an already-minted device must
// push its last_active forward, or a repeatedly-rediscovered device would still get swept on its ORIGINAL
// mint time.
TEST_F(DialProxyTest, RediscoveryRefreshesLastActivePastTheOriginalGraceDeadline) {
    auto proxy = MakeProxy();
    const auto device = Device(120);

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());  // first mint: try_emplace stamps last_active
    const auto after_first = std::chrono::steady_clock::now();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});  // a real gap the refresh must land past

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());  // re-advertise: the reuse branch's refresh

    // Past the original mint's deadline, but well before (original + the 50ms gap)'s deadline: only the
    // refresh decides whether this endpoint is still alive here.
    Evict(after_first + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{10});

    EXPECT_TRUE(HasEndpoint(proxy, device));  // survives only because re-advertising refreshed last_active
}

// OnAccept's own refresh (dial_proxy.cpp:289), run BEFORE Accept() itself: even a spurious/EAGAIN accept edge
// counts as activity, so a device mid-connect-attempt isn't swept out from under it. Fire the listener's
// readable edge with NO client pending -- Accept() then reports EAGAIN, so no Connection is created and
// active_connections stays 0, isolating this refresh from the (separate) endpoint-reference eviction guard.
TEST_F(DialProxyTest, SpuriousAcceptEdgeRefreshesLastActivePastTheOriginalGraceDeadline) {
    auto proxy = MakeProxy();
    const auto device = Device(121);

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());
    const auto after_first = std::chrono::steady_clock::now();
    const int listener_fd = ListenerFd(proxy, device);
    ASSERT_GE(listener_fd, 0);

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    dispatcher.FireReadable(listener_fd);  // no pending client: OnAccept stamps last_active, then Accept() EAGAINs
    ASSERT_EQ(EndpointActiveConnections(proxy, device), 0u);  // confirms nothing was actually accepted

    Evict(after_first + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{10});

    EXPECT_TRUE(HasEndpoint(proxy, device));  // survives only because the accept edge refreshed last_active
}

// 5. Lazy-start / self-stop: no timer before the first mint; one after; and once everything is reaped the
//    sweep self-stops (TimerCount back to 0).
TEST_F(DialProxyForwardTest, EvictionTimerLazyStartsAndSelfStops) {
    auto proxy = MakeProxy();
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // nothing minted yet -> no timer

    const auto device = Device(70);
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(device).has_value());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);  // the first mint lazy-starts the sweep

    // A second mint does not restart/duplicate the timer.
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(71)).has_value());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);

    // Drive past every grace: both endpoints are unreferenced, so the sweep empties both maps and self-stops.
    Evict(std::chrono::steady_clock::now() + DialProxy::REST_ENDPOINT_GRACE + std::chrono::hours{1});

    EXPECT_EQ(EndpointCount(proxy), 0u);
    EXPECT_EQ(ConnectionCount(proxy), 0u);
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // self-stopped once both maps emptied
}

// ---- Endpoint.active_connections refcount: ctor ++ / dtor --, EvictExpired reaps an endpoint only at 0 ----

// A referenced endpoint past its grace is kept; only when its LAST connection is reaped (count 1->0, in the
// same sweep) does the now-unreferenced endpoint go. Exercises the connection-before-endpoint sweep order.
TEST_F(DialProxyForwardTest, EndpointReapedOnlyAfterItsLastConnectionEndsSameSweep) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    const auto dev = oc.device->endpoint;
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 1u);  // ctor incremented

    const auto base = std::chrono::steady_clock::now();
    SetEndpointLastActive(proxy, dev, base);                 // idle past the grace below
    SetConnDeadline(*conn, base + std::chrono::hours{1});    // keep the connection out of this first reap

    // Past grace but still referenced -> endpoint survives, count stays 1.
    Evict(base + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_TRUE(HasEndpoint(proxy, dev));
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 1u);

    // Expire the connection: in ONE sweep it is reaped (dtor: count 1->0) and the now-unreferenced, past-grace
    // endpoint is reaped after it. A reordered sweep (endpoints before connections) would keep the endpoint.
    SetConnDeadline(*conn, base);
    Evict(base + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_EQ(ConnectionCount(proxy), 0u);
    EXPECT_FALSE(HasEndpoint(proxy, dev));
}

// Two connections on ONE endpoint (count 2): reaping one leaves it referenced (count 1, kept); the endpoint is
// reaped only after the LAST connection ends (count 0).
TEST_F(DialProxyForwardTest, MultiConnectionEndpointReapedAfterTheLast) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const auto dev = device->endpoint;

    const int client1 = ConnectRawClient(*authority);
    ASSERT_GE(client1, 0);
    auto* conn1 = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn1, nullptr);
    const int client2 = ConnectRawClient(*authority);
    ASSERT_GE(client2, 0);
    auto* conn2 = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn2, nullptr);
    ASSERT_NE(conn1, conn2);
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 2u);  // both pinned to the one endpoint

    const auto base = std::chrono::steady_clock::now();
    SetEndpointLastActive(proxy, dev, base);  // idle past grace throughout

    // Reap conn1 only: count 2->1, endpoint still referenced -> kept.
    SetConnDeadline(*conn1, base);
    SetConnDeadline(*conn2, base + std::chrono::hours{1});
    Evict(base + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 1u);
    EXPECT_TRUE(HasEndpoint(proxy, dev));

    // Reap conn2: count 1->0, the now-unreferenced past-grace endpoint goes.
    SetConnDeadline(*conn2, base);
    Evict(base + DialProxy::DISCOVERY_ENDPOINT_GRACE + std::chrono::milliseconds{1});
    EXPECT_FALSE(HasEndpoint(proxy, dev));
    EXPECT_EQ(ConnectionCount(proxy), 0u);

    ::close(client1);
    ::close(client2);
}

// The OnAccept registration-failure rollback runs the just-constructed Connection's dtor, so the ctor's ++ is
// balanced back to 0 — no leaked refcount that would pin the endpoint forever. The id is consumed.
TEST_F(DialProxyForwardTest, AcceptRollbackOnRegisterFailureRestoresRefcount) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const auto dev = device->endpoint;
    const auto id_before = NextConnectionId(proxy);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);
    dispatcher.fail_registers_remaining = 1;  // fail the client-fd Register inside OnAccept -> rollback
    for (int i = 0; i < 100 && NextConnectionId(proxy) == id_before; ++i) {
        dispatcher.FireReadable(listener_fd);
    }

    EXPECT_EQ(NextConnectionId(proxy), id_before + 1);             // exactly one accept reached construction
    EXPECT_EQ(ConnectionCount(proxy), 0u);                         // ...and was rolled back
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 0u);          // ctor ++ then dtor -- on the rollback erase
    EXPECT_TRUE(HasEndpoint(proxy, dev));                          // the listener endpoint is untouched
    ::close(client_fd);
}

// Abort (deferred teardown) does NOT release the refcount — the count drops only when the lingering node is
// actually reaped (its dtor runs). So an endpoint with an Aborted-but-not-yet-reaped connection stays pinned.
TEST_F(DialProxyForwardTest, AbortDefersRefcountReleaseUntilReap) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    const auto dev = oc.device->endpoint;
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 1u);

    // Peer EOF -> Forward Aborts: closed set, both regs dropped, node lingers — but refcount NOT yet released.
    oc.DeviceSide().Close();
    pollfd pfd{.fd = oc.conn_upstream_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0);
    dispatcher.FireReadable(oc.conn_upstream_fd);
    ASSERT_TRUE(ConnClosed(*conn));
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 1u);  // Abort did not decrement

    // The reap (well within the endpoint's grace, so the endpoint itself stays) runs the dtor -> count 0.
    Evict(std::chrono::steady_clock::now());
    EXPECT_EQ(ConnectionCount(proxy), 0u);
    EXPECT_TRUE(HasEndpoint(proxy, dev));                  // endpoint within grace -> still present
    EXPECT_EQ(EndpointActiveConnections(proxy, dev), 0u);  // released on destruction, not on close
}

// ---- Error-path rollbacks: a mint/accept that fails partway leaks no endpoint, connection, fd, or refcount ----

// When TcpSocket::Listen fails (the source bind address is not local), EnsureListener returns nullopt and
// inserts nothing — no endpoint, no registration, and the eviction timer (a later hook) never starts.
TEST_F(DialProxyTest, ListenFailureLeavesNothingBehind) {
    auto proxy = MakeProxy();
    source_if.SetV4(IpAddress::FromString("192.0.2.1"));  // TEST-NET-1: not a local addr -> bind fails
    const auto dev = Device(80);

    const auto authority = proxy.EnsureDiscoveryListener(dev);

    EXPECT_FALSE(authority.has_value());
    EXPECT_FALSE(HasEndpoint(proxy, dev));
    EXPECT_EQ(EndpointCount(proxy), 0u);
    EXPECT_EQ(dispatcher.RegistrationCount(), 0u);
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // the timer-start hook sits past the failure -> not reached
}

// When the listener's accept Register fails, EnsureListener erases the just-emplaced Endpoint (no leak),
// returns nullopt, leaves no fd watched, and does not start the eviction timer.
TEST_F(DialProxyTest, ListenerRegisterFailureRollsBackTheEndpoint) {
    auto proxy = MakeProxy();
    dispatcher.fail_registers_remaining = 1;  // fail the listener's accept Register
    const auto dev = Device(81);

    const auto authority = proxy.EnsureDiscoveryListener(dev);

    EXPECT_FALSE(authority.has_value());
    EXPECT_FALSE(HasEndpoint(proxy, dev));    // the emplaced endpoint was erased on the rollback
    EXPECT_EQ(EndpointCount(proxy), 0u);
    EXPECT_EQ(dispatcher.RegistrationCount(), 0u);
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

// When the upstream connect cannot even start (its bind source is not local), OnAccept logs and drops the
// accept before constructing a Connection: no Connection, the id is not consumed, the endpoint untouched.
TEST_F(DialProxyForwardTest, UpstreamConnectStartFailureDropsTheAccept) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    target_if.SetV4(IpAddress::FromString("192.0.2.1"));  // unbindable connect source -> Connect nullopt
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());  // the listener (source_if) is fine; only the upstream bind fails
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const auto id_before = NextConnectionId(proxy);

    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);
    // Fire the accept until the dropped client's raw peer sees the close (proving the accept+Connect-fail ran).
    pollfd cpoll{.fd = client_fd, .events = POLLIN, .revents = 0};
    bool dropped = false;
    for (int i = 0; i < 100 && !dropped; ++i) {
        dispatcher.FireReadable(listener_fd);
        dropped = ::poll(&cpoll, 1, 50) > 0;
    }

    EXPECT_TRUE(dropped) << "the accepted client should be dropped on the upstream Connect-start failure";
    EXPECT_EQ(ConnectionCount(proxy), 0u);                              // no Connection emplaced
    EXPECT_EQ(NextConnectionId(proxy), id_before);                      // Connect failed before the id consume
    EXPECT_EQ(EndpointActiveConnections(proxy, device->endpoint), 0u);   // no refcount touched
    ::close(client_fd);
}

// ---- Forward / writable edges: idle-deadline gating, the connect->idle transition, Sync/closed guards ----

// A forwarded byte on an Open connection pushes the idle deadline forward (now + IDLE_TIMEOUT).
TEST_F(DialProxyForwardTest, ForwardRefreshesIdleDeadlineOnAnOpenConnection) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(ConnIsOpen(*conn));

    const auto stale = std::chrono::steady_clock::now() - std::chrono::hours{1};
    SetConnDeadline(*conn, stale);

    const std::string_view req = "GET / HTTP/1.1\r\n";  // a partial header: read happens (bytes > 0)
    ASSERT_EQ(::write(oc.client_fd, req.data(), req.size()), static_cast<ssize_t>(req.size()));
    ASSERT_TRUE(FireReadableWhenReady(oc.conn_client_fd));

    EXPECT_GT(ConnDeadline(*conn), stale);  // the read refreshed the idle deadline
}

// A client that speaks first (while the upstream is still connecting) is read and buffered, but the connect
// deadline must NOT be pushed out to the longer idle grace (the refresh is gated on !IsConnecting).
TEST_F(DialProxyForwardTest, ForwardDoesNotRefreshDeadlineWhileUpstreamConnecting) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);
    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    ASSERT_FALSE(ConnIsOpen(*conn));  // still Connecting: deadline is the connect deadline
    const auto connect_deadline = ConnDeadline(*conn);

    const std::string_view req = "GET / HTTP/1.1\r\n";
    ASSERT_EQ(::write(client_fd, req.data(), req.size()), static_cast<ssize_t>(req.size()));
    ASSERT_TRUE(FireReadableWhenReady(ConnClientFd(*conn)));

    EXPECT_FALSE(ConnIsOpen(*conn));                   // still connecting
    EXPECT_EQ(ConnDeadline(*conn), connect_deadline);  // connect deadline preserved (no idle push-out)
    ::close(client_fd);
}

// On connect completion, OnUpstreamWritable -> FinishConnect -> Drain moves the deadline off the (shorter)
// connect deadline onto the idle deadline (now + IDLE_TIMEOUT).
TEST_F(DialProxyForwardTest, ConnectCompletionMovesDeadlineFromConnectToIdle) {
    auto device = FakeDevice::Make();
    ASSERT_TRUE(device.has_value());
    auto proxy = MakeProxy();
    const auto authority = proxy.EnsureDiscoveryListener(device->endpoint);
    ASSERT_TRUE(authority.has_value());
    const int listener_fd = ListenerFd(proxy, device->endpoint);
    const int client_fd = ConnectRawClient(*authority);
    ASSERT_GE(client_fd, 0);
    auto* conn = AcceptOne(proxy, listener_fd);
    ASSERT_NE(conn, nullptr);
    ASSERT_FALSE(ConnIsOpen(*conn));
    const auto connect_deadline = ConnDeadline(*conn);

    WaitConnectComplete(ConnUpstreamFd(*conn));
    const auto before = std::chrono::steady_clock::now();
    dispatcher.FireWritable(ConnUpstreamFd(*conn));  // FinishConnect -> Open -> Drain sets the idle deadline

    ASSERT_TRUE(ConnIsOpen(*conn));
    EXPECT_GT(ConnDeadline(*conn), connect_deadline);                          // moved off the connect deadline
    EXPECT_GE(ConnDeadline(*conn), before + DialProxy::IDLE_TIMEOUT - std::chrono::seconds{1});  // ~now+IDLE
    ::close(client_fd);
}

// When Sync's SetWriteInterest fails (the fd is no longer serviceable), the connection is Aborted, like any
// other I/O failure on the path.
TEST_F(DialProxyForwardTest, SyncFailureAbortsTheConnection) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);
    ASSERT_FALSE(ConnClosed(*conn));

    dispatcher.fail_set_write_interest_remaining = 1;  // fail the Sync(to) at the end of Forward
    const std::string_view req = "GET / HTTP/1.1\r\n";
    ASSERT_EQ(::write(oc.client_fd, req.data(), req.size()), static_cast<ssize_t>(req.size()));
    ASSERT_TRUE(FireReadableWhenReady(oc.conn_client_fd));

    EXPECT_TRUE(ConnClosed(*conn));  // Sync's SetWriteInterest false -> Abort
}

// Both writable handlers bail at the `closed` guard: no Drain, so no deadline refresh and no FinishConnect.
TEST_F(DialProxyForwardTest, WritableHandlersAreNoOpsOnAClosedConnection) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    auto* conn = FindConnection(proxy, oc.id);
    ASSERT_NE(conn, nullptr);

    conn->Abort();  // closed = true, regs dropped, node lingers
    ASSERT_TRUE(ConnClosed(*conn));
    const auto sentinel = std::chrono::steady_clock::now() + std::chrono::hours{1};
    SetConnDeadline(*conn, sentinel);  // Drain would move this; the guard must not let it run

    conn->OnClientWritable(ConnClientFd(*conn));
    conn->OnUpstreamWritable(ConnUpstreamFd(*conn));

    EXPECT_TRUE(ConnClosed(*conn));
    EXPECT_EQ(ConnDeadline(*conn), sentinel);  // unchanged -> Drain never ran
}

// ---- Eviction timer lifecycle: keep-running, restart-after-stop, multi-reap in one sweep ----

// The sweep self-stops only when BOTH maps are empty: reaping every connection while an endpoint remains
// (within its grace) leaves the timer running.
TEST_F(DialProxyForwardTest, EvictionTimerKeepsRunningWhileAnEndpointRemains) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    const auto dev = oc.device->endpoint;
    ASSERT_EQ(dispatcher.TimerCount(), 1u);

    const auto base = std::chrono::steady_clock::now();
    SetEndpointLastActive(proxy, dev, base + std::chrono::hours{1});  // endpoint well within grace
    SetConnDeadline(*FindConnection(proxy, oc.id), base);             // expire only the connection

    Evict(base + std::chrono::milliseconds{1});

    EXPECT_EQ(ConnectionCount(proxy), 0u);    // connection reaped
    EXPECT_EQ(EndpointCount(proxy), 1u);       // endpoint kept (within grace, now unreferenced)
    EXPECT_EQ(dispatcher.TimerCount(), 1u);    // still running: endpoints_ non-empty
}

// After a self-stop (both maps empty), a fresh mint lazy-restarts the sweep.
TEST_F(DialProxyTest, EvictionTimerRestartsOnAMintAfterSelfStop) {
    auto proxy = MakeProxy();
    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(90)).has_value());
    ASSERT_EQ(dispatcher.TimerCount(), 1u);

    Evict(std::chrono::steady_clock::now() + DialProxy::REST_ENDPOINT_GRACE + std::chrono::hours{1});
    ASSERT_EQ(EndpointCount(proxy), 0u);
    ASSERT_EQ(dispatcher.TimerCount(), 0u);  // self-stopped

    ASSERT_TRUE(proxy.EnsureDiscoveryListener(Device(91)).has_value());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);  // a new mint restarts it
}

// One sweep reaps a mix at once: a closed (deferred-teardown) node, an idle-expired Open pair, and a
// connect-expired Connecting pair.
TEST_F(DialProxyForwardTest, EvictionReapsAClosedIdleAndConnectingNodeInOneSweep) {
    auto proxy = MakeProxy();
    OpenConnection closed_oc = OpenOne(proxy);
    ASSERT_NE(closed_oc.id, 0u);
    OpenConnection idle_oc = OpenOne(proxy);
    ASSERT_NE(idle_oc.id, 0u);

    auto connecting_device = FakeDevice::Make();

    ASSERT_TRUE(connecting_device.has_value());
    const auto auth = proxy.EnsureDiscoveryListener(connecting_device->endpoint);
    ASSERT_TRUE(auth.has_value());
    const int conn_client = ConnectRawClient(*auth);
    ASSERT_GE(conn_client, 0);
    auto* connecting = AcceptOne(proxy, ListenerFd(proxy, connecting_device->endpoint));
    ASSERT_NE(connecting, nullptr);
    ASSERT_FALSE(ConnIsOpen(*connecting));
    ASSERT_EQ(ConnectionCount(proxy), 3u);

    // Close the first (peer EOF -> Abort -> lingering closed node).
    closed_oc.DeviceSide().Close();
    pollfd pfd{.fd = closed_oc.conn_upstream_fd, .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, 5000), 0);
    dispatcher.FireReadable(closed_oc.conn_upstream_fd);
    ASSERT_TRUE(ConnClosed(*FindConnection(proxy, closed_oc.id)));

    // Expire the other two by deadline (idle and connect).
    const auto base = std::chrono::steady_clock::now();
    SetConnDeadline(*FindConnection(proxy, idle_oc.id), base);
    SetConnDeadline(*connecting, base);

    Evict(base + std::chrono::milliseconds{1});
    EXPECT_EQ(ConnectionCount(proxy), 0u);  // all three reaped in the one sweep

    ::close(conn_client);
}

// A source-address change drops not only the stale listeners but the live connections pinned to them: a
// Connection borrows Endpoint&, so it must be erased before the endpoint it references — and its client
// reached an authority that no longer routes anyway.
TEST_F(DialProxyForwardTest, OnInterfaceChangedDropsConnectionsPinnedToAStaleListener) {
    auto proxy = MakeProxy();
    OpenConnection oc = OpenOne(proxy);
    ASSERT_NE(oc.id, 0u);
    ASSERT_EQ(ConnectionCount(proxy), 1u);
    ASSERT_EQ(EndpointCount(proxy), 1u);

    source_if.SetV4(std::nullopt);  // the listener's bind address is gone -> endpoint and its connection stale
    proxy.OnInterfaceChanged();

    EXPECT_EQ(ConnectionCount(proxy), 0u);   // the pinned connection went first, with no dangling Endpoint&
    EXPECT_EQ(EndpointCount(proxy), 0u);
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // both maps empty -> reaper stopped
}

} // namespace reflector
