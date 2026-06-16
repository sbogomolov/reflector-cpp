#include "reflector/application.h"

#include "reflector/config/config.h"
#include "reflector/error.h"
#include "reflector/interface.h"
#include "reflector/link_socket.h"
#include "reflector/mac_address.h"
#include "mocks/fake_address_monitor.h"
#include "mocks/fake_dispatcher.h"
#include "mocks/fake_interface.h"
#include "mocks/fake_link_socket.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace reflector {

// Exercises Application's wiring entirely against fakes — a fake dispatcher, address monitor, and
// per-interface interface/socket factories injected via ForTesting — so dedup, fail-fast, and
// address-refresh routing are covered with no real epoll/netlink/capture sockets and no privilege.
class ApplicationTest : public ::testing::Test {
protected:
    static size_t SocketCount(const Application& app) { return app.SocketCount(); }
    static size_t ReflectorCount(const Application& app) { return app.ReflectorCount(); }
    // The signal-wakeup self-pipe read fd (friendship isn't inherited, so the TEST_F body reaches the
    // private member through this fixture accessor, like the counts above).
    static int WakeupReadFd(const Application& app) { return app.wakeup_read_.Get(); }

    // Per-interface settings the factories stamp onto the Interface and socket when first
    // created. Interfaces with no entry get the defaults (valid, can send both families,
    // auto-assigned index).
    struct SocketConfig {
        bool valid = true;
        bool interface_valid = true;   // false: the Interface resolves as invalid (index 0)
        bool can_send_v4 = true;
        bool can_send_v6 = true;
        unsigned interface_index = 0;  // 0 = auto-assign a unique nonzero index
    };

    // Sets how the socket for `interface` will behave; must be called before Configure creates it.
    void ConfigureSocket(std::string_view interface, const SocketConfig& config) {
        socket_configs_.insert_or_assign(std::string{interface}, config);
    }

    // The fake socket the factory created for `interface`, or nullptr if it never asked for one.
    [[nodiscard]] FakeLinkSocket* Socket(std::string_view interface) {
        const auto it = created_sockets_.find(std::string{interface});
        return it == created_sockets_.end() ? nullptr : it->second;
    }

    // The fake Interface the factory created for `interface`, or nullptr if it never asked.
    [[nodiscard]] FakeInterface* Iface(std::string_view interface) {
        const auto it = created_interfaces_.find(std::string{interface});
        return it == created_interfaces_.end() ? nullptr : it->second;
    }

    // Builds an Application through the ForTesting seam with a fake dispatcher and address monitor
    // (both recorded for the test to drive/inspect) and the recording socket factory. Set
    // monitor_starts_ and any ConfigureSocket() entries beforehand.
    Application MakeApp() {
        auto dispatcher = std::make_unique<FakeDispatcher>();
        dispatcher_ = dispatcher.get();
        auto monitor = std::make_unique<FakeAddressMonitor>();
        monitor->start_succeeds = monitor_starts_;
        monitor_ = monitor.get();
        return Application::ForTesting(std::move(dispatcher), std::move(monitor),
            MakeInterfaceFactory(), MakeFactory());
    }

    static WolConfig MakeWolConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, std::vector<uint16_t> ports) {
        return WolConfig{
            .name = std::string{name},
            .mac = *MacAddress::FromString("00:11:22:33:44:55"),
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .ports = std::move(ports),
            .address_family = AddressFamily::IPv4,
        };
    }

    static MdnsConfig MakeMdnsConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, AddressFamily family = AddressFamily::IPv4) {
        return MdnsConfig{
            .name = std::string{name},
            .mac = std::nullopt,
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .address_family = family,
        };
    }

    static SsdpConfig MakeSsdpConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, AddressFamily family = AddressFamily::IPv4) {
        return SsdpConfig{
            .name = std::string{name},
            .mac = std::nullopt,
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .address_family = family,
        };
    }

    FakeDispatcher* dispatcher_ = nullptr;
    FakeAddressMonitor* monitor_ = nullptr;
    bool monitor_starts_ = true;
    int factory_calls_ = 0;

private:
    Application::SocketFactory MakeFactory() {
        return [this](const Interface& interface) -> std::unique_ptr<LinkSocket> {
            ++factory_calls_;
            const std::string name{interface.Name()};
            auto socket = std::make_unique<FakeLinkSocket>(interface);
            const auto it = socket_configs_.find(name);
            const SocketConfig config = it == socket_configs_.end() ? SocketConfig{} : it->second;
            socket->valid = config.valid;
            socket->fd = next_fd_++;
            created_sockets_.insert_or_assign(name, socket.get());
            return socket;
        };
    }

    Application::InterfaceFactory MakeInterfaceFactory() {
        return [this](std::string_view name) -> std::unique_ptr<Interface> {
            const auto it = socket_configs_.find(std::string{name});
            const SocketConfig config = it == socket_configs_.end() ? SocketConfig{} : it->second;
            const unsigned index = !config.interface_valid ? 0
                : config.interface_index != 0               ? config.interface_index
                                                            : next_interface_index_++;
            auto iface = std::make_unique<FakeInterface>(name, index);
            iface->SetHasSource(IpAddress::Family::V4, config.can_send_v4);
            iface->SetHasSource(IpAddress::Family::V6, config.can_send_v6);
            created_interfaces_.insert_or_assign(std::string{name}, iface.get());
            return iface;
        };
    }

    std::unordered_map<std::string, SocketConfig> socket_configs_;
    std::unordered_map<std::string, FakeLinkSocket*> created_sockets_;
    std::unordered_map<std::string, FakeInterface*> created_interfaces_;
    int next_fd_ = 100;
    // Far from the explicit indexes tests pick (e.g. 5, 9), so an auto-assigned index never
    // collides with a FireChange target.
    unsigned next_interface_index_ = 100;
};

TEST_F(ApplicationTest, SharesOneSocketPerInterfaceAcrossConfigs) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {7}))
        .Add(MakeWolConfig("console", "src", "dst", {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // "src" and "dst" are each created once and shared by both reflectors.
    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 2);
    // The shared source fd is watched exactly once, however many reflectors register on it.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 1);
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("src")->fd));
}

TEST_F(ApplicationTest, StartsMemoryReportTimerWhenDebugMemoryEnabled) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {7}))
        .DebugMemory(true)
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // A WoL-only config starts no timers of its own, so the periodic memory report is the only one.
    EXPECT_EQ(dispatcher_->TimerCount(), 1u);
    // Firing it exercises the ReportMemory callback (reads /proc + mallinfo2 on glibc); must not crash.
    dispatcher_->FireTimers(std::chrono::steady_clock::now());
}

TEST_F(ApplicationTest, NoMemoryReportTimerByDefault) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {7}))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    EXPECT_EQ(dispatcher_->TimerCount(), 0u);
}

TEST_F(ApplicationTest, CreatesDistinctSocketsForDistinctInterfaces) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src-a", "dst", {7}))
        .Add(MakeWolConfig("console", "src-b", "dst", {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    EXPECT_EQ(factory_calls_, 3); // src-a, src-b, and the shared dst
    EXPECT_EQ(SocketCount(app), 3);
    EXPECT_EQ(ReflectorCount(app), 2);
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2); // two distinct source fds watched
}

TEST_F(ApplicationTest, FailsWhenSourceSocketInvalid) {
    ConfigureSocket("bad-src", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "bad-src", "dst", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("bad-src"), std::string::npos) << output; // the log names the source interface
}

TEST_F(ApplicationTest, FailsWhenTargetSocketInvalid) {
    ConfigureSocket("bad-dst", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "bad-dst", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("bad-dst"), std::string::npos) << output; // the log names the target interface
}

TEST_F(ApplicationTest, FailsWhenReflectorSetupFails) {
    // The target socket is valid but can't originate IPv4, so the (IPv4) reflector fails to
    // initialize even though both socket checks pass.
    ConfigureSocket("dst", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}

TEST_F(ApplicationTest, StopsAtFirstFailure) {
    ConfigureSocket("dst-bad", {.can_send_v4 = false}); // the second config's reflector will fail
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("first", "src1", "dst1", {7}))
        .Add(MakeWolConfig("second", "src2", "dst-bad", {8}))
        .Add(MakeWolConfig("third", "src3", "dst3", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;        // a failed Configure leaves nothing wired
    EXPECT_EQ(Socket("src3"), nullptr);                 // the third config was never reached
}

TEST_F(ApplicationTest, WiresMdnsReflectorOnBothInterfaces) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeMdnsConfig("cast", "src", "dst"))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 1);
    // mDNS captures on both interfaces, so each socket's fd is watched once.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("src")->fd));
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("dst")->fd));
}

TEST_F(ApplicationTest, SharesSocketsBetweenWolAndMdns) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Add(MakeMdnsConfig("cast", "src", "dst"))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // Both protocols reuse the same per-interface sockets.
    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 2);
    // WoL watches "src"; mDNS additionally watches "dst" — two distinct fds total.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
}

TEST_F(ApplicationTest, FailsWhenMdnsSourceSocketInvalid) {
    ConfigureSocket("bad-src", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeMdnsConfig("cast", "bad-src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("mdns"), std::string::npos) << output;     // the log names the protocol
    EXPECT_NE(output.find("bad-src"), std::string::npos) << output;  // and the source interface
}

TEST_F(ApplicationTest, FailsWhenMdnsTargetSocketInvalid) {
    ConfigureSocket("bad-dst", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeMdnsConfig("cast", "src", "bad-dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("bad-dst"), std::string::npos) << output;  // the log names the target interface
}

TEST_F(ApplicationTest, FailsWhenMdnsReflectorSetupFails) {
    // mDNS needs the family sendable on both interfaces; the IPv4 config can't be reflected when
    // the target can't originate IPv4, so the reflector fails to initialize.
    ConfigureSocket("dst", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeMdnsConfig("cast", "src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}

TEST_F(ApplicationTest, ClearsWolReflectorWhenLaterMdnsFails) {
    // WoL is configured before mDNS, so the WoL reflector wires successfully before the mDNS entry
    // fails. Configure is transactional: that earlier success is rolled back, leaving nothing wired.
    // A source that can't originate IPv4 breaks mDNS (which reflects in both directions) but not WoL
    // (whose source only captures).
    ConfigureSocket("src", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Add(MakeMdnsConfig("cast", "src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output; // the WoL reflector wired earlier is rolled back
}

TEST_F(ApplicationTest, WiresSsdpReflectorOnBothInterfaces) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "src", "dst"))  // IPv4: one group
        .Build();

    ASSERT_TRUE(app.Configure(config));

    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 1);
    // SSDP captures on both interfaces, so each socket's fd is watched once (the dispatcher counts
    // watched fds, not the per-group registrations behind them).
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("src")->fd));
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("dst")->fd));
}

TEST_F(ApplicationTest, SharesSocketsAcrossAllProtocols) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Add(MakeMdnsConfig("bridge", "src", "dst"))
        .Add(MakeSsdpConfig("cast", "src", "dst"))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // All three protocols reuse the same per-interface sockets.
    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 3);
    // "src" and "dst" are each watched once however many reflectors register on them.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
}

TEST_F(ApplicationTest, FailsWhenSsdpSourceSocketInvalid) {
    ConfigureSocket("bad-src", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "bad-src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("ssdp"), std::string::npos) << output;     // the log names the protocol
    EXPECT_NE(output.find("bad-src"), std::string::npos) << output;  // and the source interface
}

TEST_F(ApplicationTest, FailsWhenSsdpTargetSocketInvalid) {
    ConfigureSocket("bad-dst", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "src", "bad-dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("bad-dst"), std::string::npos) << output;  // the log names the target interface
}

TEST_F(ApplicationTest, FailsWhenSsdpReflectorSetupFails) {
    // SSDP needs the family sendable on both interfaces; the IPv4 config can't be reflected when the
    // target can't originate IPv4, so the reflector fails to initialize.
    ConfigureSocket("dst", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("cast", "src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}

TEST_F(ApplicationTest, ClearsEarlierReflectorsWhenSsdpFails) {
    // SSDP is configured last; a source that can't originate IPv4 breaks SSDP (which reflects in
    // both directions) but not the WoL reflector wired before it. Configure is transactional, so the
    // earlier success is rolled back, leaving nothing wired.
    ConfigureSocket("src", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Add(MakeSsdpConfig("cast", "src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output; // the WoL reflector wired earlier is rolled back
}

TEST_F(ApplicationTest, SubscribesToTheAddressMonitor) {
    auto app = MakeApp();

    // Application binds its OnInterfaceChanged callback to the monitor at construction.
    EXPECT_TRUE(monitor_->Started());
}

TEST_F(ApplicationTest, WarnsButProceedsWhenMonitorCannotStart) {
    monitor_starts_ = false; // the monitor's Start() will report failure

    const std::string output = CaptureStdout([&] {
        auto app = MakeApp();
        // The daemon carries on without address refresh: configuration still succeeds.
        EXPECT_TRUE(app.Configure(TestConfigBuilder{}
            .Add(MakeWolConfig("tv", "src", "dst", {9}))
            .Build()));
    });

    EXPECT_NE(output.find("Address monitor unavailable"), std::string::npos) << output;
}

TEST_F(ApplicationTest, RefreshesOnlyTheChangedInterface) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeWolConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(5);

    EXPECT_EQ(Iface("src")->refresh_count, 1u);
    EXPECT_EQ(Iface("dst")->refresh_count, 0u);
}

// After refreshing interfaces, Application notifies every reflector so it can react to the change.
// Verified end-to-end: a WoL reflector whose target gains a v6 address logs the capability notice
// only once the monitor fires (its Observe runs in OnInterfaceChanged, not on packet traffic).
TEST_F(ApplicationTest, NotifiesReflectorsWhenAnInterfaceChanges) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.can_send_v6 = false, .interface_index = 9});  // dst has no v6 at startup
    auto app = MakeApp();
    auto wol = MakeWolConfig("tv", "src", "dst", {9});
    wol.address_family = AddressFamily::Default;  // uses both families, requires only v4
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(wol).Build()));

    Iface("dst")->SetHasSource(IpAddress::Family::V6, true);  // a v6 address appears on the target
    const std::string output = CaptureStdout([&] { monitor_->FireChange(9); });

    EXPECT_NE(output.find(std::format("Starting {} reflection", IpAddress::Family::V6)),
        std::string::npos) << output;
}

TEST_F(ApplicationTest, RefreshesAllInterfacesOnOverflowSignal) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeWolConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(0); // 0 is the "refresh everything" overflow signal

    EXPECT_EQ(Iface("src")->refresh_count, 1u);
    EXPECT_EQ(Iface("dst")->refresh_count, 1u);
}

TEST_F(ApplicationTest, RefreshesNothingForUnknownInterface) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeWolConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(7); // no interface has index 7

    EXPECT_EQ(Iface("src")->refresh_count, 0u);
    EXPECT_EQ(Iface("dst")->refresh_count, 0u);
}

TEST_F(ApplicationTest, FailsConfigureWhenTheInterfaceIsInvalid) {
    ConfigureSocket("src", {.interface_valid = false});
    auto app = MakeApp();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(TestConfigBuilder{}
            .Add(MakeWolConfig("tv", "src", "dst", {9}))
            .Build()));
    });

    // The socket factory never runs for an invalid interface.
    EXPECT_EQ(factory_calls_, 0) << output;
}

TEST_F(ApplicationTest, RunDelegatesToTheDispatcher) {
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeWolConfig("tv", "src", "dst", {9})).Build()));
    volatile std::sig_atomic_t stop_requested = 1; // already stopped, so the fake returns at once

    app.Run(stop_requested);

    EXPECT_EQ(dispatcher_->run_calls, 1u);
}

// PrepareSignalWakeup registers a self-pipe read end with the dispatcher (so a signal handler can break the
// poll by writing the returned fd), and OnWakeup drains it. Opt-in -- only this test and production main
// call it, so the other cases' dispatcher-registration counts stay unperturbed.
TEST_F(ApplicationTest, SignalWakeupRegistersAndDrains) {
    auto app = MakeApp();
    const size_t before = dispatcher_->RegistrationCount();

    const int write_fd = app.PrepareSignalWakeup();
    ASSERT_GE(write_fd, 0);
    EXPECT_EQ(dispatcher_->RegistrationCount(), before + 1);  // the pipe's read end is now watched

    const int read_fd = WakeupReadFd(app);
    ASSERT_TRUE(dispatcher_->IsWatching(read_fd));

    // Simulate the handler: write the wakeup byte, then fire the readable edge the reactor would deliver.
    const unsigned char byte = 1;
    ASSERT_EQ(::write(write_fd, &byte, 1), 1);
    dispatcher_->FireReadable(read_fd);  // OnWakeup drains the pipe

    // Drained: the read end now blocks (EAGAIN), proving OnWakeup consumed the byte rather than leaving the
    // level-triggered fd readable (which would spin the real reactor after the loop's stop check).
    unsigned char drained = 0;
    EXPECT_EQ(::read(read_fd, &drained, 1), -1);
    EXPECT_TRUE(IsWouldBlockErrno(errno));
}

} // namespace reflector
