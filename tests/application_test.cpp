#include "reflector/application.h"

#include "reflector/config.h"
#include "reflector/link_socket.h"
#include "reflector/mac_address.h"
#include "mocks/fake_address_monitor.h"
#include "mocks/fake_dispatcher.h"
#include "mocks/fake_link_socket.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <csignal>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace reflector {

// Exercises Application's wiring entirely against fakes — a fake dispatcher, address monitor, and
// per-interface socket factory injected via ForTesting — so dedup, fail-fast, and address-refresh
// routing are covered with no real epoll/netlink/capture sockets and no privilege.
class ApplicationTest : public ::testing::Test {
protected:
    static size_t SocketCount(const Application& app) { return app.SocketCount(); }
    static size_t ReflectorCount(const Application& app) { return app.ReflectorCount(); }

    // Per-interface settings the factory stamps onto a socket when it first creates it. Interfaces
    // with no entry get the defaults (valid, can send both families, index 0).
    struct SocketConfig {
        bool valid = true;
        bool can_send_v4 = true;
        bool can_send_v6 = true;
        unsigned interface_index = 0;
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

    // Builds an Application through the ForTesting seam with a fake dispatcher and address monitor
    // (both recorded for the test to drive/inspect) and the recording socket factory. Set
    // monitor_starts_ and any ConfigureSocket() entries beforehand.
    Application MakeApp() {
        auto dispatcher = std::make_unique<FakeDispatcher>();
        dispatcher_ = dispatcher.get();
        auto monitor = std::make_unique<FakeAddressMonitor>();
        monitor->start_succeeds = monitor_starts_;
        monitor_ = monitor.get();
        return Application::ForTesting(std::move(dispatcher), std::move(monitor), MakeFactory());
    }

    static WolConfig MakeConfig(std::string_view name, std::string_view source_if,
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

    FakeDispatcher* dispatcher_ = nullptr;
    FakeAddressMonitor* monitor_ = nullptr;
    bool monitor_starts_ = true;
    int factory_calls_ = 0;

private:
    Application::SocketFactory MakeFactory() {
        return [this](std::string_view interface) -> std::unique_ptr<LinkSocket> {
            ++factory_calls_;
            auto socket = std::make_unique<FakeLinkSocket>();
            const auto it = socket_configs_.find(std::string{interface});
            const SocketConfig config = it == socket_configs_.end() ? SocketConfig{} : it->second;
            socket->valid = config.valid;
            socket->can_send_v4 = config.can_send_v4;
            socket->can_send_v6 = config.can_send_v6;
            socket->interface_index = config.interface_index;
            socket->fd = next_fd_++;
            created_sockets_.insert_or_assign(std::string{interface}, socket.get());
            return socket;
        };
    }

    std::unordered_map<std::string, SocketConfig> socket_configs_;
    std::unordered_map<std::string, FakeLinkSocket*> created_sockets_;
    int next_fd_ = 100;
};

TEST_F(ApplicationTest, SharesOneSocketPerInterfaceAcrossConfigs) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "src", "dst", {7}))
        .Add(MakeConfig("console", "src", "dst", {9}))
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

TEST_F(ApplicationTest, CreatesDistinctSocketsForDistinctInterfaces) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "src-a", "dst", {7}))
        .Add(MakeConfig("console", "src-b", "dst", {9}))
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
        .Add(MakeConfig("tv", "bad-src", "dst", {9}))
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
        .Add(MakeConfig("tv", "src", "bad-dst", {9}))
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
        .Add(MakeConfig("tv", "src", "dst", {9}))
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
        .Add(MakeConfig("first", "src1", "dst1", {7}))
        .Add(MakeConfig("second", "src2", "dst-bad", {8}))
        .Add(MakeConfig("third", "src3", "dst3", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 1) << output;        // only the first config was wired
    EXPECT_EQ(Socket("src3"), nullptr);                 // the third config was never reached
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
            .Add(MakeConfig("tv", "src", "dst", {9}))
            .Build()));
    });

    EXPECT_NE(output.find("Address monitor unavailable"), std::string::npos) << output;
}

TEST_F(ApplicationTest, RefreshesOnlyTheChangedInterface) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(5);

    EXPECT_EQ(Socket("src")->refresh_count, 1u);
    EXPECT_EQ(Socket("dst")->refresh_count, 0u);
}

TEST_F(ApplicationTest, RefreshesAllInterfacesOnOverflowSignal) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(0); // 0 is the "refresh everything" overflow signal

    EXPECT_EQ(Socket("src")->refresh_count, 1u);
    EXPECT_EQ(Socket("dst")->refresh_count, 1u);
}

TEST_F(ApplicationTest, RefreshesNothingForUnknownInterface) {
    ConfigureSocket("src", {.interface_index = 5});
    ConfigureSocket("dst", {.interface_index = 9});
    auto app = MakeApp();
    ASSERT_TRUE(app.Configure(TestConfigBuilder{}.Add(MakeConfig("tv", "src", "dst", {9})).Build()));

    monitor_->FireChange(7); // no socket is bound to interface index 7

    EXPECT_EQ(Socket("src")->refresh_count, 0u);
    EXPECT_EQ(Socket("dst")->refresh_count, 0u);
}

TEST_F(ApplicationTest, RunDelegatesToTheDispatcher) {
    auto app = MakeApp();
    volatile std::sig_atomic_t stop_requested = 1; // already stopped, so the fake returns at once

    app.Run(stop_requested);

    EXPECT_EQ(dispatcher_->run_calls, 1u);
}

} // namespace reflector
