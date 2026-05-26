#include "reflector/application.h"

#include "reflector/config.h"
#include "reflector/mac_address.h"
#include "reflector/raw_socket.h"
#include "mocks/fake_address_monitor.h"
#include "mocks/fake_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace reflector {

class ApplicationTest : public ::testing::Test {
protected:
    static size_t SocketCount(const Application& app) { return app.SocketCount(); }
    static size_t ReflectorCount(const Application& app) { return app.ReflectorCount(); }

    // Builds an Application with a fake dispatcher + address monitor (no real epoll or netlink)
    // and the given socket factory, through the ForTesting seam.
    static Application MakeApp(Application::SocketFactory factory) {
        return Application::ForTesting(std::make_unique<FakeDispatcher>(),
            std::make_unique<FakeAddressMonitor>(), std::move(factory));
    }

    static WolConfig MakeConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, std::vector<uint16_t> ports) {
        return WolConfig{
            .name = std::string{name},
            .mac = *MacAddress::FromString("00:11:22:33:44:55"),
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .ports = std::move(ports),
            .address_family = WolAddressFamily::IPv4,
        };
    }

    // Factory for the interfaces a test configures. The loopback target gets a real RawSocket
    // so it resolves a source address (and so CanSend) like production; every other (fake)
    // interface gets a socket wrapping an AF_UNIX fd, which the dispatcher can still register
    // without CAP_NET_RAW. Counts calls so tests can assert how many distinct interfaces were
    // opened. The RawSocket owns and closes the fd.
    struct CountingSocketFactory {
        int calls = 0;

        Application::SocketFactory Make() {
            return [this](std::string_view interface) -> std::unique_ptr<RawSocket> {
                ++calls;
                if (interface == LoopbackInterface()) {
                    return std::make_unique<RawSocket>(interface);
                }
                const int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
                return RawSocket::ForTestingPtr(interface, fd);
            };
        }
    };
};

TEST_F(ApplicationTest, InvalidSocketFailsConfigure) {
    auto app = MakeApp([](std::string_view interface) {
        return RawSocket::ForTestingPtr(interface, -1);
    });
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", LoopbackInterface(), {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}

TEST_F(ApplicationTest, ConfigureFailsWhenReflectorSetupFails) {
    CountingSocketFactory factory;
    auto app = MakeApp(factory.Make());

    // Both injected sockets have valid fds, so Configure gets past the socket checks and on to
    // building the reflector. The target is a ForTesting socket with no resolved interface
    // address, so CanSend(IPv4) is false and the reflector (which requires IPv4) fails to
    // initialize — exercising the reflector-failure branch deterministically without root.
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", "captest-target", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}

// Wiring tests that build real reflectors: the loopback target socket must open as a real
// RawSocket so it resolves a source address (needs CAP_NET_RAW on Linux, bpf access on macOS).
// The "RequiresRoot" name carries the "root" ctest label; SetUp skips when it is unavailable.
class ApplicationRequiresRootTest : public ApplicationTest {
protected:
    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "raw socket on loopback unavailable (needs CAP_NET_RAW / bpf access)";
        }
    }
};

TEST_F(ApplicationRequiresRootTest, WiresReflectorsAndSharesSocketForSameInterface) {
    CountingSocketFactory factory;
    auto app = MakeApp(factory.Make());

    // Two reflectors over the same source and target interfaces, different ports: each
    // interface is opened once and shared (the packet dispatcher watches the source fd once),
    // so two interfaces back two reflectors.
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", LoopbackInterface(), {7}))
        .Add(MakeConfig("console", "captest", LoopbackInterface(), {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));
    EXPECT_EQ(factory.calls, 2); // source "captest" + target loopback, each created once
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 2);
}

TEST_F(ApplicationRequiresRootTest, WiresSeparateSocketsForDistinctInterfaces) {
    CountingSocketFactory factory;
    auto app = MakeApp(factory.Make());

    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "cap-a", LoopbackInterface(), {7}))
        .Add(MakeConfig("console", "cap-b", LoopbackInterface(), {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));
    EXPECT_EQ(factory.calls, 3); // distinct sources "cap-a"/"cap-b" + the shared loopback target
    EXPECT_EQ(SocketCount(app), 3);
    EXPECT_EQ(ReflectorCount(app), 2);
}

} // namespace reflector
