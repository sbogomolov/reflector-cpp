#include "reflector/application.h"

#include "reflector/config.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/packet_capture_socket.h"
#include "reflector/udp_link_fanout_sender.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace reflector {

class ApplicationTest : public ::testing::Test {
protected:
    static size_t CaptureSocketCount(const Application& app) { return app.CaptureSocketCount(); }
    static size_t ListenerCount(const Application& app) { return app.ListenerCount(); }
    static size_t ReflectorCount(const Application& app) { return app.ReflectorCount(); }

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

    // Factory that hands out capture sockets wrapping real AF_UNIX fds (so the dispatcher
    // can register them) without needing CAP_NET_RAW. Counts calls so tests can assert how
    // many distinct interfaces were opened. The PacketCaptureSocket owns and closes the fd.
    struct CountingCaptureFactory {
        int calls = 0;

        Application::CaptureSocketFactory Make() {
            return [this](std::string_view interface) {
                ++calls;
                const int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
                return PacketCaptureSocket::ForTestingPtr(interface, fd);
            };
        }
    };

    // A loopback sender needs SO_BINDTODEVICE on Linux (root); IP_BOUND_IF on macOS works
    // unprivileged. Tests that wire real reflectors skip when it is unavailable.
    static bool CanBindLoopbackSender() {
        UdpLinkFanoutSender probe{LoopbackInterface(), IpAddress::Family::V4};
        return probe.IsValid();
    }
};

TEST_F(ApplicationTest, InvalidCaptureSocketFailsConfigure) {
    Application app{[](std::string_view interface) {
        return PacketCaptureSocket::ForTestingPtr(interface, -1);
    }};
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", LoopbackInterface(), {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("capture socket on interface \"captest\" is invalid"), std::string::npos) << output;
}

TEST_F(ApplicationTest, ConfigureFailsWhenReflectorSetupFails) {
    CountingCaptureFactory factory;
    Application app{factory.Make()};

    // The injected capture socket is valid, so Configure gets past the capture check and on
    // to building the reflector, whose sender then fails to resolve a nonexistent target
    // interface. if_nametoindex fails for a missing interface regardless of privileges, so
    // this exercises the reflector-failure branch deterministically on every platform.
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", "nonexistent-iface-xyz", {9}))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("Cannot configure wol reflector \"tv\": setup failed"), std::string::npos) << output;
}

// Wiring tests that build real reflectors: their UDP sender must bind to a real loopback
// interface (SO_BINDTODEVICE → root on Linux; unprivileged on macOS). The "RequiresRoot"
// name carries the "root" ctest label; SetUp skips when the privilege is unavailable.
class ApplicationRequiresRootTest : public ApplicationTest {
protected:
    void SetUp() override {
        if (!CanBindLoopbackSender()) {
            GTEST_SKIP() << "loopback UDP sender unavailable (needs root for SO_BINDTODEVICE on Linux)";
        }
    }
};

TEST_F(ApplicationRequiresRootTest, WiresReflectorsAndSharesCaptureForSameInterface) {
    CountingCaptureFactory factory;
    Application app{factory.Make()};

    // Two reflectors on the same source interface, different ports: they must share one
    // capture socket and one listener while producing two reflectors.
    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "captest", LoopbackInterface(), {7}))
        .Add(MakeConfig("console", "captest", LoopbackInterface(), {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));
    EXPECT_EQ(factory.calls, 1);
    EXPECT_EQ(CaptureSocketCount(app), 1);
    EXPECT_EQ(ListenerCount(app), 1);
    EXPECT_EQ(ReflectorCount(app), 2);
}

TEST_F(ApplicationRequiresRootTest, WiresSeparateCaptureSocketsForDistinctInterfaces) {
    CountingCaptureFactory factory;
    Application app{factory.Make()};

    const Config config = TestConfigBuilder{}
        .Add(MakeConfig("tv", "cap-a", LoopbackInterface(), {7}))
        .Add(MakeConfig("console", "cap-b", LoopbackInterface(), {9}))
        .Build();

    ASSERT_TRUE(app.Configure(config));
    EXPECT_EQ(factory.calls, 2);
    EXPECT_EQ(CaptureSocketCount(app), 2);
    EXPECT_EQ(ListenerCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 2);
}

} // namespace reflector
