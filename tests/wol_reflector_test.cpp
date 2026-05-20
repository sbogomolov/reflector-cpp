#include "reflector/wol_reflector.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace reflector {

class WolReflectorTestBase {
protected:
    static WolConfig MakeConfig(IpAddress::Family family) {
        return WolConfig{
            .name = "tv",
            .mac = *MacAddress::FromString("00:11:22:33:44:55"),
            .source_if = "src",
            .target_if = "dst",
            .ports = {FreeLoopbackPort(family)},
            .address_family = family == IpAddress::Family::V4
                ? WolAddressFamily::IPv4
                : WolAddressFamily::IPv6,
        };
    }

    static std::vector<std::byte> MakeMagicPacket(const MacAddress& mac) {
        constexpr size_t PREFIX_SIZE = 6;
        constexpr size_t MAC_REPETITIONS = 16;

        std::vector<std::byte> payload(PREFIX_SIZE, std::byte{0xff});
        const auto& mac_bytes = mac.Bytes();
        for (size_t i = 0; i < MAC_REPETITIONS; ++i) {
            payload.insert(payload.end(), mac_bytes.begin(), mac_bytes.end());
        }
        return payload;
    }

    static Packet MakePacket(std::span<const std::byte> payload, IpAddress source_ip, uint16_t dest_port) {
        return Packet{
            .header = PacketHeader{
                .source_ip = source_ip,
                .dest_ip = source_ip.IsV4() ? IpAddress::BroadcastV4() : IpAddress::AllNodesLinkLocalV6(),
                .source_port = 12345,
                .dest_port = dest_port,
            },
            .payload = payload,
        };
    }

    static WolReflector MakeReflector(WolListener& listener, const WolConfig& config,
        std::optional<UdpLinkFanoutSender> v4_sender,
        std::optional<UdpLinkFanoutSender> v6_sender) {
        return WolReflector{listener, config, std::move(v4_sender), std::move(v6_sender)};
    }

    static void Dispatch(WolReflector& reflector, uint16_t port, const Packet& packet) {
        reflector.HandlePacket(packet, port);
    }

    static void ReplaceV4Sender(WolReflector& reflector, std::optional<UdpLinkFanoutSender> sender) {
        reflector.v4_sender_ = std::move(sender);
    }
};

class WolReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                  public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    TestCaptureSocket capture;
    WolListener listener{dispatcher, capture.socket};

    size_t DispatcherRegistrationCount() const { return dispatcher.RegistrationCount(); }

    WolReflector BuildReflector(const WolConfig& config) {
        if (GetParam() == IpAddress::Family::V4) {
            return MakeReflector(listener, config,
                UdpLinkFanoutSender{"", IpAddress::LoopbackV4()}, std::nullopt);
        }
        return MakeReflector(listener, config,
            std::nullopt, UdpLinkFanoutSender{"", IpAddress::LoopbackV6()});
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    WolReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& info) -> std::string {
        return std::format("{}", info.param);
    });

TEST_P(WolReflectorPerFamilyTest, RegistersWithListener) {
    const auto reflector = BuildReflector(MakeConfig(GetParam()));

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_P(WolReflectorPerFamilyTest, CreatedLogUsesConfigNameInLoggerName) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const auto config = MakeConfig(GetParam());

    const std::string output = CaptureStdout([&] {
        const auto reflector = BuildReflector(config);
        EXPECT_TRUE(reflector.IsValid());
    });

    EXPECT_NE(output.find("[WolReflector:tv]"), std::string::npos) << output;
    EXPECT_NE(output.find("Created wol reflector \"tv\""), std::string::npos) << output;
}

TEST_P(WolReflectorPerFamilyTest, DestructorUnregistersFromListener) {
    {
        const auto reflector = BuildReflector(MakeConfig(GetParam()));
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_P(WolReflectorPerFamilyTest, ReflectsMagicPacket) {
    const auto family = GetParam();
    const auto port = FreeLoopbackPort(family);
    LoopbackReceiver receiver{port, family};

    auto config = MakeConfig(family);
    config.ports = {port};
    auto reflector = BuildReflector(config);
    ASSERT_TRUE(reflector.IsValid());

    ASSERT_TRUE(config.mac.has_value());
    const auto payload = MakeMagicPacket(*config.mac);
    Dispatch(reflector, port, MakePacket(payload, LoopbackFor(family), port));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

class WolReflectorTest : public ::testing::Test, public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    TestCaptureSocket capture;
    WolListener listener{dispatcher, capture.socket};

    size_t DispatcherRegistrationCount() const { return dispatcher.RegistrationCount(); }

    WolReflector BuildV4Reflector(const WolConfig& config) {
        return MakeReflector(listener, config,
            UdpLinkFanoutSender{"", IpAddress::LoopbackV4()}, std::nullopt);
    }
};

TEST_F(WolReflectorTest, RejectsConfigWithEmptyPorts) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {};

    const auto reflector = BuildV4Reflector(config);

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, IsInvalidWhenSenderInvalid) {
    UdpLinkFanoutSender invalid_sender{"nonexistent-iface-xyz", IpAddress::Family::V4};
    ASSERT_FALSE(invalid_sender.IsValid());

    const auto reflector = MakeReflector(listener, MakeConfig(IpAddress::Family::V4),
        std::move(invalid_sender), std::nullopt);

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, LogsErrorWhenSenderRejectsPacket) {
    // Build the reflector with a valid sender so Initialize fully sets up magic-packet
    // state, then swap in an invalid sender so sender->Send() returns false. This is the
    // only way to reach HandlePacket's send-failure branch — in production the path is
    // unreachable (a sender that fails Send was already invalid at construction time, so
    // the reflector itself would have failed to initialize).
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());
    ReplaceV4Sender(reflector,
        UdpLinkFanoutSender{"nonexistent-iface-xyz", IpAddress::Family::V4});

    LoopbackReceiver receiver{0, IpAddress::Family::V4};
    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);

    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, receiver.Port(),
            MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));
    });

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
    EXPECT_NE(output.find("Cannot reflect wol packet"), std::string::npos) << output;
}

TEST_F(WolReflectorTest, IgnoresPacketWithUnsupportedFamily) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    // Inject an IPv6 packet — the v4-only reflector has no v6 sender and must drop.
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::LoopbackV6(), receiver.Port()));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, ReflectsPacketWithTrailingBytes) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    payload.push_back(std::byte{0x12});
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, IgnoresShortPacket) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const std::vector<std::byte> payload(12, std::byte{0xff});
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresInvalidMagicPrefix) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    payload.front() = std::byte{0x00};
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresDifferentMac) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, ReflectsAnyMagicPacketWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, IgnoresMalformedMagicPacketWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    payload[12] = std::byte{0x12};
    Dispatch(reflector, receiver.Port(),
        MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), receiver.Port()));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

// In Default mode the config "uses" but doesn't "require" IPv6: if the v6 sender setup
// fails (e.g. no IPv6 on target_if) the reflector is still valid via IPv4. Incoming v6
// packets must then be silently dropped — not handed to the invalid sender, which would
// log a per-packet error on top of every drop.
TEST_F(WolReflectorTest, SilentlyDropsV6PacketsWhenV6SenderUnavailableInDefault) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.address_family = WolAddressFamily::Default;
    UdpLinkFanoutSender invalid_v6{"nonexistent-iface-xyz", IpAddress::Family::V6};
    ASSERT_FALSE(invalid_v6.IsValid());

    auto reflector = MakeReflector(listener, config,
        UdpLinkFanoutSender{"", IpAddress::LoopbackV4()}, std::move(invalid_v6));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V6};
    const auto payload = MakeMagicPacket(*config.mac);

    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, receiver.Port(),
            MakePacket(payload, IpAddress::LoopbackV6(), receiver.Port()));
    });

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
    EXPECT_EQ(output.find("ERROR"), std::string::npos)
        << "v6 packet on a v6-unavailable Default reflector should not log at ERROR level: " << output;
}

} // namespace reflector
