#include "reflector/wol_reflector.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
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
            .ports = {9},
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

    static Packet MakePacket(std::span<const std::byte> payload, IpAddress source_ip,
        uint16_t dest_port, uint8_t ttl = 64) {
        return Packet{
            .header = PacketHeader{
                .source_ip = source_ip,
                .dest_ip = IpAddress::LinkFanoutFor(source_ip.AddressFamily()),
                .source_port = 12345,
                .dest_port = dest_port,
                .ttl = ttl,
            },
            .payload = payload,
        };
    }

    static void Dispatch(WolReflector& reflector, const Packet& packet) {
        reflector.OnPacket(packet);
    }
};

class WolReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                  public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    DefaultPacketDispatcher packet_dispatcher{dispatcher};
    TestCaptureSocket source;
    RecordingUdpSender target;

    size_t DispatcherRegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

    WolReflector BuildReflector(const WolConfig& config) {
        target.can_send_v4 = GetParam() == IpAddress::Family::V4;
        target.can_send_v6 = GetParam() == IpAddress::Family::V6;
        return WolReflector{packet_dispatcher, source.socket, target, config};
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    WolReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& param_info) -> std::string {
        return std::format("{}", param_info.param);
    });

TEST_P(WolReflectorPerFamilyTest, RegistersWithDefaultPacketDispatcher) {
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

    // The reflector names its logger after the config, so per-config logs are attributable.
    EXPECT_NE(output.find("tv"), std::string::npos) << output;
}

TEST_P(WolReflectorPerFamilyTest, DestructorUnregistersFromDefaultPacketDispatcher) {
    {
        const auto reflector = BuildReflector(MakeConfig(GetParam()));
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_P(WolReflectorPerFamilyTest, ReflectsMagicPacket) {
    const auto family = GetParam();
    const auto config = MakeConfig(family);
    auto reflector = BuildReflector(config);
    ASSERT_TRUE(reflector.IsValid());

    ASSERT_TRUE(config.mac.has_value());
    const auto payload = MakeMagicPacket(*config.mac);
    const uint16_t dest_port = config.ports.front();
    constexpr uint8_t source_ttl = 200;
    Dispatch(reflector, MakePacket(payload, LoopbackFor(family), dest_port, source_ttl));

    ASSERT_EQ(target.sent.size(), 1u);
    const auto& sent = target.sent.front();
    // Fans out to the family's link-everyone address (the V4/V6 mapping itself is covered by
    // the IpAddress::LinkFanoutFor test).
    EXPECT_EQ(sent.dst_ip, IpAddress::LinkFanoutFor(family));
    EXPECT_EQ(sent.dst_port, dest_port);
    EXPECT_EQ(sent.src_port, 12345);     // the original datagram's source port is preserved
    EXPECT_EQ(sent.ttl, source_ttl);     // re-emitted with the captured TTL, not a fixed one
    EXPECT_EQ(sent.payload, payload);
}

class WolReflectorTest : public ::testing::Test, public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    DefaultPacketDispatcher packet_dispatcher{dispatcher};
    TestCaptureSocket source;
    RecordingUdpSender target;

    size_t DispatcherRegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

    WolReflector BuildV4Reflector(const WolConfig& config) {
        target.can_send_v4 = true;
        target.can_send_v6 = false;
        return WolReflector{packet_dispatcher, source.socket, target, config};
    }
};

TEST_F(WolReflectorTest, RejectsConfigWithEmptyPorts) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {};

    const auto reflector = BuildV4Reflector(config);

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, IsInvalidWhenTargetCannotSendRequiredFamily) {
    target.can_send_v4 = false;

    const WolReflector reflector{packet_dispatcher, source.socket, target,
        MakeConfig(IpAddress::Family::V4)};

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, LogsErrorWhenSendFails) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());
    target.fail_send = true;

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(WolReflectorTest, ReflectedLogShowsMacAndInterfaces) {
    const ScopedMinLogLevel level{LogLevel::Info};
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
    });

    EXPECT_NE(output.find("src"), std::string::npos) << output;
    EXPECT_NE(output.find("dst"), std::string::npos) << output;
    EXPECT_NE(output.find("00:11:22:33:44:55"), std::string::npos) << output;
}

// The logged MAC is taken from the payload, not config.mac: in any-MAC mode there is no
// configured MAC, so a payload MAC distinct from any config value proves the source.
TEST_F(WolReflectorTest, ReflectedLogShowsPayloadMacInAnyMacMode) {
    const ScopedMinLogLevel level{LogLevel::Info};
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
    });

    EXPECT_NE(output.find("66:55:44:33:22:11"), std::string::npos) << output;
}

TEST_F(WolReflectorTest, IgnoresPacketWithUnsupportedFamily) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    // Inject an IPv6 packet — the v4-only reflector does not handle v6 and must drop it.
    Dispatch(reflector, MakePacket(payload, IpAddress::LoopbackV6(), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, ReflectsPacketWithTrailingBytes) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    payload.push_back(std::byte{0x12});
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    ASSERT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(target.sent.front().payload, payload);
}

TEST_F(WolReflectorTest, IgnoresShortPacket) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const std::vector<std::byte> payload(12, std::byte{0xff});
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresInvalidMagicPrefix) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    payload.front() = std::byte{0x00};
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresDifferentMac) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, ReflectsAnyMagicPacketWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    ASSERT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(target.sent.front().payload, payload);
}

TEST_F(WolReflectorTest, IgnoresMalformedMagicPacketWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    payload[12] = std::byte{0x12};
    Dispatch(reflector, MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

// In Default mode the config "uses" but doesn't "require" IPv6: if the target cannot send v6
// (e.g. no IPv6 on target_if) the reflector is still valid via IPv4. Incoming v6 packets must
// then be silently dropped — not sent (which would fail) and not logged at ERROR per packet.
TEST_F(WolReflectorTest, SilentlyDropsV6PacketsWhenV6UnavailableInDefault) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.address_family = WolAddressFamily::Default;
    target.can_send_v4 = true;
    target.can_send_v6 = false;

    WolReflector reflector{packet_dispatcher, source.socket, target, config};
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*config.mac);
    const std::string output = CaptureStdout([&] {
        Dispatch(reflector, MakePacket(payload, IpAddress::LoopbackV6(), 9));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(output.find("ERROR"), std::string::npos)
        << "v6 packet on a v6-unavailable Default reflector should not log at ERROR level: " << output;
}

} // namespace reflector
