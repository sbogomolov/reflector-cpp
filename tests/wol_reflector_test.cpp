#include "reflector/wol_reflector.h"
#include "reflector/mac_address.h"
#include "mocks/fake_link_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

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
                ? AddressFamily::IPv4
                : AddressFamily::IPv6,
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
};

// Tests whose behavior depends on the address family run for both V4 and V6: setup-time family
// gating and the reflection/send path (the destination and the target's per-family send).
class WolReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                  public WolReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;
    FakeLinkSocket target;

    size_t DispatcherRegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

    WolReflector BuildReflector(const WolConfig& config) {
        target.can_send_v4 = GetParam() == IpAddress::Family::V4;
        target.can_send_v6 = GetParam() == IpAddress::Family::V6;
        return WolReflector{packet_dispatcher, source, target, config};
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    WolReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& param_info) -> std::string {
        return std::format("{}", param_info.param);
    });

TEST_P(WolReflectorPerFamilyTest, RegistersWithPacketDispatcher) {
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

TEST_P(WolReflectorPerFamilyTest, DestructorUnregistersFromPacketDispatcher) {
    {
        const auto reflector = BuildReflector(MakeConfig(GetParam()));
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

// A config that requires a family (IPv4 requires v4, IPv6 requires v6) the target cannot send
// fails setup, and the error names that family.
TEST_P(WolReflectorPerFamilyTest, RequiredFamilyUnavailableMakesInvalid) {
    const auto family = GetParam();
    target.can_send_v4 = false;
    target.can_send_v6 = false;

    const std::string output = CaptureStdout([&] {
        const WolReflector reflector{packet_dispatcher, source, target, MakeConfig(family)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(DispatcherRegistrationCount(), 0);
    });

    EXPECT_NE(output.find(std::format("{}", family)), std::string::npos) << output;
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
    packet_dispatcher.Deliver(MakePacket(payload, LoopbackFor(family), dest_port, source_ttl));

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

TEST_P(WolReflectorPerFamilyTest, ReflectsPacketWithTrailingBytes) {
    const auto family = GetParam();
    const auto config = MakeConfig(family);
    auto reflector = BuildReflector(config);
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*config.mac);
    payload.push_back(std::byte{0x12}); // e.g. a trailing SecureOn password — forwarded as-is
    packet_dispatcher.Deliver(MakePacket(payload, LoopbackFor(family), config.ports.front()));

    ASSERT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(target.sent.front().payload, payload);
}

TEST_P(WolReflectorPerFamilyTest, ReflectsAnyMagicPacketWhenMacIsUnspecified) {
    const auto family = GetParam();
    auto config = MakeConfig(family);
    config.mac.reset();
    auto reflector = BuildReflector(config);
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    packet_dispatcher.Deliver(MakePacket(payload, LoopbackFor(family), config.ports.front()));

    ASSERT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(target.sent.front().payload, payload);
}

// Family-independent behavior is exercised once, over IPv4.
class WolReflectorTest : public ::testing::Test, public WolReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;
    FakeLinkSocket target;

    size_t DispatcherRegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

    WolReflector BuildV4Reflector(const WolConfig& config) {
        target.can_send_v4 = true;
        target.can_send_v6 = false;
        return WolReflector{packet_dispatcher, source, target, config};
    }
};

TEST_F(WolReflectorTest, RejectsConfigWithEmptyPorts) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {};

    const std::string output = CaptureStdout([&] {
        const auto reflector = BuildV4Reflector(config);
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(DispatcherRegistrationCount(), 0);
    });

    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(WolReflectorTest, RegistersACallbackPerConfiguredPort) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {7, 9};
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 2);

    const auto payload = MakeMagicPacket(*config.mac);
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 7));
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    ASSERT_EQ(target.sent.size(), 2u);
    EXPECT_EQ(target.sent[0].dst_port, 7);
    EXPECT_EQ(target.sent[1].dst_port, 9);
}

// If registering one port fails, the already-registered ports are rolled back and the reflector
// reports itself invalid.
TEST_F(WolReflectorTest, RegistrationFailureRollsBackAndInvalidates) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {7, 9};
    packet_dispatcher.fail_register_on_call = 2; // second port's registration fails

    const std::string output = CaptureStdout([&] {
        const auto reflector = BuildV4Reflector(config);
        EXPECT_FALSE(reflector.IsValid());
    });

    EXPECT_EQ(DispatcherRegistrationCount(), 0); // the first port's registration was rolled back
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(WolReflectorTest, IgnoresPacketOnUnconfiguredPort) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {9};
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*config.mac);
    // Port 7 is not configured, so the reflector's dest_port=9 filter must reject it.
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 7));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, DualModeValidWhenBothFamiliesAvailable) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.address_family = AddressFamily::Dual;
    target.can_send_v4 = true;
    target.can_send_v6 = true;

    const WolReflector reflector{packet_dispatcher, source, target, config};

    EXPECT_TRUE(reflector.IsValid());
}

TEST_F(WolReflectorTest, DualModeInvalidWhenAFamilyIsUnavailable) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.address_family = AddressFamily::Dual;
    target.can_send_v4 = true;
    target.can_send_v6 = false; // Dual requires v6 too

    const WolReflector reflector{packet_dispatcher, source, target, config};

    EXPECT_FALSE(reflector.IsValid());
}

TEST_F(WolReflectorTest, LogsErrorWhenSendFails) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());
    target.fail_send = true;

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
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
        packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
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
        packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));
    });

    EXPECT_NE(output.find("66:55:44:33:22:11"), std::string::npos) << output;
}

// A v4-only config must drop v6 packets even when the target *can* send v6 — proving it is the
// config's family selection, not the target's capability, that rejects them.
TEST_F(WolReflectorTest, IgnoresPacketWithUnsupportedFamily) {
    target.can_send_v4 = true;
    target.can_send_v6 = true;
    const WolReflector reflector{packet_dispatcher, source, target, MakeConfig(IpAddress::Family::V4)};
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::LoopbackV6(), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresShortPacket) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const std::vector<std::byte> payload(12, std::byte{0xff});
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresInvalidMagicPrefix) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MakeConfig(IpAddress::Family::V4).mac);
    payload.front() = std::byte{0x00};
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresDifferentMac) {
    auto reflector = BuildV4Reflector(MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

TEST_F(WolReflectorTest, IgnoresMalformedMagicPacketWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    payload[12] = std::byte{0x12}; // break the MAC repetition consistency
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

// Any-MAC mode still requires the six-0xFF prefix (a different code path from the fixed-MAC
// memcmp that IgnoresInvalidMagicPrefix exercises).
TEST_F(WolReflectorTest, IgnoresBadPrefixWhenMacIsUnspecified) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.mac.reset();
    auto reflector = BuildV4Reflector(config);
    ASSERT_TRUE(reflector.IsValid());

    auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    payload.front() = std::byte{0x00};
    packet_dispatcher.Deliver(MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1), 9));

    EXPECT_TRUE(target.sent.empty());
}

// In Default mode the config "uses" but doesn't "require" IPv6: if the target cannot send v6
// (e.g. no IPv6 on target_if) the reflector is still valid via IPv4. Incoming v6 packets must
// then be silently dropped — not sent (which would fail) and not logged at ERROR per packet.
TEST_F(WolReflectorTest, SilentlyDropsV6PacketsWhenV6UnavailableInDefault) {
    auto config = MakeConfig(IpAddress::Family::V4);
    config.address_family = AddressFamily::Default;
    target.can_send_v4 = true;
    target.can_send_v6 = false;

    WolReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    const auto payload = MakeMagicPacket(*config.mac);
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(MakePacket(payload, IpAddress::LoopbackV6(), 9));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(output.find("ERROR"), std::string::npos)
        << "v6 packet on a v6-unavailable Default reflector should not log at ERROR level: " << output;
}

} // namespace reflector
