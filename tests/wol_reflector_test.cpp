#include "reflector/wol_reflector.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include "packet_helpers.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <vector>

namespace reflector {

// Friend class used by both fixtures for private test hooks.
class WolReflectorTestBase {
protected:
    static WolConfig MakeConfig(IpAddress::Family family) {
        return WolConfig{
            .name = "tv",
            .mac = *MacAddress::FromString("00:11:22:33:44:55"),
            .source_if = "src",
            .target_if = "dst",
            .ports = {FreeLoopbackPort(family)},
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

    static Packet MakePacket(std::span<const std::byte> payload, IpAddress source_ip) {
        return Packet{
            .header = PacketHeader{
                .source_ip = source_ip,
                .source_port = 12345,
            },
            .payload = payload,
        };
    }

    static int ListenerFdForPort(const WolListener& l, uint16_t port) {
        for (const auto& entry : l.listeners_) {
            if (entry.port == port) {
                return entry.listener.Socket().Fd();
            }
        }
        return -1;
    }

    static WolReflector MakeReflector(
        WolListener& listener, UdpLinkFanoutSender& sender, const WolConfig& config) {
        return WolReflector{listener, sender, config};
    }

    static void Dispatch(WolReflector& reflector, uint16_t port, const Packet& packet) {
        reflector.HandlePacket(packet, port);
    }
};

// Only family-dependent behavior is parameterized; the rest stays on the IPv4 fixture.
class WolReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                  public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, "", GetParam()};

    size_t DispatcherRegistrationCount() const { return dispatcher.RegistrationCount(); }
    void DispatchPacket(int fd, const Packet& packet) { dispatcher.DispatchPacket(fd, packet); }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    WolReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& info) -> std::string {
        return std::format("{}", info.param);
    });

TEST_P(WolReflectorPerFamilyTest, RegistersWithListener) {
    UdpLinkFanoutSender sender{"", LoopbackFor(GetParam())};

    const auto reflector = MakeReflector(listener, sender, MakeConfig(GetParam()));

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_P(WolReflectorPerFamilyTest, DestructorUnregistersFromListener) {
    UdpLinkFanoutSender sender{"", LoopbackFor(GetParam())};

    {
        const auto reflector = MakeReflector(listener, sender, MakeConfig(GetParam()));
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_P(WolReflectorPerFamilyTest, ReflectsMagicPacket) {
    const auto family = GetParam();
    const auto port = FreeLoopbackPort(family);
    LoopbackReceiver receiver{port, family};

    UdpLinkFanoutSender sender{"", LoopbackFor(family)};
    auto config = MakeConfig(family);
    config.ports = {port};
    const auto reflector = MakeReflector(listener, sender, config);
    ASSERT_TRUE(reflector.IsValid());

    const auto fd = ListenerFdForPort(listener, port);
    ASSERT_GE(fd, 0);

    const auto payload = MakeMagicPacket(config.mac);
    DispatchPacket(fd, MakePacket(payload, LoopbackFor(family)));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

class WolReflectorTest : public ::testing::Test, public WolReflectorTestBase {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, "", IpAddress::Family::V4};

    size_t DispatcherRegistrationCount() const { return dispatcher.RegistrationCount(); }
};

TEST_F(WolReflectorTest, RejectsConfigWithEmptyPorts) {
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto config = MakeConfig(IpAddress::Family::V4);
    config.ports = {};

    const auto reflector = MakeReflector(listener, sender, config);

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, IsInvalidWhenSenderInvalid) {
    UdpLinkFanoutSender sender{"nonexistent-iface-xyz", IpAddress::Family::V4};
    ASSERT_FALSE(sender.IsValid());

    const auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, ReflectsPacketWithTrailingBytes) {
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(MakeConfig(IpAddress::Family::V4).mac);
    payload.push_back(std::byte{0x12});
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1)));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, ReflectsLargePacketWithTrailingBytesIntact) {
    constexpr size_t LARGE_PAYLOAD_SIZE = 8 * 1024;
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(MakeConfig(IpAddress::Family::V4).mac);
    const auto magic_packet_size = payload.size();
    payload.resize(LARGE_PAYLOAD_SIZE);
    for (size_t i = magic_packet_size; i < payload.size(); ++i) {
        payload[i] = std::byte{static_cast<unsigned char>(i & 0xff)};
    }
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1)));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, IgnoresShortPacket) {
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const std::vector<std::byte> payload(12, std::byte{0xff});
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1)));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresInvalidMagicPrefix) {
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    auto payload = MakeMagicPacket(MakeConfig(IpAddress::Family::V4).mac);
    payload.front() = std::byte{0x00};
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1)));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresDifferentMac) {
    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    auto reflector = MakeReflector(listener, sender, MakeConfig(IpAddress::Family::V4));
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, receiver.Port(), MakePacket(payload, IpAddress::FromV4Bytes(192, 0, 2, 1)));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

} // namespace reflector
