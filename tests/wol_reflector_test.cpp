#include "reflector/wol_reflector.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include "packet_helpers.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace reflector {

class WolReflectorTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, ""};

    size_t DispatcherRegistrationCount() const {
        return dispatcher.RegistrationCount();
    }

    static WolConfig MakeConfig() {
        return WolConfig{
            .name = "tv",
            .mac = *MacAddress::FromString("00:11:22:33:44:55"),
            .source_if = "src",
            .target_if = "dst",
            .ports = {FreeLoopbackPort()},
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

    static Packet MakePacket(std::span<const std::byte> payload) {
        return Packet{
            .header = PacketHeader{
                .source_ip = IpAddress::FromBytes(192, 0, 2, 1),
                .source_port = 12345,
            },
            .payload = payload,
        };
    }

    int ListenerFdForPort(uint16_t port) const {
        for (const auto& entry : listener.listeners_) {
            if (entry.port == port) {
                return entry.listener.Socket().Fd();
            }
        }
        return -1;
    }

    void DispatchPacket(int fd, const Packet& packet) {
        dispatcher.DispatchPacket(fd, packet);
    }

    static void Dispatch(WolReflector& reflector, uint16_t port, const Packet& packet) {
        reflector.HandlePacket(packet, port);
    }
};

TEST_F(WolReflectorTest, RegistersWithWolListener) {
    UdpSender sender{"", IpAddress::Loopback()};

    const WolReflector reflector{listener, sender, MakeConfig()};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_F(WolReflectorTest, DestructorUnregistersFromWolListener) {
    UdpSender sender{"", IpAddress::Loopback()};

    {
        const WolReflector reflector{listener, sender, MakeConfig()};
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, RejectsConfigWithEmptyPorts) {
    auto config = MakeConfig();
    config.ports = {};

    const WolReflector reflector{listener, config};

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, RejectsInvalidUdpSender) {
    UdpSender sender{"nonexistent-iface-xyz"};
    ASSERT_FALSE(sender.IsValid());

    const WolReflector reflector{listener, sender, MakeConfig()};

    EXPECT_FALSE(reflector.IsValid());
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolReflectorTest, ReflectsMagicPacket) {
    const auto port = FreeLoopbackPort();
    LoopbackReceiver receiver{port};

    UdpSender sender{"", IpAddress::Loopback()};
    auto config = MakeConfig();
    config.ports = {port};
    const WolReflector reflector{listener, sender, config};
    ASSERT_TRUE(reflector.IsValid());

    const auto fd = ListenerFdForPort(port);
    ASSERT_GE(fd, 0);

    const auto payload = MakeMagicPacket(config.mac);
    DispatchPacket(fd, MakePacket(payload));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, ReflectsPacketWithTrailingBytes) {
    UdpSender sender{"", IpAddress::Loopback()};
    WolReflector reflector{listener, sender, MakeConfig()};
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver;

    auto payload = MakeMagicPacket(MakeConfig().mac);
    payload.push_back(std::byte{0x12});
    Dispatch(reflector, receiver.Port(), MakePacket(payload));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, payload);
}

TEST_F(WolReflectorTest, IgnoresShortPacket) {
    UdpSender sender{"", IpAddress::Loopback()};
    WolReflector reflector{listener, sender, MakeConfig()};
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver;

    const std::vector<std::byte> payload(12, std::byte{0xff});
    Dispatch(reflector, receiver.Port(), MakePacket(payload));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresInvalidMagicPrefix) {
    UdpSender sender{"", IpAddress::Loopback()};
    WolReflector reflector{listener, sender, MakeConfig()};
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver;

    auto payload = MakeMagicPacket(MakeConfig().mac);
    payload.front() = std::byte{0x00};
    Dispatch(reflector, receiver.Port(), MakePacket(payload));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

TEST_F(WolReflectorTest, IgnoresDifferentMac) {
    UdpSender sender{"", IpAddress::Loopback()};
    WolReflector reflector{listener, sender, MakeConfig()};
    ASSERT_TRUE(reflector.IsValid());

    LoopbackReceiver receiver;

    const auto payload = MakeMagicPacket(*MacAddress::FromString("66:55:44:33:22:11"));
    Dispatch(reflector, receiver.Port(), MakePacket(payload));

    EXPECT_FALSE(receiver.PollOnce(std::chrono::milliseconds{50}));
    EXPECT_EQ(receiver.recorder.count, 0);
}

} // namespace reflector
