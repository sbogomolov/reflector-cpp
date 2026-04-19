#include "reflector/udp_sender.h"

#include "packet_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <vector>

using namespace reflector;

TEST(UdpSenderTest, EmptyInterfaceNameIsValid) {
    UdpSender sender{""};
    EXPECT_TRUE(sender.IsValid());
}

TEST(UdpSenderTest, UnknownInterfaceIsInvalid) {
    UdpSender sender{"nonexistent-iface-xyz"};
    EXPECT_FALSE(sender.IsValid());
}

TEST(UdpSenderTest, SendBroadcastOnInvalidSenderFails) {
    UdpSender sender{"nonexistent-iface-xyz"};
    ASSERT_FALSE(sender.IsValid());

    const std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
    EXPECT_FALSE(sender.SendBroadcast(payload, 9));
}

TEST(UdpSenderTest, SendBroadcastToLoopbackAddress) {
    LoopbackReceiver receiver;

    UdpSender sender{"", IpAddress::Loopback()};
    ASSERT_TRUE(sender.IsValid());

    const std::array payload{std::byte{1}, std::byte{2}, std::byte{3}};
    ASSERT_TRUE(sender.SendBroadcast(payload, receiver.Port()));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
}
