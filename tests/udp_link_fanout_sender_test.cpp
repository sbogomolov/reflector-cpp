#include "reflector/udp_link_fanout_sender.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <vector>

using namespace reflector;

TEST(UdpLinkFanoutSenderTest, EmptyInterfaceNameIsValid) {
    UdpLinkFanoutSender sender{"", IpAddress::Family::V4};
    EXPECT_TRUE(sender.IsValid());
}

TEST(UdpLinkFanoutSenderTest, EmptyInterfaceNameIsValidForV6) {
    UdpLinkFanoutSender sender{"", IpAddress::Family::V6};
    EXPECT_TRUE(sender.IsValid());
    EXPECT_EQ(sender.AddressFamily(), IpAddress::Family::V6);
    EXPECT_EQ(sender.DestinationAddress(), IpAddress::AllNodesLinkLocalV6());
}

TEST(UdpLinkFanoutSenderTest, UnknownInterfaceIsInvalid) {
    UdpLinkFanoutSender sender{"nonexistent-iface-xyz", IpAddress::Family::V4};
    EXPECT_FALSE(sender.IsValid());
}

TEST(UdpLinkFanoutSenderTest, SendOnInvalidSenderFails) {
    UdpLinkFanoutSender sender{"nonexistent-iface-xyz", IpAddress::Family::V4};
    ASSERT_FALSE(sender.IsValid());

    const std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
    EXPECT_FALSE(sender.Send(payload, 9));
}

TEST(UdpLinkFanoutSenderTest, SendToLoopbackAddress) {
    LoopbackReceiver receiver{0, IpAddress::Family::V4};

    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV4()};
    ASSERT_TRUE(sender.IsValid());

    const std::array payload{std::byte{1}, std::byte{2}, std::byte{3}};
    ASSERT_TRUE(sender.Send(payload, receiver.Port()));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
}

TEST(UdpLinkFanoutSenderTest, SendToV6LoopbackAddress) {
    LoopbackReceiver receiver{0, IpAddress::Family::V6};

    UdpLinkFanoutSender sender{"", IpAddress::LoopbackV6()};
    ASSERT_TRUE(sender.IsValid());

    const std::array payload{std::byte{4}, std::byte{5}, std::byte{6}};
    ASSERT_TRUE(sender.Send(payload, receiver.Port()));

    ASSERT_TRUE(receiver.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(receiver.recorder.count, 1);
    EXPECT_EQ(receiver.recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(receiver.recorder.source_ip, IpAddress::LoopbackV6());
}
