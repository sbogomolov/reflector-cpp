#include "reflector/wol_listener.h"

#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include "packet_helpers.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <vector>

namespace reflector {

class WolListenerTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, ""};

    size_t DispatcherRegistrationCount() const {
        return dispatcher.RegistrationCount();
    }

    size_t ListenerCount() const {
        return listener.ListenerCount();
    }
};

TEST_F(WolListenerTest, RegisterCreatesUdpListenerForPort) {
    PacketCounter counter;
    const auto port = FreeLoopbackPort();

    const auto registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_F(WolListenerTest, UnregisterRemovesUnusedListener) {
    PacketCounter counter;
    const auto port = FreeLoopbackPort();
    auto registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());

    EXPECT_EQ(ListenerCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolListenerTest, RegistrationsShareUdpListener) {
    PacketCounter first;
    PacketCounter second;
    const auto port = FreeLoopbackPort();

    const auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));

    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());
    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_F(WolListenerTest, UnregisterKeepsSharedListener) {
    PacketCounter first;
    PacketCounter second;
    const auto port = FreeLoopbackPort();
    auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    EXPECT_TRUE(first_registration.Reset());

    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_F(WolListenerTest, DifferentPortsCreateSeparateListeners) {
    PacketCounter counter;
    const auto ports = FreeLoopbackPorts(2);

    const auto first = listener.Register(ports[0], CreateDelegate<&PacketCounter::OnPacket>(&counter));
    const auto second = listener.Register(ports[1], CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(first.IsValid());
    ASSERT_TRUE(second.IsValid());
    EXPECT_EQ(ListenerCount(), 2);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_F(WolListenerTest, RejectsPortZero) {
    PacketCounter counter;

    const auto registration = listener.Register(0, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(ListenerCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolListenerTest, RegisteredCallbackReceivesPacket) {
    const auto port = FreeLoopbackPort();
    ASSERT_NE(port, 0);

    PacketRecorder recorder;
    const auto registration = listener.Register(port, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    UdpSocket sender;
    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(sender.SendTo(payload, IpAddress::Loopback(), port));

    ASSERT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(recorder.source_ip, IpAddress::Loopback());
}

TEST_F(WolListenerTest, SharedListenerForwardsToAllRegistrations) {
    const auto port = FreeLoopbackPort();
    PacketCounter first;
    PacketCounter second;
    const auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    UdpSocket sender;
    const std::array payload{std::byte{0xab}};
    ASSERT_TRUE(sender.SendTo(payload, IpAddress::Loopback(), port));

    ASSERT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

} // namespace reflector
