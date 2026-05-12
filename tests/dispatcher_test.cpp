#include "reflector/dispatcher.h"
#include "reflector/udp_socket.h"

#include "reflector/util/delegate.h"

#include "packet_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <utility>
#include <vector>

namespace reflector {

class DispatcherTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;

    void Dispatch(int fd, const Packet& packet) {
        dispatcher.DispatchPacket(fd, packet);
    }

    size_t RegistrationCount() const {
        return dispatcher.RegistrationCount();
    }
};

struct UnregisteringPacketCounter {
    void OnPacket(const Packet&) {
        ++count;
        if (registration_to_reset != nullptr && registration_to_reset->IsValid()) {
            reset_result = registration_to_reset->Reset();
        }
    }

    Dispatcher::Registration* registration_to_reset = nullptr;
    bool reset_result = false;
    int count = 0;
};

TEST_F(DispatcherTest, RegistersCallback) {
    UdpSocket socket;
    PacketCounter counter;

    const auto registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DispatcherTest, RegisterRejectsMovedFromSocket) {
    UdpSocket socket;
    auto moved_socket = std::move(socket);
    PacketCounter counter;

    const auto registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(socket.IsValid());
    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_TRUE(moved_socket.IsValid());
}

TEST_F(DispatcherTest, DispatchesMatchingPacket) {
    UdpSocket socket;
    PacketCounter counter;
    const auto registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(socket.Fd(), MakePacket());

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, SourceFiltersRejectNonMatchingPackets) {
    UdpSocket socket;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromBytes(192, 0, 2, 10),
        .source_port = 7,
    };
    const auto registration = dispatcher.Register(socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(socket.Fd(), MakePacket(IpAddress::FromBytes(192, 0, 2, 10), 9));
    Dispatch(socket.Fd(), MakePacket(IpAddress::FromBytes(192, 0, 2, 11), 7));

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, SourceFiltersAcceptMatchingPackets) {
    UdpSocket socket;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromBytes(192, 0, 2, 10),
        .source_port = 7,
    };
    const auto registration = dispatcher.Register(socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(socket.Fd(), MakePacket(IpAddress::FromBytes(192, 0, 2, 10), 7));

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, MultipleRegistrationsReceivePacket) {
    UdpSocket socket;
    PacketCounter first;
    PacketCounter second;

    const auto first_registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    Dispatch(socket.Fd(), MakePacket());

    EXPECT_EQ(RegistrationCount(), 2);
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

TEST_F(DispatcherTest, UnregisterRemovesCallback) {
    UdpSocket socket;
    PacketCounter counter;
    auto registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());
    Dispatch(socket.Fd(), MakePacket());

    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_EQ(counter.count, 0);
}

TEST(DispatcherRegistrationLifetimeTest, RegistrationInvalidAfterDispatcherDestroyed) {
    Dispatcher::Registration registration;
    UdpSocket socket;
    PacketCounter counter;

    {
        Dispatcher dispatcher;
        registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
        ASSERT_TRUE(registration.IsValid());
    }

    EXPECT_FALSE(registration.IsValid());
    EXPECT_FALSE(registration.Reset());
}

TEST_F(DispatcherTest, SkipsRegistrationUnregisteredDuringDispatch) {
    UdpSocket socket;
    UnregisteringPacketCounter first;
    PacketCounter second;

    const auto first_registration =
        dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&UnregisteringPacketCounter::OnPacket>(&first));
    auto second_registration = dispatcher.Register(socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    first.registration_to_reset = &second_registration;

    Dispatch(socket.Fd(), MakePacket());

    EXPECT_EQ(first.count, 1);
    EXPECT_TRUE(first.reset_result);
    EXPECT_EQ(second.count, 0);
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DispatcherTest, PollOnceDispatchesPacket) {
    UdpSocket listener_socket;
    ASSERT_TRUE(listener_socket.SetReuseAddr(true));
    ASSERT_TRUE(listener_socket.Bind(IpAddress::Loopback(), 0));
    const auto listener_port = BoundPort(listener_socket);
    ASSERT_NE(listener_port, 0);

    PacketRecorder recorder;
    const auto registration = dispatcher.Register(listener_socket, PacketFilter{}, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    UdpSocket sender_socket;
    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::Loopback(), listener_port));

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(recorder.source_ip, IpAddress::Loopback());
}

TEST_F(DispatcherTest, PollOnceDispatchesLargePacket) {
    constexpr size_t LARGE_PAYLOAD_SIZE = 8 * 1024;
    UdpSocket listener_socket;
    ASSERT_TRUE(listener_socket.SetReuseAddr(true));
    ASSERT_TRUE(listener_socket.Bind(IpAddress::Loopback(), 0));
    const auto listener_port = BoundPort(listener_socket);
    ASSERT_NE(listener_port, 0);

    PacketRecorder recorder;
    const auto registration = dispatcher.Register(listener_socket, PacketFilter{}, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    std::vector<std::byte> payload(LARGE_PAYLOAD_SIZE);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = std::byte{static_cast<unsigned char>(i & 0xff)};
    }

    UdpSocket sender_socket;
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::Loopback(), listener_port));

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, payload);
    EXPECT_EQ(recorder.source_ip, IpAddress::Loopback());
}

TEST_F(DispatcherTest, PollOnceWithoutPacketReturnsFalse) {
    UdpSocket listener_socket;
    ASSERT_TRUE(listener_socket.SetReuseAddr(true));
    ASSERT_TRUE(listener_socket.Bind(IpAddress::Loopback(), 0));

    PacketCounter counter;
    const auto registration = dispatcher.Register(listener_socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, PollOnceDispatchesQueuedPacketBurst) {
    UdpSocket listener_socket;
    ASSERT_TRUE(listener_socket.SetReuseAddr(true));
    ASSERT_TRUE(listener_socket.Bind(IpAddress::Loopback(), 0));
    const auto listener_port = BoundPort(listener_socket);
    ASSERT_NE(listener_port, 0);

    PacketCounter counter;
    const auto registration = dispatcher.Register(listener_socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    UdpSocket sender_socket;
    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    constexpr int packet_count = 3;
    for (int i = 0; i < packet_count; ++i) {
        ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::Loopback(), listener_port));
    }

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(counter.count, packet_count);
}

} // namespace reflector
