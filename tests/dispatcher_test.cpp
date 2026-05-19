#include "reflector/dispatcher.h"
#include "reflector/packet_capture_socket.h"

#include "reflector/util/delegate.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>

namespace reflector {

class DispatcherTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;

    void Dispatch(const PacketCaptureSocket& socket, const Packet& packet) {
        dispatcher.DispatchPacket(socket, packet);
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

// Registers a second callback the first time it runs, then disables itself so subsequent
// dispatches don't keep adding more.
struct RegisteringPacketCounter {
    void OnPacket(const Packet&) {
        ++count;
        if (dispatcher != nullptr) {
            new_registration = dispatcher->Register(*socket, PacketFilter{},
                CreateDelegate<&PacketCounter::OnPacket>(target));
            dispatcher = nullptr;
        }
    }

    Dispatcher* dispatcher = nullptr;
    PacketCaptureSocket* socket = nullptr;
    PacketCounter* target = nullptr;
    Dispatcher::Registration new_registration;
    int count = 0;
};

TEST_F(DispatcherTest, RegistersCallback) {
    TestCaptureSocket capture;
    PacketCounter counter;

    const auto registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DispatcherTest, RegisterRejectsInvalidCaptureSocket) {
    auto invalid = PacketCaptureSocket::ForTesting("invalid", -1);
    PacketCounter counter;

    const auto registration = dispatcher.Register(
        invalid, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
}

TEST_F(DispatcherTest, DispatchesMatchingPacket) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, SourceFiltersRejectNonMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromV4Bytes(192, 0, 2, 10),
        .source_port = uint16_t{7},
    };
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 10), 9));
    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 11), 7));

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, SourceFiltersAcceptMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromV4Bytes(192, 0, 2, 10),
        .source_port = uint16_t{7},
    };
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 10), 7));

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, DestFilterRejectsNonMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_port = uint16_t{9}};
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket,
        MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/7));

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, DestFilterAcceptsMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_port = uint16_t{9}};
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket,
        MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/9));

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, MacFilterRequiresPacketMacToBePresent) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.source_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff")};
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    // Packet header has no source_mac set; filter requires one — must not match.
    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, SourceMacFilterMatchesEqualMac) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    PacketFilter filter{.source_mac = mac};
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    auto packet = MakePacket();
    packet.header.source_mac = mac;
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, DestMacFilterRejectsDifferentMac) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff")};
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    auto packet = MakePacket();
    packet.header.dest_mac = *MacAddress::FromString("11:22:33:44:55:66");
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, CombinedFilterRequiresAllFields) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    PacketFilter filter{
        .dest_ip = IpAddress::BroadcastV4(),
        .dest_port = uint16_t{9},
        .source_mac = mac,
    };
    const auto registration = dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    auto packet = MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), 12345, 9);
    packet.header.source_mac = mac;
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 1);

    packet.header.dest_port = 7;
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DispatcherTest, MultipleRegistrationsReceivePacket) {
    TestCaptureSocket capture;
    PacketCounter first;
    PacketCounter second;

    const auto first_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(RegistrationCount(), 2);
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

TEST_F(DispatcherTest, UnregisterRemovesCallback) {
    TestCaptureSocket capture;
    PacketCounter counter;
    auto registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());
    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_EQ(counter.count, 0);
}

TEST_F(DispatcherTest, PollOnceWithoutRegistrationsReturnsFalse) {
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
}

TEST_F(DispatcherTest, PollOnceWithoutPacketReturnsFalse) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    // The test pipe is never written to, so kqueue/epoll has nothing to deliver and
    // PollOnce returns false without invoking the callback.
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(counter.count, 0);
}

TEST(DispatcherRegistrationLifetimeTest, RegistrationInvalidAfterDispatcherDestroyed) {
    Dispatcher::Registration registration;
    TestCaptureSocket capture;
    PacketCounter counter;

    {
        Dispatcher dispatcher;
        registration = dispatcher.Register(
            capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
        ASSERT_TRUE(registration.IsValid());
    }

    EXPECT_FALSE(registration.IsValid());
    EXPECT_FALSE(registration.Reset());
}

TEST_F(DispatcherTest, SkipsRegistrationUnregisteredDuringDispatch) {
    TestCaptureSocket capture;
    UnregisteringPacketCounter first;
    PacketCounter second;

    const auto first_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&UnregisteringPacketCounter::OnPacket>(&first));
    auto second_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    first.registration_to_reset = &second_registration;

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(first.count, 1);
    EXPECT_TRUE(first.reset_result);
    EXPECT_EQ(second.count, 0);
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DispatcherTest, DispatchesToCallbackRegisteredDuringDispatch) {
    TestCaptureSocket capture;
    RegisteringPacketCounter first;
    PacketCounter second;
    first.dispatcher = &dispatcher;
    first.socket = &capture.socket;
    first.target = &second;

    const auto first_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&RegisteringPacketCounter::OnPacket>(&first));
    ASSERT_TRUE(first_registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(first.count, 1);
    ASSERT_TRUE(first.new_registration.IsValid());
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(RegistrationCount(), 2);
}

TEST_F(DispatcherTest, UnregisterPreservesOtherRegistrationOnSameSocket) {
    TestCaptureSocket capture;
    PacketCounter first;
    PacketCounter second;

    auto first_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    ASSERT_TRUE(first_registration.Reset());
    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(first.count, 0);
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(RegistrationCount(), 1);
}

} // namespace reflector
