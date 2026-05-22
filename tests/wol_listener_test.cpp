#include "reflector/wol_listener.h"

#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <cstddef>

namespace reflector {

class WolListenerTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;
    PacketDispatcher packet_dispatcher{dispatcher};
    TestCaptureSocket capture;
    WolListener listener{packet_dispatcher, capture.socket};

    size_t DispatcherRegistrationCount() const {
        return DispatcherRegistrationCount(packet_dispatcher);
    }

    size_t DispatcherRegistrationCount(const PacketDispatcher& inspected_packet_dispatcher) const {
        return inspected_packet_dispatcher.RegistrationCount();
    }

    size_t RegistrationCount() const {
        return listener.RegistrationCount();
    }

    void Dispatch(const Packet& packet) {
        packet_dispatcher.DispatchPacket(capture.socket, packet);
    }
};

TEST_F(WolListenerTest, RegisterCreatesDispatcherRegistration) {
    PacketCounter counter;

    const auto registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_F(WolListenerTest, UnregisterRemovesDispatcherRegistration) {
    PacketCounter counter;
    auto registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());

    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolListenerTest, MultipleRegistrationsForSamePort) {
    PacketCounter first;
    PacketCounter second;

    const auto first_registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&second));

    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_F(WolListenerTest, DifferentPortsTrackedSeparately) {
    PacketCounter counter;

    const auto first = listener.Register(7, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    const auto second = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(first.IsValid());
    ASSERT_TRUE(second.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_F(WolListenerTest, RegisteredCallbackReceivesMatchingPort) {
    PacketRecorder recorder;
    const auto registration = listener.Register(9, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/9));

    EXPECT_EQ(recorder.count, 1);
}

TEST_F(WolListenerTest, RegisteredCallbackIgnoresOtherPort) {
    PacketRecorder recorder;
    const auto registration = listener.Register(9, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/7));

    EXPECT_EQ(recorder.count, 0);
}

TEST_F(WolListenerTest, RegistrationInvalidAfterListenerDestroyed) {
    WolListener::Registration registration;
    PacketCounter counter;

    {
        WolListener scoped_listener{packet_dispatcher, capture.socket};
        registration = scoped_listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&counter));
        ASSERT_TRUE(registration.IsValid());
        EXPECT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
    EXPECT_FALSE(registration.IsValid());
    EXPECT_FALSE(registration.Reset());
}

TEST_F(WolListenerTest, RejectsPortZero) {
    PacketCounter counter;

    const auto registration = listener.Register(0, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolListenerTest, SameRegistrationForwardsToBothCallbacks) {
    PacketCounter first;
    PacketCounter second;
    const auto first_registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(9, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    Dispatch(MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/9));

    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

} // namespace reflector
