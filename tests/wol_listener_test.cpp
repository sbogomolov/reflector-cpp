#include "reflector/wol_listener.h"

#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include "packet_helpers.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <string>
#include <vector>

namespace reflector {

class WolListenerTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, "", IpAddress::Family::V4};

    size_t DispatcherRegistrationCount() const {
        return DispatcherRegistrationCount(dispatcher);
    }

    size_t DispatcherRegistrationCount(const Dispatcher& inspected_dispatcher) const {
        return inspected_dispatcher.RegistrationCount();
    }

    size_t ListenerCount() const {
        return ListenerCount(listener);
    }

    size_t ListenerCount(const WolListener& inspected_listener) const {
        return inspected_listener.ListenerCount();
    }
};

class WolListenerPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family> {
protected:
    Dispatcher dispatcher;
    WolListener listener{dispatcher, "", GetParam()};

    size_t DispatcherRegistrationCount() const {
        return dispatcher.RegistrationCount();
    }

    size_t ListenerCount() const {
        return listener.ListenerCount();
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    WolListenerPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& info) -> std::string {
        return std::format("{}", info.param);
    });

TEST_P(WolListenerPerFamilyTest, RegisterCreatesSocketForPort) {
    PacketCounter counter;
    const auto port = FreeLoopbackPort(GetParam());

    const auto registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_P(WolListenerPerFamilyTest, UnregisterRemovesUnusedListener) {
    PacketCounter counter;
    const auto port = FreeLoopbackPort(GetParam());
    auto registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());

    EXPECT_EQ(ListenerCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_P(WolListenerPerFamilyTest, RegistrationsShareSocket) {
    PacketCounter first;
    PacketCounter second;
    const auto port = FreeLoopbackPort(GetParam());

    const auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));

    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());
    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_P(WolListenerPerFamilyTest, DifferentPortsCreateSeparateSockets) {
    PacketCounter counter;
    const auto ports = FreeLoopbackPorts(2, GetParam());

    const auto first = listener.Register(ports[0], CreateDelegate<&PacketCounter::OnPacket>(&counter));
    const auto second = listener.Register(ports[1], CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(first.IsValid());
    ASSERT_TRUE(second.IsValid());
    EXPECT_EQ(ListenerCount(), 2);
    EXPECT_EQ(DispatcherRegistrationCount(), 2);
}

TEST_P(WolListenerPerFamilyTest, RegisteredCallbackReceivesPacket) {
    const auto port = FreeLoopbackPort(GetParam());
    ASSERT_NE(port, 0);

    PacketRecorder recorder;
    const auto registration = listener.Register(port, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    UdpSocket sender{GetParam()};
    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(sender.SendTo(payload, LoopbackFor(GetParam()), port));

    ASSERT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(recorder.source_ip, LoopbackFor(GetParam()));
}

TEST_F(WolListenerTest, RegistrationInvalidAfterListenerDestroyed) {
    WolListener::Registration registration;
    PacketCounter counter;

    {
        WolListener scoped_listener{dispatcher, "", IpAddress::Family::V4};
        registration = scoped_listener.Register(
            FreeLoopbackPort(IpAddress::Family::V4), CreateDelegate<&PacketCounter::OnPacket>(&counter));
        ASSERT_TRUE(registration.IsValid());
        EXPECT_EQ(DispatcherRegistrationCount(), 1);
    }

    EXPECT_EQ(DispatcherRegistrationCount(), 0);
    EXPECT_FALSE(registration.IsValid());
    EXPECT_FALSE(registration.Reset());
}

TEST_F(WolListenerTest, RegistrationInvalidAfterDispatcherDestroyedBeforeListener) {
    WolListener::Registration registration;
    PacketCounter counter;
    std::unique_ptr<WolListener> scoped_listener;

    {
        Dispatcher scoped_dispatcher;
        scoped_listener = std::make_unique<WolListener>(scoped_dispatcher, "", IpAddress::Family::V4);
        registration = scoped_listener->Register(
            FreeLoopbackPort(IpAddress::Family::V4), CreateDelegate<&PacketCounter::OnPacket>(&counter));
        ASSERT_TRUE(registration.IsValid());
        EXPECT_EQ(DispatcherRegistrationCount(scoped_dispatcher), 1);
        EXPECT_EQ(ListenerCount(*scoped_listener), 1);
    }

    EXPECT_FALSE(registration.IsValid());
    EXPECT_TRUE(registration.Reset());
    EXPECT_EQ(ListenerCount(*scoped_listener), 0);

    scoped_listener.reset();
    EXPECT_FALSE(registration.Reset());
}

TEST_F(WolListenerTest, UnregisterKeepsSharedListener) {
    PacketCounter first;
    PacketCounter second;
    const auto port = FreeLoopbackPort(IpAddress::Family::V4);
    auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    EXPECT_TRUE(first_registration.Reset());

    EXPECT_EQ(ListenerCount(), 1);
    EXPECT_EQ(DispatcherRegistrationCount(), 1);
}

TEST_F(WolListenerTest, RejectsPortZero) {
    PacketCounter counter;

    const auto registration = listener.Register(0, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(ListenerCount(), 0);
    EXPECT_EQ(DispatcherRegistrationCount(), 0);
}

TEST_F(WolListenerTest, SharedListenerForwardsToAllRegistrations) {
    const auto port = FreeLoopbackPort(IpAddress::Family::V4);
    PacketCounter first;
    PacketCounter second;
    const auto first_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = listener.Register(port, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    UdpSocket sender{IpAddress::Family::V4};
    const std::array payload{std::byte{0xab}};
    ASSERT_TRUE(sender.SendTo(payload, IpAddress::LoopbackV4(), port));

    ASSERT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

} // namespace reflector
