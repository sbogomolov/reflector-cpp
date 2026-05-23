#include "reflector/default_packet_dispatcher.h"

#include "reflector/event_loop_dispatcher.h"
#include "reflector/ip_address.h"
#include "reflector/packet.h"
#include "reflector/raw_socket.h"
#include "reflector/udp_socket.h"

#include "reflector/util/delegate.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

constexpr auto WAIT_BUDGET = std::chrono::milliseconds{2000};
constexpr auto POLL_SLICE = std::chrono::milliseconds{100};

} // namespace

namespace reflector {

class DefaultPacketDispatcherTest : public ::testing::Test {
protected:
    EventLoopDispatcher dispatcher;
    DefaultPacketDispatcher packet_dispatcher{dispatcher};

    void Dispatch(const RawSocket& socket, const Packet& packet) {
        packet_dispatcher.DispatchPacket(socket, packet);
    }

    size_t RegistrationCount() const {
        return packet_dispatcher.RegistrationCount();
    }
};

// Registers a second callback the first time it runs, then disables itself so subsequent
// dispatches don't keep adding more.
struct RegisteringPacketCounter {
    void OnPacket(const Packet&) {
        ++count;
        if (packet_dispatcher != nullptr) {
            new_registration = packet_dispatcher->Register(*socket, PacketFilter{},
                CreateDelegate<&PacketCounter::OnPacket>(target));
            packet_dispatcher = nullptr;
        }
    }

    DefaultPacketDispatcher* packet_dispatcher = nullptr;
    RawSocket* socket = nullptr;
    PacketCounter* target = nullptr;
    PacketDispatcher::Registration new_registration;
    int count = 0;
};

TEST_F(DefaultPacketDispatcherTest, RegistersCallback) {
    TestCaptureSocket capture;
    PacketCounter counter;

    const auto registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DefaultPacketDispatcherTest, RegisterRejectsInvalidCaptureSocket) {
    auto invalid = RawSocket::ForTesting("invalid", -1);
    PacketCounter counter;

    const auto registration = packet_dispatcher.Register(
        invalid, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
}

TEST_F(DefaultPacketDispatcherTest, DispatchesMatchingPacket) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DefaultPacketDispatcherTest, SourceFiltersRejectNonMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromV4Bytes(192, 0, 2, 10),
        .source_port = uint16_t{7},
    };
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 10), 9));
    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 11), 7));

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DefaultPacketDispatcherTest, SourceFiltersAcceptMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{
        .source_ip = IpAddress::FromV4Bytes(192, 0, 2, 10),
        .source_port = uint16_t{7},
    };
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket, MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 10), 7));

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DefaultPacketDispatcherTest, DestFilterRejectsNonMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_port = uint16_t{9}};
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket,
        MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/7));

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DefaultPacketDispatcherTest, DestFilterAcceptsMatchingPackets) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_port = uint16_t{9}};
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    Dispatch(capture.socket,
        MakePacket(IpAddress::FromV4Bytes(192, 0, 2, 1), /*source_port=*/12345, /*dest_port=*/9));

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DefaultPacketDispatcherTest, SourceMacFilterMatchesEqualMac) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    PacketFilter filter{.source_mac = mac};
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    auto packet = MakePacket();
    packet.header.source_mac = mac;
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 1);
}

TEST_F(DefaultPacketDispatcherTest, DestMacFilterRejectsDifferentMac) {
    TestCaptureSocket capture;
    PacketCounter counter;
    PacketFilter filter{.dest_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff")};
    const auto registration = packet_dispatcher.Register(
        capture.socket, filter, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    auto packet = MakePacket();
    packet.header.dest_mac = *MacAddress::FromString("11:22:33:44:55:66");
    Dispatch(capture.socket, packet);

    EXPECT_EQ(counter.count, 0);
}

TEST_F(DefaultPacketDispatcherTest, CombinedFilterRequiresAllFields) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    PacketFilter filter{
        .dest_ip = IpAddress::BroadcastV4(),
        .dest_port = uint16_t{9},
        .source_mac = mac,
    };
    const auto registration = packet_dispatcher.Register(
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

TEST_F(DefaultPacketDispatcherTest, MultipleRegistrationsReceivePacket) {
    TestCaptureSocket capture;
    PacketCounter first;
    PacketCounter second;

    const auto first_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(RegistrationCount(), 2);
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 1);
}

TEST_F(DefaultPacketDispatcherTest, UnregisterRemovesCallback) {
    TestCaptureSocket capture;
    PacketCounter counter;
    auto registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());
    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_EQ(counter.count, 0);
}

TEST_F(DefaultPacketDispatcherTest, SkipsRegistrationUnregisteredDuringDispatch) {
    TestCaptureSocket capture;
    UnregisteringPacketCounter first;
    PacketCounter second;

    const auto first_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&UnregisteringPacketCounter::OnPacket>(&first));
    auto second_registration = packet_dispatcher.Register(
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

TEST_F(DefaultPacketDispatcherTest, DispatchesToCallbackRegisteredDuringDispatch) {
    TestCaptureSocket capture;
    RegisteringPacketCounter first;
    PacketCounter second;
    first.packet_dispatcher = &packet_dispatcher;
    first.socket = &capture.socket;
    first.target = &second;

    const auto first_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&RegisteringPacketCounter::OnPacket>(&first));
    ASSERT_TRUE(first_registration.IsValid());

    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(first.count, 1);
    ASSERT_TRUE(first.new_registration.IsValid());
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(RegistrationCount(), 2);
}

TEST_F(DefaultPacketDispatcherTest, UnregisterPreservesOtherRegistrationOnSameSocket) {
    TestCaptureSocket capture;
    PacketCounter first;
    PacketCounter second;

    auto first_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&first));
    const auto second_registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());

    ASSERT_TRUE(first_registration.Reset());
    Dispatch(capture.socket, MakePacket());

    EXPECT_EQ(first.count, 0);
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(DefaultPacketDispatcherTest, PollOnceWithoutPacketReturnsFalse) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto registration = packet_dispatcher.Register(
        capture.socket, PacketFilter{}, CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    // The test pipe is never written to, so kqueue/epoll has nothing to deliver and
    // PollOnce returns false without invoking the callback.
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(counter.count, 0);
}

// Drives an Ethernet/IPv4/UDP frame through TestCaptureSocket's socketpair so that
// dispatcher.PollOnce wakes via kqueue/epoll, invokes the per-fd callback,
// DefaultPacketDispatcher drains the socket, ParseFrame decodes the frame, and DispatchPacket
// invokes the subscriber. Exercises the full receive path on both macOS (bpf_hdr-prefixed)
// and Linux (raw bytes) without needing capture privileges or real loopback traffic.
TEST_F(DefaultPacketDispatcherTest, PollOnceDispatchesFrameWrittenToTestSocket) {
    TestCaptureSocket capture;
    PacketRecorder recorder;
    const auto registration = packet_dispatcher.Register(capture.socket,
        PacketFilter{.dest_port = uint16_t{9}},
        CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::FromV4Bytes(192, 0, 2, 1);
    const auto dst_ip = IpAddress::BroadcastV4();
    const auto payload = MakeBytes({0xde, 0xad, 0xbe, 0xef});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV4_ETHERTYPE);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
    f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    ASSERT_TRUE(capture.WriteFrame(f.bytes));

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, payload);
    EXPECT_EQ(recorder.source_ip, src_ip);
}

TEST_F(DefaultPacketDispatcherTest, DispatchesNothingForUnparseableFrame) {
    TestCaptureSocket capture;
    PacketCounter counter;
    const auto registration = packet_dispatcher.Register(capture.socket, PacketFilter{},
        CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    // Three bytes — shorter than the 14-byte Ethernet header, so ParseFrame rejects.
    ASSERT_TRUE(capture.WriteFrame(MakeBytes({0x00, 0x01, 0x02})));

    bool poll_result = false;
    const auto output = CaptureStdout([&] {
        poll_result = dispatcher.PollOnce(std::chrono::milliseconds{100});
    });
    // The fd was readable, so PollOnce serviced it (returns true); the frame just yielded no
    // dispatchable packet.
    EXPECT_TRUE(poll_result) << output;
    EXPECT_EQ(counter.count, 0);
}

class DefaultPacketDispatcherRequiresRootTest : public ::testing::Test {
protected:
    EventLoopDispatcher dispatcher;
    DefaultPacketDispatcher packet_dispatcher{dispatcher};
    std::optional<RawSocket> socket;
    UdpSocket listener_socket{IpAddress::Family::V4};
    uint16_t listener_port = 0;
    UdpSocket sender_socket{IpAddress::Family::V4};

    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "RawSocket on " << LoopbackInterface()
                << " requires CAP_NET_RAW (Linux) or bpf group / root (macOS)";
        }
        socket.emplace(LoopbackInterface());
        ASSERT_TRUE(socket->IsValid());
        listener_port = BindLoopback(listener_socket);
    }

    PacketFilter LoopbackFilter() const {
        return PacketFilter{
            .dest_ip = IpAddress::LoopbackV4(),
            .dest_port = listener_port,
        };
    }

    // PollOnce in a loop until `target` reaches `at_least` or the budget is exhausted.
    // The shared loopback interface can carry unrelated UDP noise — using a single
    // long-timeout PollOnce would wake on the first such frame and miss ours.
    bool WaitForCount(const int& target, int at_least,
        std::chrono::milliseconds budget = WAIT_BUDGET) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (target < at_least) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (remaining <= std::chrono::milliseconds{0}) {
                return false;
            }
            dispatcher.PollOnce(std::min(remaining, POLL_SLICE));
        }
        return true;
    }
};

TEST_F(DefaultPacketDispatcherRequiresRootTest, PollOnceDispatchesLoopbackPacket) {
    PacketRecorder recorder;
    const auto registration = packet_dispatcher.Register(*socket, LoopbackFilter(),
        CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));

    ASSERT_TRUE(WaitForCount(recorder.count, 1));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(recorder.source_ip, IpAddress::LoopbackV4());
}

TEST_F(DefaultPacketDispatcherRequiresRootTest, PollOnceDispatchesQueuedPacketBurst) {
    PacketCounter counter;
    const auto registration = packet_dispatcher.Register(*socket, LoopbackFilter(),
        CreateDelegate<&PacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());

    constexpr int packet_count = 3;
    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    for (int i = 0; i < packet_count; ++i) {
        ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));
    }

    ASSERT_TRUE(WaitForCount(counter.count, packet_count));
    EXPECT_EQ(counter.count, packet_count);
}

TEST_F(DefaultPacketDispatcherRequiresRootTest, DrainStopsWhenCallbackResetsLastRegistration) {
    UnregisteringPacketCounter counter;
    auto registration = packet_dispatcher.Register(*socket, LoopbackFilter(),
        CreateDelegate<&UnregisteringPacketCounter::OnPacket>(&counter));
    ASSERT_TRUE(registration.IsValid());
    counter.registration_to_reset = &registration;

    const std::array payload{std::byte{0x01}};
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));

    ASSERT_TRUE(WaitForCount(counter.count, 1));
    EXPECT_EQ(counter.count, 1);
    EXPECT_FALSE(registration.IsValid());
}

} // namespace reflector
