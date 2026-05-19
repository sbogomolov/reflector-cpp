#include "reflector/dispatcher.h"
#include "reflector/ip_address.h"
#include "reflector/packet.h"
#include "reflector/packet_capture_socket.h"
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
#include <span>
#include <vector>

namespace reflector {

namespace {

constexpr auto WAIT_BUDGET = std::chrono::milliseconds{2000};
constexpr auto POLL_SLICE = std::chrono::milliseconds{100};

} // namespace

class DispatcherRequiresRootTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;
    std::optional<PacketCaptureSocket> capture;
    UdpSocket listener_socket{IpAddress::Family::V4};
    uint16_t listener_port = 0;
    UdpSocket sender_socket{IpAddress::Family::V4};

    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "PacketCaptureSocket on " << LoopbackInterface()
                << " requires CAP_NET_RAW (Linux) or bpf group / root (macOS)";
        }
        capture.emplace(LoopbackInterface());
        ASSERT_TRUE(capture->IsValid());
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

TEST_F(DispatcherRequiresRootTest, PollOnceDispatchesLoopbackPacket) {
    PacketRecorder recorder;
    const auto registration = dispatcher.Register(*capture, LoopbackFilter(),
        CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
    ASSERT_TRUE(registration.IsValid());

    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));

    ASSERT_TRUE(WaitForCount(recorder.count, 1));
    EXPECT_EQ(recorder.count, 1);
    EXPECT_EQ(recorder.payload, std::vector<std::byte>(payload.begin(), payload.end()));
    EXPECT_EQ(recorder.source_ip, IpAddress::LoopbackV4());
}

TEST_F(DispatcherRequiresRootTest, PollOnceDispatchesQueuedPacketBurst) {
    PacketCounter counter;
    const auto registration = dispatcher.Register(*capture, LoopbackFilter(),
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

struct UnregisteringPacketCounter {
    void OnPacket(const Packet&) {
        ++count;
        if (registration_to_reset != nullptr && registration_to_reset->IsValid()) {
            registration_to_reset->Reset();
        }
    }

    Dispatcher::Registration* registration_to_reset = nullptr;
    int count = 0;
};

TEST_F(DispatcherRequiresRootTest, DrainStopsWhenCallbackResetsLastRegistration) {
    UnregisteringPacketCounter counter;
    auto registration = dispatcher.Register(*capture, LoopbackFilter(),
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
