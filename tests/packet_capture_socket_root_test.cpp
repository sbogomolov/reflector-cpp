#include "reflector/packet_capture_socket.h"

#include "reflector/ip_address.h"
#include "reflector/packet.h"
#include "reflector/udp_socket.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <poll.h>
#include <span>
#include <vector>

namespace reflector {

namespace {

constexpr auto WAIT_BUDGET = std::chrono::milliseconds{2000};
constexpr auto POLL_SLICE_MS = 100;

} // namespace

class PacketCaptureSocketRequiresRootTest : public ::testing::Test {
protected:
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

    // The loopback interface carries unrelated UDP traffic too; drain Receive() until we
    // see one matching our test's dest_port or the budget is exhausted. Uses poll() between
    // EAGAIN returns to avoid spinning.
    std::optional<Packet> ReceiveOurDatagram(std::chrono::milliseconds budget = WAIT_BUDGET) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            auto packet = capture->Receive();
            if (packet) {
                if (packet->header.dest_port == listener_port
                        && packet->header.dest_ip == IpAddress::LoopbackV4()) {
                    return packet;
                }
                continue;
            }
            pollfd pfd{.fd = capture->Fd(), .events = POLLIN, .revents = 0};
            ::poll(&pfd, 1, POLL_SLICE_MS);
        }
        return std::nullopt;
    }
};

TEST_F(PacketCaptureSocketRequiresRootTest, ReceivesLoopbackUdpDatagram) {
    const std::array payload{std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));

    const auto packet = ReceiveOurDatagram();
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source_ip, IpAddress::LoopbackV4());
    EXPECT_EQ(packet->header.dest_ip, IpAddress::LoopbackV4());
    EXPECT_EQ(packet->header.dest_port, listener_port);
    EXPECT_NE(packet->header.source_port, 0);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()),
        std::vector<std::byte>(payload.begin(), payload.end()));
}

// Sends a burst of datagrams faster than we drain so the kernel batches multiple
// bpf_hdr-prefixed frames into one read(). On macOS, asserts that at least one Receive()
// left userland-buffered data behind — that's the only direct coverage of the multi-frame
// walk in Receive(). On Linux this just verifies the burst is delivered (AF_PACKET has no
// userland buffering, so the walk doesn't apply).
TEST_F(PacketCaptureSocketRequiresRootTest, DrainsBatchedFramesFromOneRead) {
    constexpr int packet_count = 8;
    const std::array payload{std::byte{0xab}, std::byte{0xcd}};
    for (int i = 0; i < packet_count; ++i) {
        ASSERT_TRUE(sender_socket.SendTo(payload, IpAddress::LoopbackV4(), listener_port));
    }

#if defined(__APPLE__)
    bool observed_buffered_read = false;
#endif
    for (int i = 0; i < packet_count; ++i) {
        const auto packet = ReceiveOurDatagram();
        ASSERT_TRUE(packet.has_value()) << "missing packet " << (i + 1);
#if defined(__APPLE__)
        if (capture->HasBufferedData()) {
            observed_buffered_read = true;
        }
#endif
    }

#if defined(__APPLE__)
    EXPECT_TRUE(observed_buffered_read)
        << "Expected at least one Receive() to leave userland-buffered data behind — "
           "the macOS multi-frame BPF batch walk was not exercised";
#endif
}

} // namespace reflector
