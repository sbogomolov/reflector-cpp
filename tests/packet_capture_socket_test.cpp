#include "reflector/packet_capture_socket.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

class PacketCaptureSocketTest : public ::testing::Test {
protected:
    PacketCaptureSocket socket{PacketCaptureSocket::ForTesting("test", -1)};

#if defined(__APPLE__)
    using LinkType = PacketCaptureSocket::LinkType;
    void SetLinkType(LinkType link_type) noexcept { socket.link_type_ = link_type; }
#endif

    std::optional<Packet> Parse(std::span<const std::byte> frame) noexcept {
        return socket.ParseFrame(frame);
    }

    // Swallows logger output during the parse so failure-path tests stay quiet on stdout.
    std::optional<Packet> ParseQuietly(std::span<const std::byte> frame) {
        std::optional<Packet> result;
        (void)CaptureStdout([&] { result = socket.ParseFrame(frame); });
        return result;
    }
};

TEST_F(PacketCaptureSocketTest, ParsesEthernetIpv4Udp) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::FromV4Bytes(192, 0, 2, 1);
    const auto dst_ip = IpAddress::FromV4Bytes(192, 0, 2, 255);
    const auto payload = MakeBytes({0xde, 0xad, 0xbe, 0xef});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV4_ETHERTYPE);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
    f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source_ip, src_ip);
    EXPECT_EQ(packet->header.dest_ip, dst_ip);
    EXPECT_EQ(packet->header.source_port, 12345);
    EXPECT_EQ(packet->header.dest_port, 9);
    ASSERT_TRUE(packet->header.source_mac.has_value());
    EXPECT_EQ(*packet->header.source_mac, src_mac);
    ASSERT_TRUE(packet->header.dest_mac.has_value());
    EXPECT_EQ(*packet->header.dest_mac, dst_mac);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), payload);
}

TEST_F(PacketCaptureSocketTest, ParsesEthernetIpv6Udp) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::LoopbackV6();
    const auto dst_ip = IpAddress::AllNodesLinkLocalV6();
    const auto payload = MakeBytes({0x01, 0x02, 0x03});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV6_ETHERTYPE);
    f.AppendIPv6Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*payload_length=*/static_cast<uint16_t>(8 + payload.size()));
    f.AppendUdp(5353, 5353, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source_ip, src_ip);
    EXPECT_EQ(packet->header.dest_ip, dst_ip);
    EXPECT_EQ(packet->header.source_port, 5353);
    EXPECT_EQ(packet->header.dest_port, 5353);
    ASSERT_TRUE(packet->header.source_mac.has_value());
    EXPECT_EQ(*packet->header.source_mac, src_mac);
    ASSERT_TRUE(packet->header.dest_mac.has_value());
    EXPECT_EQ(*packet->header.dest_mac, dst_mac);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), payload);
}

// DLT_NULL is macOS-only — on Linux AF_PACKET delivers Ethernet frames for every
// interface, lo included, so the parser never encounters loopback framing there.
#if defined(__APPLE__)
TEST_F(PacketCaptureSocketTest, ParsesLoopbackIpv4UdpWithZeroMacs) {
    SetLinkType(LinkType::Loopback);
    const auto src_ip = IpAddress::LoopbackV4();
    const auto dst_ip = IpAddress::LoopbackV4();
    const auto payload = MakeBytes({0xff});

    FrameBuilder f;
    f.AppendLoopback(AF_INET);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
    f.AppendUdp(40000, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source_ip, src_ip);
    EXPECT_EQ(packet->header.dest_ip, dst_ip);
    EXPECT_EQ(packet->header.source_port, 40000);
    EXPECT_EQ(packet->header.dest_port, 9);
    ASSERT_TRUE(packet->header.source_mac.has_value());
    EXPECT_EQ(*packet->header.source_mac, MacAddress{});
    ASSERT_TRUE(packet->header.dest_mac.has_value());
    EXPECT_EQ(*packet->header.dest_mac, MacAddress{});
}

TEST_F(PacketCaptureSocketTest, ParsesLoopbackIpv6Udp) {
    SetLinkType(LinkType::Loopback);
    const auto src_ip = IpAddress::LoopbackV6();
    const auto dst_ip = IpAddress::LoopbackV6();
    const auto payload = MakeBytes({0x10, 0x20});

    FrameBuilder f;
    f.AppendLoopback(AF_INET6);
    f.AppendIPv6Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*payload_length=*/static_cast<uint16_t>(8 + payload.size()));
    f.AppendUdp(1234, 5678, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source_ip, src_ip);
    EXPECT_EQ(packet->header.dest_ip, dst_ip);
    EXPECT_EQ(packet->header.source_port, 1234);
    EXPECT_EQ(packet->header.dest_port, 5678);
}
#endif  // defined(__APPLE__)

TEST_F(PacketCaptureSocketTest, TrimsPayloadToUdpLength) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::FromV4Bytes(10, 0, 0, 1);
    const auto dst_ip = IpAddress::FromV4Bytes(10, 0, 0, 2);
    const auto declared = MakeBytes({0xaa, 0xbb});
    const auto trailer = MakeBytes({0xcc, 0xdd, 0xee});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV4_ETHERTYPE);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + declared.size() + trailer.size()));
    f.AppendUdp(1, 2, static_cast<uint16_t>(8 + declared.size()));
    f.AppendPayload(declared);
    f.AppendPayload(trailer);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), declared);
}

TEST_F(PacketCaptureSocketTest, RejectsFrameShorterThanEthernetHeader) {
    const auto frame = MakeBytes({0x00, 0x01, 0x02});

    EXPECT_FALSE(ParseQuietly(frame).has_value());
}

#if defined(__APPLE__)
TEST_F(PacketCaptureSocketTest, RejectsFrameShorterThanLoopbackHeader) {
    SetLinkType(LinkType::Loopback);
    const auto frame = MakeBytes({0x02, 0x00});

    EXPECT_FALSE(ParseQuietly(frame).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsLoopbackWithUnsupportedFamily) {
    SetLinkType(LinkType::Loopback);
    FrameBuilder f;
    f.AppendLoopback(/*AF_UNIX-ish*/ 1);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}
#endif  // defined(__APPLE__)

TEST_F(PacketCaptureSocketTest, RejectsUnknownEthertype) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, ARP_ETHERTYPE);
    f.bytes.resize(64, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4FrameTruncatedBeforeHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.bytes.insert(f.bytes.end(), 10, std::byte{0});  // only 10 bytes of IP, need 20

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4WithWrongVersion) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, 8);
    f.bytes[14] = std::byte{(6u << 4) | 5u};  // version=6, IHL=5

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4WithIhlTooSmall) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, 8);
    f.bytes[14] = std::byte{(4u << 4) | 4u};  // IHL=4 → 16-byte header, below minimum

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4FragmentWithMfFlag) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP,
        /*total_length=*/28, /*flags_fragment=*/0x2000);  // MF set
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4FragmentWithNonZeroOffset) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP,
        /*total_length=*/28, /*flags_fragment=*/0x0001);  // offset=1
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4NonUdpProtocol) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), /*protocol=*/6 /*TCP*/, 28);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv6WithWrongVersion) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP,
        /*payload_length=*/8, /*version=*/4);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv6ExtensionHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IPV6_NEXT_HOPOPT,
        /*payload_length=*/16);
    f.bytes.insert(f.bytes.end(), 16, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsFrameTruncatedBeforeUdpHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/24);
    f.bytes.insert(f.bytes.end(), 4, std::byte{0});  // only 4 of the 8 UDP-header bytes

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsUdpLengthBelowHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/4);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsUdpLengthExceedingL4Size) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/64);  // claims much more than actually present

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4TotalLengthBelowHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/10);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv4TotalLengthExceedingCapturedFrame) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/200);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

// total_length=28 declares only the UDP header (20 + 8); udp_length=20 claims 12 bytes
// of data the IP datagram says don't exist. Twelve trailing Ethernet-pad bytes follow.
// Without trimming l4 by total_length the parser would extract those 12 padding bytes
// as the UDP payload.
TEST_F(PacketCaptureSocketTest, RejectsIpv4UdpLengthExceedingIpDatagram) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/20);
    f.bytes.resize(f.bytes.size() + 12, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(PacketCaptureSocketTest, RejectsIpv6PayloadLengthExceedingCapturedFrame) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP, /*payload_length=*/200);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

// Mirror of RejectsIpv4UdpLengthExceedingIpDatagram for IPv6: payload_length=8 covers
// just the UDP header, udp_length=20 claims 12 bytes that aren't in the IPv6 payload.
TEST_F(PacketCaptureSocketTest, RejectsIpv6UdpLengthExceedingIpDatagram) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP, /*payload_length=*/8);
    f.AppendUdp(1, 2, /*udp_length=*/20);
    f.bytes.resize(f.bytes.size() + 12, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

#if defined(__APPLE__)
// Packs N bpf_hdr-prefixed frames into a single batch (one read returns all of them),
// then verifies Receive() walks them one at a time. Mirrors what
// PacketCaptureSocketRequiresRootTest::DrainsBatchedFramesFromOneRead exercises against
// real BPF + loopback, but without needing capture privileges — the test stages bytes
// directly via TestCaptureSocket::WriteFrameBatch.
TEST(PacketCaptureSocketBatchTest, ReceiveWalksMultiFrameBpfBatch) {
    TestCaptureSocket capture;
    constexpr int frame_count = 4;
    const auto payload = MakeBytes({0xab, 0xcd});

    std::vector<std::vector<std::byte>> frame_storage;
    std::vector<std::span<const std::byte>> frame_spans;
    frame_storage.reserve(frame_count);
    frame_spans.reserve(frame_count);
    for (int i = 0; i < frame_count; ++i) {
        FrameBuilder f;
        f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
        f.AppendIPv4Header(IpAddress::FromV4Bytes(192, 0, 2, 1), IpAddress::BroadcastV4(),
            IP_PROTO_UDP, /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
        f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
        f.AppendPayload(payload);
        frame_storage.push_back(std::move(f.bytes));
        frame_spans.emplace_back(frame_storage.back());
    }
    ASSERT_TRUE(capture.WriteFrameBatch(frame_spans));

    int received = 0;
    bool observed_buffered = false;
    for (int i = 0; i < frame_count; ++i) {
        const auto packet = capture.socket.Receive();
        ASSERT_TRUE(packet.has_value()) << "missing packet " << (i + 1);
        ++received;
        if (capture.socket.HasBufferedData()) {
            observed_buffered = true;
        }
    }

    EXPECT_EQ(received, frame_count);
    EXPECT_TRUE(observed_buffered)
        << "Expected the buffer walker to leave bytes between frames — got single-frame reads";
    EXPECT_FALSE(capture.socket.Receive().has_value())
        << "Expected no more frames after draining the batch";
}
#endif  // defined(__APPLE__)

} // namespace reflector
