#include "reflector/packet_capture_socket.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

namespace {

constexpr uint16_t IPV4_ETHERTYPE = 0x0800;
constexpr uint16_t IPV6_ETHERTYPE = 0x86dd;
constexpr uint16_t ARP_ETHERTYPE = 0x0806;
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr uint8_t IPV6_NEXT_HOPOPT = 0;

void AppendBytes(std::vector<std::byte>& out, std::span<const std::byte> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendU16Be(std::vector<std::byte>& out, uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

void AppendIpv4(std::vector<std::byte>& out, const IpAddress& ip) {
    AppendBytes(out, std::span{ip.Bytes().data(), 4});
}

void AppendIpv6(std::vector<std::byte>& out, const IpAddress& ip) {
    AppendBytes(out, ip.Bytes());
}

void AppendMac(std::vector<std::byte>& out, const MacAddress& mac) {
    AppendBytes(out, mac.Bytes());
}

std::vector<std::byte> MakeBytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value & 0xff));
    }
    return bytes;
}

struct FrameBuilder {
    std::vector<std::byte> bytes;

    void AppendEthernet(const MacAddress& dst, const MacAddress& src, uint16_t ethertype) {
        AppendMac(bytes, dst);
        AppendMac(bytes, src);
        AppendU16Be(bytes, ethertype);
    }

    void AppendLoopback(uint32_t family) {
        std::byte buf[4];
        std::memcpy(buf, &family, sizeof(family));
        AppendBytes(bytes, std::span{buf, 4});
    }

    void AppendIPv4Header(const IpAddress& src, const IpAddress& dst, uint8_t protocol,
        uint16_t total_length, uint16_t flags_fragment = 0, uint8_t ihl_words = 5) {
        bytes.push_back(static_cast<std::byte>((4u << 4) | (ihl_words & 0x0f))); // version+IHL
        bytes.push_back(std::byte{0x00});                                         // DSCP/ECN
        AppendU16Be(bytes, total_length);                                         // total length
        AppendU16Be(bytes, 0);                                                    // identification
        AppendU16Be(bytes, flags_fragment);                                       // flags + fragment offset
        bytes.push_back(std::byte{64});                                           // TTL
        bytes.push_back(static_cast<std::byte>(protocol));                        // protocol
        AppendU16Be(bytes, 0);                                                    // header checksum (ignored)
        AppendIpv4(bytes, src);
        AppendIpv4(bytes, dst);
        // Pad to ihl_words * 4 bytes if requested IHL is larger than the minimum 20.
        const size_t want = static_cast<size_t>(ihl_words) * 4;
        const size_t have = 20;
        if (want > have) {
            bytes.insert(bytes.end(), want - have, std::byte{0});
        }
    }

    void AppendIPv6Header(const IpAddress& src, const IpAddress& dst, uint8_t next_header,
        uint16_t payload_length, uint8_t version = 6) {
        bytes.push_back(static_cast<std::byte>(version << 4));                    // version + traffic class hi
        bytes.push_back(std::byte{0x00});                                         // traffic class lo + flow hi
        AppendU16Be(bytes, 0);                                                    // flow lo
        AppendU16Be(bytes, payload_length);                                       // payload length
        bytes.push_back(static_cast<std::byte>(next_header));                     // next header
        bytes.push_back(std::byte{64});                                           // hop limit
        AppendIpv6(bytes, src);
        AppendIpv6(bytes, dst);
    }

    void AppendUdp(uint16_t src_port, uint16_t dst_port, uint16_t udp_length) {
        AppendU16Be(bytes, src_port);
        AppendU16Be(bytes, dst_port);
        AppendU16Be(bytes, udp_length);
        AppendU16Be(bytes, 0); // checksum (ignored)
    }

    void AppendPayload(std::span<const std::byte> payload) {
        AppendBytes(bytes, payload);
    }
};

} // namespace

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

} // namespace reflector
