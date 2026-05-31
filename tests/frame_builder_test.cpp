#include "reflector/frame_builder.h"

#include "reflector/checksum.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/util/byte_order.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <sys/socket.h>
#include <vector>

using namespace reflector;

namespace {

MacAddress Mac(std::array<int, 6> octets) {
    MacAddress::ByteArray bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>(octets[i]);
    }
    return MacAddress{bytes};
}

} // namespace

TEST(MulticastMacForTest, Ipv4Multicast) {
    EXPECT_EQ(MulticastMacFor(*IpAddress::FromString("224.0.0.251")), Mac({0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}));
    // 239.255.255.250 (SSDP): only the low 23 bits map, so 0xef -> top bit dropped in byte 1.
    EXPECT_EQ(MulticastMacFor(*IpAddress::FromString("239.255.255.250")), Mac({0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}));
}

TEST(BroadcastMacTest, IsAllOnes) {
    EXPECT_EQ(BroadcastMac(), Mac({0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
}

TEST(MulticastMacForTest, Ipv6Multicast) {
    EXPECT_EQ(MulticastMacFor(*IpAddress::FromString("ff02::fb")), Mac({0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}));
    EXPECT_EQ(MulticastMacFor(*IpAddress::FromString("ff02::1")), Mac({0x33, 0x33, 0x00, 0x00, 0x00, 0x01}));
}

TEST(FrameBuilderTest, ReturnsZeroWhenBufferTooSmall) {
    const auto src_ip = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const auto dst_ip = *IpAddress::FromString("224.0.0.251");
    std::array<std::byte, 8> buffer{};  // far smaller than a 14+20+8 frame
    EXPECT_EQ(
        BuildUdpFrame(MulticastMacFor(dst_ip), MacAddress{}, src_ip, dst_ip, 5353, 5353, {}, 255, buffer),
        0u);
}

// A datagram whose length can't fit the protocol's 16-bit length field yields no frame. The
// ceiling differs by family: IPv4's total_length counts the 20-byte IP header (payload <= 65507),
// while IPv6's only field is the UDP length (payload <= 65527). The overflow is rejected before
// the buffer-size check, so the output buffer size is irrelevant here.
TEST(FrameBuilderTest, ReturnsZeroWhenDatagramOverflowsLengthField) {
    std::array<std::byte, 64> buffer{};

    const auto v4_src = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const auto v4_dst = *IpAddress::FromString("224.0.0.251");
    const std::vector<std::byte> v4_payload(65508);  // 20 + 8 + 65508 = 65536, one past the limit
    EXPECT_EQ(
        BuildUdpFrame(MulticastMacFor(v4_dst), MacAddress{}, v4_src, v4_dst, 5353, 5353, v4_payload, 255, buffer),
        0u);

    const auto v6_src = *IpAddress::FromString("fe80::1");
    const auto v6_dst = *IpAddress::FromString("ff02::fb");
    const std::vector<std::byte> v6_payload(65528);  // 8 + 65528 = 65536, one past the limit
    EXPECT_EQ(
        BuildUdpFrame(MulticastMacFor(v6_dst), MacAddress{}, v6_src, v6_dst, 5353, 5353, v6_payload, 255, buffer),
        0u);
}

TEST(FrameBuilderTest, EthernetIpv4) {
    const auto src_mac = Mac({0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto dst_ip = *IpAddress::FromString("224.0.0.251");
    const auto dst_mac = MulticastMacFor(dst_ip);
    const auto src_ip = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const auto payload = MakeBytes({0xde, 0xad, 0xbe, 0xef});

    std::array<std::byte, 128> buffer{};
    const auto size = BuildUdpFrame(dst_mac, src_mac, src_ip, dst_ip, 5353, 5353, payload, 255, buffer);
    ASSERT_EQ(size, 14u + 20u + 8u + 4u);

    const std::span<const std::byte> frame{buffer.data(), size};
    EXPECT_EQ(MacAddress::FromBytes(frame.subspan<0, 6>()), dst_mac);  // dest MAC
    EXPECT_EQ(MacAddress::FromBytes(frame.subspan<6, 6>()), src_mac);  // source MAC
    EXPECT_EQ(ReadU16Be(frame.subspan(12)), 0x0800);  // ethertype IPv4

    const auto ip = frame.subspan(14, 20);
    EXPECT_EQ(std::to_integer<uint8_t>(ip[0]), 0x45);  // version 4, IHL 5
    EXPECT_EQ(std::to_integer<uint8_t>(ip[1]), 0);  // DSCP / ECN
    EXPECT_EQ(ReadU16Be(ip.subspan(2)), 20u + 8u + 4u);  // total length
    EXPECT_EQ(ReadU16Be(ip.subspan(4)), 0);  // identification
    EXPECT_EQ(ReadU16Be(ip.subspan(6)), 0);  // flags / fragment offset
    EXPECT_EQ(std::to_integer<uint8_t>(ip[8]), 255);  // TTL
    EXPECT_EQ(std::to_integer<uint8_t>(ip[9]), 17);  // protocol UDP
    EXPECT_EQ(Ipv4HeaderChecksum(ip), 0x0000);  // header checksum in place re-sums to zero
    EXPECT_TRUE(std::equal(ip.begin() + 12, ip.begin() + 16, src_ip.Bytes().begin()));  // source IP
    EXPECT_TRUE(std::equal(ip.begin() + 16, ip.begin() + 20, dst_ip.Bytes().begin()));  // dest IP

    const auto udp = frame.subspan(34);
    EXPECT_EQ(ReadU16Be(udp), 5353);  // source port
    EXPECT_EQ(ReadU16Be(udp.subspan(2)), 5353);  // dest port
    EXPECT_EQ(ReadU16Be(udp.subspan(4)), 8u + 4u);  // UDP length
    EXPECT_EQ(UdpChecksum(src_ip, dst_ip, udp), 0xffff);  // UDP checksum in place verifies
    EXPECT_TRUE(std::equal(udp.begin() + 8, udp.end(), payload.begin()));  // payload
}

TEST(FrameBuilderTest, EthernetIpv6) {
    const auto src_mac = Mac({0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto dst_ip = *IpAddress::FromString("ff02::fb");
    const auto dst_mac = MulticastMacFor(dst_ip);
    const auto src_ip = *IpAddress::FromString("fe80::1");
    const auto payload = MakeBytes({0x01, 0x02, 0x03});

    std::array<std::byte, 128> buffer{};
    const auto size = BuildUdpFrame(dst_mac, src_mac, src_ip, dst_ip, 5353, 5353, payload, 255, buffer);
    ASSERT_EQ(size, 14u + 40u + 8u + 3u);

    const std::span<const std::byte> frame{buffer.data(), size};
    EXPECT_EQ(MacAddress::FromBytes(frame.subspan<0, 6>()), dst_mac);  // dest MAC
    EXPECT_EQ(MacAddress::FromBytes(frame.subspan<6, 6>()), src_mac);  // source MAC
    EXPECT_EQ(ReadU16Be(frame.subspan(12)), 0x86dd);  // ethertype IPv6

    const auto ip = frame.subspan(14, 40);
    EXPECT_EQ(std::to_integer<uint8_t>(ip[0]), 0x60);  // version 6, traffic class high
    EXPECT_EQ(std::to_integer<uint8_t>(ip[1]), 0);  // traffic class low + flow label high
    EXPECT_EQ(ReadU16Be(ip.subspan(2)), 0);  // flow label low
    EXPECT_EQ(ReadU16Be(ip.subspan(4)), 8u + 3u);  // payload length
    EXPECT_EQ(std::to_integer<uint8_t>(ip[6]), 17);  // next header UDP
    EXPECT_EQ(std::to_integer<uint8_t>(ip[7]), 255);  // hop limit
    EXPECT_TRUE(std::equal(ip.begin() + 8, ip.begin() + 24, src_ip.Bytes().begin()));  // source IP
    EXPECT_TRUE(std::equal(ip.begin() + 24, ip.begin() + 40, dst_ip.Bytes().begin()));  // dest IP

    const auto udp = frame.subspan(54);
    EXPECT_EQ(ReadU16Be(udp), 5353);  // source port
    EXPECT_EQ(ReadU16Be(udp.subspan(2)), 5353);  // dest port
    EXPECT_EQ(ReadU16Be(udp.subspan(4)), 8u + 3u);  // UDP length
    EXPECT_EQ(UdpChecksum(src_ip, dst_ip, udp), 0xffff);  // UDP checksum in place verifies
    EXPECT_TRUE(std::equal(udp.begin() + 8, udp.end(), payload.begin()));  // payload
}

#if defined(__APPLE__)
TEST(FrameBuilderTest, LoopbackIpv4) {
    const auto src_ip = IpAddress::FromV4Bytes(127, 0, 0, 1);
    const auto dst_ip = *IpAddress::FromString("224.0.0.251");
    const auto payload = MakeBytes({0xde, 0xad, 0xbe, 0xef});

    std::array<std::byte, 128> buffer{};
    const auto size = BuildLoopbackUdpFrame(src_ip, dst_ip, 5353, 5353, payload, 255, buffer);
    ASSERT_EQ(size, 4u + 20u + 8u + 4u);

    const std::span<const std::byte> frame{buffer.data(), size};
    uint32_t family = 0;
    std::memcpy(&family, frame.data(), sizeof(family));  // DLT_NULL: address family, host byte order
    EXPECT_EQ(family, static_cast<uint32_t>(AF_INET));

    const auto ip = frame.subspan(4, 20);
    EXPECT_EQ(std::to_integer<uint8_t>(ip[0]), 0x45);  // version 4, IHL 5
    EXPECT_EQ(std::to_integer<uint8_t>(ip[1]), 0);  // DSCP / ECN
    EXPECT_EQ(ReadU16Be(ip.subspan(2)), 20u + 8u + 4u);  // total length
    EXPECT_EQ(ReadU16Be(ip.subspan(4)), 0);  // identification
    EXPECT_EQ(ReadU16Be(ip.subspan(6)), 0);  // flags / fragment offset
    EXPECT_EQ(std::to_integer<uint8_t>(ip[8]), 255);  // TTL
    EXPECT_EQ(std::to_integer<uint8_t>(ip[9]), 17);  // protocol UDP
    EXPECT_EQ(Ipv4HeaderChecksum(ip), 0x0000);  // header checksum in place re-sums to zero
    EXPECT_TRUE(std::equal(ip.begin() + 12, ip.begin() + 16, src_ip.Bytes().begin()));  // source IP
    EXPECT_TRUE(std::equal(ip.begin() + 16, ip.begin() + 20, dst_ip.Bytes().begin()));  // dest IP

    const auto udp = frame.subspan(24);
    EXPECT_EQ(ReadU16Be(udp), 5353);  // source port
    EXPECT_EQ(ReadU16Be(udp.subspan(2)), 5353);  // dest port
    EXPECT_EQ(ReadU16Be(udp.subspan(4)), 8u + 4u);  // UDP length
    EXPECT_EQ(UdpChecksum(src_ip, dst_ip, udp), 0xffff);  // UDP checksum in place verifies
    EXPECT_TRUE(std::equal(udp.begin() + 8, udp.end(), payload.begin()));  // payload
}

TEST(FrameBuilderTest, LoopbackIpv6) {
    const auto src_ip = *IpAddress::FromString("::1");
    const auto dst_ip = *IpAddress::FromString("ff02::fb");
    const auto payload = MakeBytes({0x01, 0x02, 0x03});

    std::array<std::byte, 128> buffer{};
    const auto size = BuildLoopbackUdpFrame(src_ip, dst_ip, 5353, 5353, payload, 255, buffer);
    ASSERT_EQ(size, 4u + 40u + 8u + 3u);

    const std::span<const std::byte> frame{buffer.data(), size};
    uint32_t family = 0;
    std::memcpy(&family, frame.data(), sizeof(family));  // DLT_NULL: address family, host byte order
    EXPECT_EQ(family, static_cast<uint32_t>(AF_INET6));

    const auto ip = frame.subspan(4, 40);
    EXPECT_EQ(std::to_integer<uint8_t>(ip[0]), 0x60);  // version 6, traffic class high
    EXPECT_EQ(std::to_integer<uint8_t>(ip[1]), 0);  // traffic class low + flow label high
    EXPECT_EQ(ReadU16Be(ip.subspan(2)), 0);  // flow label low
    EXPECT_EQ(ReadU16Be(ip.subspan(4)), 8u + 3u);  // payload length
    EXPECT_EQ(std::to_integer<uint8_t>(ip[6]), 17);  // next header UDP
    EXPECT_EQ(std::to_integer<uint8_t>(ip[7]), 255);  // hop limit
    EXPECT_TRUE(std::equal(ip.begin() + 8, ip.begin() + 24, src_ip.Bytes().begin()));  // source IP
    EXPECT_TRUE(std::equal(ip.begin() + 24, ip.begin() + 40, dst_ip.Bytes().begin()));  // dest IP

    const auto udp = frame.subspan(44);
    EXPECT_EQ(ReadU16Be(udp), 5353);  // source port
    EXPECT_EQ(ReadU16Be(udp.subspan(2)), 5353);  // dest port
    EXPECT_EQ(ReadU16Be(udp.subspan(4)), 8u + 3u);  // UDP length
    EXPECT_EQ(UdpChecksum(src_ip, dst_ip, udp), 0xffff);  // UDP checksum in place verifies
    EXPECT_TRUE(std::equal(udp.begin() + 8, udp.end(), payload.begin()));  // payload
}
#endif
