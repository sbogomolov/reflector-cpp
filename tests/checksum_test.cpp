#include "reflector/checksum.h"

#include "reflector/ip_address.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

namespace reflector {

// Canonical IPv4 header example (Wikipedia): with the checksum field zeroed the checksum is
// 0xb861, and with that value in place the header re-sums to zero.
TEST(ChecksumTest, Ipv4HeaderKnownVector) {
    const auto header = MakeBytes({
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    });
    EXPECT_EQ(Ipv4HeaderChecksum(header), 0xb861);
}

TEST(ChecksumTest, Ipv4HeaderWithChecksumInPlaceSumsToZero) {
    const auto header = MakeBytes({
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    });
    EXPECT_EQ(Ipv4HeaderChecksum(header), 0x0000);
}

// Hand-computed vector: 192.168.0.1 -> 192.168.0.199, UDP sport 50000 dport 53, payload
// "test". Validates the IPv4 pseudo-header construction independently of self-consistency.
TEST(ChecksumTest, UdpV4KnownVector) {
    const auto src = IpAddress::FromV4Bytes(192, 168, 0, 1);
    const auto dst = IpAddress::FromV4Bytes(192, 168, 0, 199);
    const auto udp = MakeBytes({
        0xc3, 0x50, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00,
        0x74, 0x65, 0x73, 0x74,
    });
    EXPECT_EQ(UdpChecksum(src, dst, udp), 0xd25d);
}

TEST(ChecksumTest, UdpV4WithChecksumInPlaceMapsToAllOnes) {
    const auto src = IpAddress::FromV4Bytes(192, 168, 0, 1);
    const auto dst = IpAddress::FromV4Bytes(192, 168, 0, 199);
    const auto udp = MakeBytes({
        0xc3, 0x50, 0x00, 0x35, 0x00, 0x0c, 0xd2, 0x5d,
        0x74, 0x65, 0x73, 0x74,
    });
    EXPECT_EQ(UdpChecksum(src, dst, udp), 0xffff);
}

// Independently-computed vector (struct.unpack reference): fe80::1 -> ff02::fb, UDP
// sport/dport 5353, payload "hello" (odd length, exercising the tail-byte path). The IPv6
// pseudo-header (32-bit length, mandatory checksum) differs from IPv4, so it gets its own
// ground truth rather than a self-consistency check.
TEST(ChecksumTest, UdpV6KnownVector) {
    const auto src = *IpAddress::FromString("fe80::1");
    const auto dst = *IpAddress::FromString("ff02::fb");
    const auto udp = MakeBytes({
        0x14, 0xe9, 0x14, 0xe9, 0x00, 0x0d, 0x00, 0x00,
        0x68, 0x65, 0x6c, 0x6c, 0x6f,
    });
    EXPECT_EQ(UdpChecksum(src, dst, udp), 0x93b0);
}

TEST(ChecksumTest, UdpV6WithChecksumInPlaceMapsToAllOnes) {
    const auto src = *IpAddress::FromString("fe80::1");
    const auto dst = *IpAddress::FromString("ff02::fb");
    const auto udp = MakeBytes({
        0x14, 0xe9, 0x14, 0xe9, 0x00, 0x0d, 0x93, 0xb0,
        0x68, 0x65, 0x6c, 0x6c, 0x6f,
    });
    EXPECT_EQ(UdpChecksum(src, dst, udp), 0xffff);
}

}  // namespace reflector
