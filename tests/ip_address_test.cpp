#include "reflector/ip_address.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cstddef>
#include <functional>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace reflector;

TEST(IpAddressTest, AnyV4AndAnyV6AreFamilyWildcards) {
    EXPECT_TRUE(IpAddress::AnyV4().IsV4());
    EXPECT_EQ(IpAddress::AnyV4().ToString(), "0.0.0.0");
    EXPECT_TRUE(IpAddress::AnyV6().IsV6());
    EXPECT_EQ(IpAddress::AnyV6().ToString(), "::");
    EXPECT_NE(IpAddress::AnyV4(), IpAddress::AnyV6());
}

TEST(IpAddressTest, BroadcastV4ReturnsLimitedBroadcastAddress) {
    const auto addr = IpAddress::BroadcastV4();

    EXPECT_TRUE(addr.IsV4());
    EXPECT_EQ(addr, IpAddress::FromV4Bytes(255, 255, 255, 255));
    EXPECT_EQ(addr.ToString(), "255.255.255.255");
}

TEST(IpAddressTest, AllNodesLinkLocalV6ReturnsAllNodesMulticastAddress) {
    const auto addr = IpAddress::AllNodesLinkLocalV6();

    EXPECT_TRUE(addr.IsV6());
    EXPECT_EQ(addr, IpAddress::FromString("ff02::1"));
    EXPECT_EQ(addr.ToString(), "ff02::1");
}

TEST(IpAddressTest, LoopbackV4ReturnsLoopbackAddress) {
    const auto addr = IpAddress::LoopbackV4();

    EXPECT_TRUE(addr.IsV4());
    EXPECT_EQ(addr, IpAddress::FromV4Bytes(127, 0, 0, 1));
    EXPECT_EQ(addr.ToString(), "127.0.0.1");
}

TEST(IpAddressTest, LoopbackV6ReturnsLoopbackAddress) {
    const auto addr = IpAddress::LoopbackV6();

    EXPECT_TRUE(addr.IsV6());
    EXPECT_EQ(addr, IpAddress::FromString("::1"));
    EXPECT_EQ(addr.ToString(), "::1");
}

TEST(IpAddressTest, FromV4BytesFormatsAsDottedDecimal) {
    const auto addr = IpAddress::FromV4Bytes(192, 168, 1, 100);
    EXPECT_EQ(addr.ToString(), "192.168.1.100");
    EXPECT_TRUE(addr.IsV4());
}

TEST(IpAddressTest, BytesExposeNetworkOrderOctets) {
    const auto v4 = IpAddress::FromV4Bytes(192, 0, 2, 1);
    const IpAddress::ByteArray expected_v4{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x02}, std::byte{0x01},
    };
    EXPECT_EQ(v4.Bytes(), expected_v4);

    const auto v6 = *IpAddress::FromString("2001:db8::1");
    const IpAddress::ByteArray expected_v6{
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    EXPECT_EQ(v6.Bytes(), expected_v6);
}

TEST(IpAddressTest, ParsesDottedDecimalString) {
    const auto addr = IpAddress::FromString("10.0.0.1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_TRUE(addr->IsV4());
    EXPECT_EQ(addr->ToString(), "10.0.0.1");
}

TEST(IpAddressTest, ParsesIpv6String) {
    const auto addr = IpAddress::FromString("2001:db8::1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_TRUE(addr->IsV6());
    EXPECT_EQ(addr->ToString(), "2001:db8::1");
}

TEST(IpAddressTest, WildcardStringsParsePerFamily) {
    EXPECT_EQ(IpAddress::FromString("0.0.0.0"), IpAddress::AnyV4());
    EXPECT_EQ(IpAddress::FromString("::"), IpAddress::AnyV6());
}

TEST(IpAddressTest, InvalidStringFails) {
    EXPECT_FALSE(IpAddress::FromString("").has_value());
    EXPECT_FALSE(IpAddress::FromString("*").has_value());
    EXPECT_FALSE(IpAddress::FromString("999.0.0.0").has_value());
    EXPECT_FALSE(IpAddress::FromString("abc").has_value());
    EXPECT_FALSE(IpAddress::FromString("1.2.3").has_value());
    EXPECT_FALSE(IpAddress::FromString("2001:db8::xyz").has_value());
}

TEST(IpAddressTest, Equality) {
    EXPECT_EQ(IpAddress::FromV4Bytes(1, 2, 3, 4), IpAddress::FromV4Bytes(1, 2, 3, 4));
    EXPECT_NE(IpAddress::FromV4Bytes(1, 2, 3, 4), IpAddress::FromV4Bytes(1, 2, 3, 5));
    EXPECT_EQ(*IpAddress::FromString("2001:db8::1"), *IpAddress::FromString("2001:db8::1"));
    EXPECT_NE(*IpAddress::FromString("2001:db8::1"), *IpAddress::FromString("2001:db8::2"));
}

TEST(IpAddressTest, SameBytesWithDifferentFamiliesNeverCompareEqual) {
    const auto v4 = IpAddress::FromV4Bytes(0, 0, 0, 1);
    const auto v6 = IpAddress::FromString("0:1::");
    ASSERT_TRUE(v6.has_value());

    ASSERT_EQ(v4.Bytes(), v6->Bytes());
    EXPECT_NE(v4, *v6);
}

TEST(IpAddressTest, Hash) {
    const auto v4 = IpAddress::FromV4Bytes(1, 2, 3, 4);
    const auto v6 = *IpAddress::FromString("2001:db8::1");
    EXPECT_EQ(std::hash<IpAddress>{}(v4), std::hash<IpAddress>{}(IpAddress::FromV4Bytes(1, 2, 3, 4)));
    EXPECT_NE(std::hash<IpAddress>{}(v4), std::hash<IpAddress>{}(IpAddress::FromV4Bytes(5, 6, 7, 8)));
    EXPECT_EQ(std::hash<IpAddress>{}(v6), std::hash<IpAddress>{}(*IpAddress::FromString("2001:db8::1")));
}

TEST(IpAddressTest, ToSockaddrV4RoundTrips) {
    const auto addr = IpAddress::FromV4Bytes(192, 0, 2, 1);
    sockaddr_storage storage{};
    const auto length = addr.ToSockaddr(storage, 7);
    ASSERT_EQ(static_cast<size_t>(length), sizeof(sockaddr_in));
    EXPECT_EQ(storage.ss_family, AF_INET);
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&storage);
    EXPECT_EQ(ntohs(v4->sin_port), 7);
    EXPECT_EQ(IpAddress::FromSockaddr(reinterpret_cast<const sockaddr*>(&storage)), addr);
}

TEST(IpAddressTest, ToSockaddrV6RoundTripsWithScopeId) {
    const auto addr = *IpAddress::FromString("fe80::1");
    sockaddr_storage storage{};
    const auto length = addr.ToSockaddr(storage, 9, 42);
    ASSERT_EQ(static_cast<size_t>(length), sizeof(sockaddr_in6));
    EXPECT_EQ(storage.ss_family, AF_INET6);
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&storage);
    EXPECT_EQ(ntohs(v6->sin6_port), 9);
    EXPECT_EQ(v6->sin6_scope_id, 42u);
    EXPECT_EQ(IpAddress::FromSockaddr(reinterpret_cast<const sockaddr*>(&storage)), addr);
}

TEST(IpAddressTest, FromSockaddrUnknownFamilyReturnsNullopt) {
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;
    EXPECT_FALSE(IpAddress::FromSockaddr(reinterpret_cast<const sockaddr*>(&storage)).has_value());
}

TEST(IpAddressTest, FromSockaddrNullReturnsNullopt) {
    EXPECT_FALSE(IpAddress::FromSockaddr(nullptr).has_value());
}
