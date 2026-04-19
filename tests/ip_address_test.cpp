#include "reflector/ip_address.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <functional>

using namespace reflector;

TEST(IpAddressTest, AnyIsZero) {
    EXPECT_TRUE(IpAddress::Any().IsAny());
    EXPECT_EQ(IpAddress::Any().InAddr(), 0u);
}

TEST(IpAddressTest, BroadcastIsAllOnes) {
    EXPECT_EQ(IpAddress::Broadcast().InAddr(), 0xffffffffu);
    EXPECT_FALSE(IpAddress::Broadcast().IsAny());
}

TEST(IpAddressTest, LoopbackFormatsAsDottedDecimal) {
    EXPECT_EQ(IpAddress::Loopback().ToString(), "127.0.0.1");
}

TEST(IpAddressTest, FromBytesFormatsAsDottedDecimal) {
    const auto addr = IpAddress::FromBytes(192, 168, 1, 100);
    EXPECT_EQ(addr.ToString(), "192.168.1.100");
    EXPECT_FALSE(addr.IsAny());
}

TEST(IpAddressTest, ParsesDottedDecimalString) {
    const auto addr = IpAddress::FromString("10.0.0.1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->ToString(), "10.0.0.1");
}

TEST(IpAddressTest, EmptyStringReturnsAny) {
    EXPECT_EQ(IpAddress::FromString(""), IpAddress::Any());
}

TEST(IpAddressTest, WildcardStringReturnsAny) {
    EXPECT_EQ(IpAddress::FromString("*"), IpAddress::Any());
}

TEST(IpAddressTest, ZeroAddressStringReturnsAny) {
    EXPECT_EQ(IpAddress::FromString("0.0.0.0"), IpAddress::Any());
}

TEST(IpAddressTest, InvalidStringFails) {
    EXPECT_FALSE(IpAddress::FromString("999.0.0.0").has_value());
    EXPECT_FALSE(IpAddress::FromString("abc").has_value());
    EXPECT_FALSE(IpAddress::FromString("1.2.3").has_value());
}

TEST(IpAddressTest, Equality) {
    const auto a = IpAddress::FromBytes(1, 2, 3, 4);
    const auto b = IpAddress::FromBytes(1, 2, 3, 4);
    const auto c = IpAddress::FromBytes(1, 2, 3, 5);
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(IpAddressTest, Hash) {
    const auto a = IpAddress::FromBytes(1, 2, 3, 4);
    const auto b = IpAddress::FromBytes(1, 2, 3, 4);
    const auto c = IpAddress::FromBytes(5, 6, 7, 8);
    EXPECT_EQ(std::hash<IpAddress>{}(a), std::hash<IpAddress>{}(b));
    EXPECT_NE(std::hash<IpAddress>{}(a), std::hash<IpAddress>{}(c));
}

TEST(IpAddressTest, PreservesNetworkOrder) {
    const auto addr = IpAddress::FromBytes(192, 0, 2, 1);
    EXPECT_EQ(IpAddress::FromInAddr(addr.InAddr()), addr);
}

TEST(IpAddressTest, FromInAddrFormatsBytes) {
    const auto addr = IpAddress::FromInAddr(htonl(0x01020304u));
    EXPECT_EQ(addr.InAddr(), htonl(0x01020304u));
    EXPECT_EQ(addr.ToString(), "1.2.3.4");
}
