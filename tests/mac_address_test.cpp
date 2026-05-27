#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <format>

using namespace reflector;

TEST(MacAddressTest, ParsesLowercaseAddress) {
    const auto mac = MacAddress::FromString("00:11:22:33:44:55");
    ASSERT_TRUE(mac.has_value());
    const auto& bytes = mac->Bytes();
    EXPECT_EQ(bytes[0], std::byte{0x00});
    EXPECT_EQ(bytes[1], std::byte{0x11});
    EXPECT_EQ(bytes[2], std::byte{0x22});
    EXPECT_EQ(bytes[3], std::byte{0x33});
    EXPECT_EQ(bytes[4], std::byte{0x44});
    EXPECT_EQ(bytes[5], std::byte{0x55});
}

TEST(MacAddressTest, ParsesUppercaseAddress) {
    const auto mac = MacAddress::FromString("B0:37:95:C5:60:BE");
    ASSERT_TRUE(mac.has_value());
    const auto& bytes = mac->Bytes();
    EXPECT_EQ(bytes[0], std::byte{0xb0});
    EXPECT_EQ(bytes[1], std::byte{0x37});
    EXPECT_EQ(bytes[2], std::byte{0x95});
    EXPECT_EQ(bytes[3], std::byte{0xc5});
    EXPECT_EQ(bytes[4], std::byte{0x60});
    EXPECT_EQ(bytes[5], std::byte{0xbe});
}

TEST(MacAddressTest, ParsesMixedCaseAddress) {
    EXPECT_TRUE(MacAddress::FromString("aA:bB:cC:dD:eE:fF").has_value());
}

TEST(MacAddressTest, DefaultInitializesToZero) {
    const MacAddress mac;
    for (const auto b : mac.Bytes()) {
        EXPECT_EQ(b, std::byte{0});
    }
}

TEST(MacAddressTest, RejectsTooShortAddress) {
    EXPECT_FALSE(MacAddress::FromString("00:11:22:33:44").has_value());
}

TEST(MacAddressTest, RejectsTooLongAddress) {
    EXPECT_FALSE(MacAddress::FromString("00:11:22:33:44:55:66").has_value());
}

TEST(MacAddressTest, RejectsEmptyAddress) {
    EXPECT_FALSE(MacAddress::FromString("").has_value());
}

TEST(MacAddressTest, RejectsNonHexDigits) {
    EXPECT_FALSE(MacAddress::FromString("GG:11:22:33:44:55").has_value());
    EXPECT_FALSE(MacAddress::FromString("00:ZZ:22:33:44:55").has_value());
}

TEST(MacAddressTest, RejectsDashSeparators) {
    EXPECT_FALSE(MacAddress::FromString("00-11-22-33-44-55").has_value());
}

TEST(MacAddressTest, RejectsDotSeparators) {
    EXPECT_FALSE(MacAddress::FromString("00.11.22.33.44.55").has_value());
}

TEST(MacAddressTest, RejectsSpaceSeparators) {
    EXPECT_FALSE(MacAddress::FromString("00 11 22 33 44 55").has_value());
}

TEST(MacAddressTest, ParsesAllZeroAddress) {
    const auto mac = MacAddress::FromString("00:00:00:00:00:00");
    ASSERT_TRUE(mac.has_value());
    for (const auto b : mac->Bytes()) {
        EXPECT_EQ(b, std::byte{0});
    }
}

TEST(MacAddressTest, ParsesAllOnesAddress) {
    const auto mac = MacAddress::FromString("ff:ff:ff:ff:ff:ff");
    ASSERT_TRUE(mac.has_value());
    for (const auto b : mac->Bytes()) {
        EXPECT_EQ(b, std::byte{0xff});
    }
}

TEST(MacAddressTest, FormatsAddress) {
    const auto mac = MacAddress::FromString("b0:37:95:c5:60:be");
    ASSERT_TRUE(mac.has_value());

    EXPECT_EQ(std::format("{}", *mac), "B0:37:95:C5:60:BE");
}

TEST(MacAddressTest, FormatsBytesBelowSixteenWithLeadingZero) {
    const auto mac = MacAddress::FromString("00:01:0a:bc:0f:05");
    ASSERT_TRUE(mac.has_value());

    EXPECT_EQ(std::format("{}", *mac), "00:01:0A:BC:0F:05");
}

TEST(MacAddressTest, FromBytesCopiesOctets) {
    const std::array<std::byte, 6> octets{
        std::byte{0xb0}, std::byte{0x37}, std::byte{0x95}, std::byte{0xc5}, std::byte{0x60}, std::byte{0xbe}};

    const auto mac = MacAddress::FromBytes(octets);

    EXPECT_EQ(mac.Bytes(), octets);
}

TEST(MacAddressTest, Equality) {
    const auto mac = *MacAddress::FromString("00:11:22:33:44:55");
    EXPECT_EQ(mac, *MacAddress::FromString("00:11:22:33:44:55"));
    EXPECT_NE(mac, *MacAddress::FromString("00:11:22:33:44:56"));
}
