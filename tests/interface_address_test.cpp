#include "reflector/interface_address.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

using namespace reflector;

TEST(InterfaceAddressTest, ResolvesLoopbackIpv4) {
    const auto addresses = ResolveInterfaceAddresses(LoopbackInterface());
    ASSERT_TRUE(addresses.v4.has_value());
    EXPECT_EQ(*addresses.v4, IpAddress::LoopbackV4());  // 127.0.0.1
    EXPECT_EQ(addresses.mac, MacAddress{});  // loopback has no link-layer address
}

TEST(InterfaceAddressTest, LoopbackIpv6IsCanonicalLinkLocalWhenPresent) {
    const auto addresses = ResolveInterfaceAddresses(LoopbackInterface());
    if (!addresses.v6.has_value()) {
        GTEST_SKIP() << "loopback has no link-local IPv6 on this platform";
    }
    const auto& bytes = addresses.v6->Bytes();
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[0]), 0xfe);  // fe80::/10 link-local
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[1]) & 0xc0, 0x80);
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[2]), 0);  // BSD embedded scope id cleared
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[3]), 0);
}

TEST(InterfaceAddressTest, UnknownInterfaceResolvesNothing) {
    const auto addresses = ResolveInterfaceAddresses("nonexistent-reflector-iface");
    EXPECT_FALSE(addresses.v4.has_value());
    EXPECT_FALSE(addresses.v6.has_value());
    EXPECT_EQ(addresses.mac, MacAddress{});
}
