#include "reflector/interface_address.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#if defined(__linux__)
#include <net/if.h>
#include <string>
#endif

using namespace reflector;

namespace {

// Resolve the loopback interface via each platform's native key — index on Linux (the form the
// netlink resolver and production refresh use), name on macOS.
InterfaceAddresses ResolveLoopback() {
#if defined(__linux__)
    return ResolveInterfaceAddresses(if_nametoindex(std::string{LoopbackInterface()}.c_str()));
#else
    return ResolveInterfaceAddresses(LoopbackInterface());
#endif
}

} // namespace

TEST(InterfaceAddressTest, ResolvesLoopbackIpv4) {
    const auto addresses = ResolveLoopback();
    ASSERT_TRUE(addresses.v4.has_value());
    EXPECT_EQ(*addresses.v4, IpAddress::LoopbackV4());  // 127.0.0.1
    EXPECT_EQ(addresses.mac, MacAddress{});  // loopback has no link-layer address
}

#if defined(__APPLE__)

// macOS lo0 carries a link-local fe80::1, which the resolver prefers; verify the BSD-embedded
// scope id (bytes 2-3) is cleared so the source is the canonical fe80::1.
TEST(InterfaceAddressTest, ResolvesLoopbackLinkLocalIpv6) {
    const auto addresses = ResolveLoopback();
    if (!addresses.v6.has_value()) {
        GTEST_SKIP() << "loopback has no IPv6 on this host";
    }
    const auto& bytes = addresses.v6->Bytes();
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[0]), 0xfe);  // fe80::/10 link-local
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[1]) & 0xc0, 0x80);
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[2]), 0);  // embedded scope id cleared
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[3]), 0);
}

#elif defined(__linux__)

// Linux lo has only ::1 (no link-local); verify we resolve that loopback address — the lowest
// Ipv6Rank fallback — rather than nothing, and don't fabricate an fe80::.
TEST(InterfaceAddressTest, ResolvesLoopbackIpv6) {
    const auto addresses = ResolveLoopback();
    if (!addresses.v6.has_value()) {
        GTEST_SKIP() << "loopback has no IPv6 on this host";
    }
    EXPECT_EQ(*addresses.v6, IpAddress::LoopbackV6());  // ::1
}

#endif

TEST(InterfaceAddressTest, UnknownInterfaceResolvesNothing) {
#if defined(__linux__)
    const auto addresses = ResolveInterfaceAddresses(0u);  // index 0 is no interface
#else
    const auto addresses = ResolveInterfaceAddresses("nonexistent-reflector-iface");
#endif
    EXPECT_FALSE(addresses.v4.has_value());
    EXPECT_FALSE(addresses.v6.has_value());
    EXPECT_EQ(addresses.mac, MacAddress{});
}

// The source-selection policy, driven directly with synthetic candidate lists — the part the
// loopback resolve tests can't reach (loopback carries at most one address per family).

TEST(SelectSourceAddressesTest, PrefersLinkLocalIpv6) {
    const auto global = *IpAddress::FromString("2001:db8::1");
    const auto unique_local = *IpAddress::FromString("fd00::1");
    const auto link_local = *IpAddress::FromString("fe80::1");
    // Listed worst-first, so a pass shows the result follows rank, not arrival order.
    const std::vector<IpAddress> candidates{global, unique_local, link_local};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, link_local);
}

TEST(SelectSourceAddressesTest, PrefersUniqueLocalOverGlobalIpv6) {
    const auto global = *IpAddress::FromString("2001:db8::1");
    const auto unique_local = *IpAddress::FromString("fd00::1");
    const std::vector<IpAddress> candidates{global, unique_local};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, unique_local);
}

TEST(SelectSourceAddressesTest, FallsBackToGlobalIpv6) {
    const auto global = *IpAddress::FromString("2001:db8::1");
    const std::vector<IpAddress> candidates{global};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, global);
}

TEST(SelectSourceAddressesTest, PrefersGlobalUnicastOverOtherIpv6) {
    const auto other = *IpAddress::FromString("::1");  // loopback: not link-local, ULA, or GUA
    const auto global = *IpAddress::FromString("2001:db8::1");
    const std::vector<IpAddress> candidates{other, global};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, global);
}

TEST(SelectSourceAddressesTest, FallsBackToOtherIpv6AsLastResort) {
    const auto other = *IpAddress::FromString("::1");  // lowest-ranked category, but still chosen alone
    const std::vector<IpAddress> candidates{other};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, other);
}

TEST(SelectSourceAddressesTest, TakesTheFirstIpv4) {
    const auto first = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const auto second = IpAddress::FromV4Bytes(10, 0, 0, 1);
    const std::vector<IpAddress> candidates{first, second};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v4.has_value());
    EXPECT_EQ(*selected.v4, first);
}

TEST(SelectSourceAddressesTest, SelectsOnePerFamilyAndPreservesMac) {
    const auto v4 = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const auto v6 = *IpAddress::FromString("fe80::1");
    const std::vector<IpAddress> candidates{v4, v6};

    // The resolver sets the MAC before selecting, so selection must leave it untouched.
    InterfaceAddresses result;
    result.mac = *MacAddress::FromString("02:00:00:00:00:01");
    detail::SelectSourceAddresses(candidates, result);

    ASSERT_TRUE(result.v4.has_value());
    EXPECT_EQ(*result.v4, v4);
    ASSERT_TRUE(result.v6.has_value());
    EXPECT_EQ(*result.v6, v6);
    EXPECT_EQ(result.mac, *MacAddress::FromString("02:00:00:00:00:01"));  // unchanged by selection
}

TEST(SelectSourceAddressesTest, EmptyCandidatesSelectNothing) {
    const std::vector<IpAddress> none;

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(none, selected);

    EXPECT_FALSE(selected.v4.has_value());
    EXPECT_FALSE(selected.v6.has_value());
}
