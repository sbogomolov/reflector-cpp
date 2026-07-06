#include "reflector/interface.h"

#include "mocks/fake_interface.h"
#include "reflector/ip_address.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include <net/if.h>

namespace reflector {

TEST(InterfaceTest, ResolvesLoopbackIdentityAndAddresses) {
    const Interface iface{LoopbackInterface()};
    ASSERT_TRUE(iface.IsValid());
    EXPECT_EQ(iface.Name(), LoopbackInterface());
    EXPECT_EQ(iface.Index(), if_nametoindex(std::string{LoopbackInterface()}.c_str()));
    ASSERT_TRUE(iface.SourceAddress(IpAddress::Family::V4).has_value());
    EXPECT_EQ(*iface.SourceAddress(IpAddress::Family::V4), IpAddress::LoopbackV4());
    EXPECT_TRUE(iface.CanSend(IpAddress::Family::V4));
    EXPECT_EQ(iface.Mac(), MacAddress{});  // loopback has no link-layer address
}

TEST(InterfaceTest, UnknownNameIsInvalid) {
    const Interface iface{"nonex0"};
    EXPECT_FALSE(iface.IsValid());
    EXPECT_EQ(iface.Index(), 0u);
    EXPECT_FALSE(iface.CanSend(IpAddress::Family::V4));
    EXPECT_FALSE(iface.SourceAddress(IpAddress::Family::V4).has_value());
}

TEST(InterfaceTest, OverlongNameIsInvalid) {
    const Interface iface{std::string(IFNAMSIZ, 'x')};
    EXPECT_FALSE(iface.IsValid());
}

TEST(InterfaceTest, RefreshKeepsLoopbackAddresses) {
    Interface iface{LoopbackInterface()};
    ASSERT_TRUE(iface.IsValid());
    iface.Refresh();
    EXPECT_TRUE(iface.SourceAddress(IpAddress::Family::V4).has_value());
}

TEST(InterfaceTest, SourceAddressForMatchesTheDestinationScope) {
    const auto link_local = *IpAddress::FromString("fe80::1");
    const auto unique_local = *IpAddress::FromString("fd00::1");
    const auto v4 = IpAddress::FromV4Bytes(192, 168, 1, 2);
    const FakeInterface iface{"fake0", 0, {.v4 = v4, .v6 = link_local, .v6_routable = unique_local}};

    EXPECT_EQ(iface.SourceAddressFor(*IpAddress::FromString("239.255.255.250")), v4);
    EXPECT_EQ(iface.SourceAddressFor(*IpAddress::FromString("ff02::c")), link_local);
    EXPECT_EQ(iface.SourceAddressFor(*IpAddress::FromString("fe80::99")), link_local);
    EXPECT_EQ(iface.SourceAddressFor(*IpAddress::FromString("ff05::c")), unique_local);
    EXPECT_EQ(iface.SourceAddressFor(*IpAddress::FromString("2001:db8::5")), unique_local);
}

TEST(InterfaceTest, SourceAddressForFallsBackAcrossScopes) {
    // Only a link-local source: a routable destination still gets it (mismatch beats dropping).
    const auto link_local = *IpAddress::FromString("fe80::1");
    const FakeInterface link_only{"fake0", 0, {.v6 = link_local}};
    EXPECT_EQ(link_only.SourceAddressFor(*IpAddress::FromString("ff05::c")), link_local);

    // Only a routable source: it is also the best-overall pick, so a link-local destination gets it.
    const auto unique_local = *IpAddress::FromString("fd00::1");
    const FakeInterface routable_only{"fake0", 0, {.v6 = unique_local, .v6_routable = unique_local}};
    EXPECT_EQ(routable_only.SourceAddressFor(*IpAddress::FromString("ff02::c")), unique_local);

    // No v6 at all: nullopt either way.
    const FakeInterface v4_only{"fake0", 0, {.v4 = IpAddress::LoopbackV4()}};
    EXPECT_EQ(v4_only.SourceAddressFor(*IpAddress::FromString("ff05::c")), std::nullopt);
}

TEST(FakeInterfaceTest, FixedIdentityNoSyscalls) {
    FakeInterface iface{"fake1", 7};
    EXPECT_TRUE(iface.IsValid());
    EXPECT_EQ(iface.Name(), "fake1");
    EXPECT_EQ(iface.Index(), 7u);
    ASSERT_TRUE(iface.SourceAddress(IpAddress::Family::V4).has_value());
    EXPECT_EQ(*iface.SourceAddress(IpAddress::Family::V4), IpAddress::LoopbackV4());

    iface.SetV4(std::nullopt);
    EXPECT_FALSE(iface.CanSend(IpAddress::Family::V4));
    EXPECT_TRUE(iface.CanSend(IpAddress::Family::V6));

    EXPECT_EQ(iface.refresh_count, 0u);
    iface.Refresh();
    EXPECT_EQ(iface.refresh_count, 1u);
    EXPECT_TRUE(iface.CanSend(IpAddress::Family::V6));  // the fake's Refresh must not re-resolve
}

TEST(FakeInterfaceTest, DefaultsMatchFakeLinkSocket) {
    const FakeInterface iface;
    EXPECT_FALSE(iface.IsValid());  // index 0 — "no egress pin"
    EXPECT_EQ(iface.Name(), "fake0");
    EXPECT_TRUE(iface.CanSend(IpAddress::Family::V4));
    EXPECT_TRUE(iface.CanSend(IpAddress::Family::V6));
}

} // namespace reflector
