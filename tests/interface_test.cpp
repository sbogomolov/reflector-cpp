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
