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
#else
#include <array>
#include <cstring>
#include <span>
#include <string_view>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet6/in6_var.h>
#include <sys/socket.h>
#endif

namespace {
using namespace reflector;

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

namespace reflector {

TEST(InterfaceAddressTest, ResolvesLoopbackIpv4) {
    const auto addresses = ResolveLoopback();
    ASSERT_TRUE(addresses.v4.has_value());
    EXPECT_EQ(*addresses.v4, IpAddress::LoopbackV4());
    EXPECT_EQ(addresses.mac, MacAddress{});  // loopback has no link-layer address
}

#if defined(__linux__)

// Linux lo has only ::1 (no link-local); verify we resolve that loopback address — the lowest
// Ipv6Rank fallback — rather than nothing, and don't fabricate an fe80::.
TEST(InterfaceAddressTest, ResolvesLoopbackIpv6) {
    const auto addresses = ResolveLoopback();
    if (!addresses.v6) {
        GTEST_SKIP() << "loopback has no IPv6 on this host";
    }
    EXPECT_EQ(*addresses.v6, IpAddress::LoopbackV6());
}

#else

// macOS and FreeBSD lo0 carry a link-local fe80::1, which the resolver prefers; verify the
// BSD-embedded scope id (bytes 2-3) is cleared so the source is the canonical fe80::1.
TEST(InterfaceAddressTest, ResolvesLoopbackLinkLocalIpv6) {
    const auto addresses = ResolveLoopback();
    if (!addresses.v6) {
        GTEST_SKIP() << "loopback has no IPv6 on this host";
    }
    const auto& bytes = addresses.v6->Bytes();
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[0]), 0xfe);  // fe80::/10 link-local
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[1]) & 0xc0, 0x80);
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[2]), 0);  // embedded scope id cleared
    EXPECT_EQ(std::to_integer<uint8_t>(bytes[3]), 0);
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

TEST(SelectSourceAddressesTest, PicksTheRoutableIpv6AlongsideTheLinkLocal) {
    const auto global = *IpAddress::FromString("2001:db8::1");
    const auto unique_local = *IpAddress::FromString("fd00::1");
    const auto link_local = *IpAddress::FromString("fe80::1");
    const std::vector<IpAddress> candidates{global, unique_local, link_local};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_EQ(*selected.v6, link_local);  // overall pick unchanged: link-local first
    ASSERT_TRUE(selected.v6_routable.has_value());
    EXPECT_EQ(*selected.v6_routable, unique_local);  // routable pick: ULA over GUA
}

TEST(SelectSourceAddressesTest, RoutableIpv6FallsBackToGlobal) {
    const auto global = *IpAddress::FromString("2001:db8::1");
    const auto link_local = *IpAddress::FromString("fe80::1");
    const std::vector<IpAddress> candidates{global, link_local};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6_routable.has_value());
    EXPECT_EQ(*selected.v6_routable, global);
}

TEST(SelectSourceAddressesTest, NoRoutableIpv6WhenOnlyLinkLocal) {
    const auto link_local = *IpAddress::FromString("fe80::1");
    const std::vector<IpAddress> candidates{link_local};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6.has_value());
    EXPECT_FALSE(selected.v6_routable.has_value());  // a link-local never masquerades as routable
}

TEST(SelectSourceAddressesTest, OtherIpv6IsARoutableLastResort) {
    // Same last-resort policy as the overall pick: an interface with only an unusual non-link-local
    // address (::1 here) still resolves a routable source rather than nothing.
    const auto other = *IpAddress::FromString("::1");
    const std::vector<IpAddress> candidates{other};

    InterfaceAddresses selected;
    detail::SelectSourceAddresses(candidates, selected);

    ASSERT_TRUE(selected.v6_routable.has_value());
    EXPECT_EQ(*selected.v6_routable, other);
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

#if !defined(__linux__)

// --- BSD getifaddrs pure helpers (the resolver itself needs a real interface) ---

namespace {

// An AF_LINK sockaddr_dl carrying `name` then `mac` in sdl_data, with sdl_len (the sa_len the reader
// bounds against) set to `sa_len`. Short inputs fit sdl_data, so a plain sockaddr_dl backs it.
sockaddr_dl MakeLinkSockaddr(std::string_view name, std::span<const std::byte> mac, uint8_t sa_len) {
    sockaddr_dl sdl{};
    sdl.sdl_family = AF_LINK;
    sdl.sdl_nlen = static_cast<unsigned char>(name.size());
    sdl.sdl_alen = static_cast<unsigned char>(mac.size());
    sdl.sdl_len = sa_len;
    std::memcpy(sdl.sdl_data, name.data(), name.size());
    std::memcpy(sdl.sdl_data + name.size(), mac.data(), mac.size());
    return sdl;
}

constexpr uint8_t LinkSaLen(size_t name_len, size_t mac_len) {
    return static_cast<uint8_t>(offsetof(sockaddr_dl, sdl_data) + name_len + mac_len);
}

}  // namespace

TEST(MacFromLinkSockaddrTest, ReadsMacAtTheNameDependentOffset) {
    // The MAC sits after the 3-char name in sdl_data; a correct read skips the name.
    const std::array<std::byte, 6> mac{std::byte{0x02}, std::byte{0x11}, std::byte{0x22},
        std::byte{0x33}, std::byte{0x44}, std::byte{0x55}};
    const auto sdl = MakeLinkSockaddr("en0", mac, LinkSaLen(3, 6));

    const auto parsed = detail::MacFromLinkSockaddr(reinterpret_cast<const sockaddr&>(sdl));
    EXPECT_EQ(parsed, *MacAddress::FromString("02:11:22:33:44:55"));
}

TEST(MacFromLinkSockaddrTest, YieldsZeroWhenTheLinkCarriesNoAddress) {
    // A loopback-style AF_LINK entry has sdl_alen 0 (no hardware address) -> all-zero MAC.
    const auto sdl = MakeLinkSockaddr("lo0", {}, LinkSaLen(3, 0));

    EXPECT_EQ(detail::MacFromLinkSockaddr(reinterpret_cast<const sockaddr&>(sdl)), MacAddress{});
}

TEST(MacFromLinkSockaddrTest, YieldsZeroWhenTheMacWouldRunPastSaLen) {
    // sdl_alen claims 6 but sa_len stops one byte short of the MAC's end: refuse rather than over-read.
    const std::array<std::byte, 6> mac{std::byte{0x02}, std::byte{0x11}, std::byte{0x22},
        std::byte{0x33}, std::byte{0x44}, std::byte{0x55}};
    const auto sdl = MakeLinkSockaddr("en0", mac, LinkSaLen(3, 6) - 1);

    EXPECT_EQ(detail::MacFromLinkSockaddr(reinterpret_cast<const sockaddr&>(sdl)), MacAddress{});
}

TEST(Ipv6SourceFlagsUsableTest, AcceptsAUsableAddress) {
    EXPECT_TRUE(detail::Ipv6SourceFlagsUsable(0));
    EXPECT_TRUE(detail::Ipv6SourceFlagsUsable(IN6_IFF_AUTOCONF));  // a benign flag, not in the reject set
}

TEST(Ipv6SourceFlagsUsableTest, RejectsEachUnusableFlag) {
    for (const int flag : {IN6_IFF_TENTATIVE, IN6_IFF_DUPLICATED, IN6_IFF_DETACHED,
                           IN6_IFF_DEPRECATED, IN6_IFF_ANYCAST}) {
        EXPECT_FALSE(detail::Ipv6SourceFlagsUsable(flag)) << "flag " << flag;
        EXPECT_FALSE(detail::Ipv6SourceFlagsUsable(flag | IN6_IFF_AUTOCONF)) << "flag " << flag;
    }
}

TEST(CanonicalizeLinkLocalV6Test, ClearsTheEmbeddedKameScopeId) {
    // KAME stashes the interface index in bytes 2-3 of a link-local sin6_addr; canonicalizing zeroes
    // just those, leaving fe80:: and the interface id intact.
    auto bytes = IpAddress::FromString("fe80::1")->Bytes();
    bytes[2] = std::byte{0x00};
    bytes[3] = std::byte{0x05};  // scope id 5 embedded KAME-style
    const auto canonical = detail::CanonicalizeLinkLocalV6(IpAddress::FromV6Bytes(bytes));

    EXPECT_EQ(canonical, *IpAddress::FromString("fe80::1"));
}

TEST(CanonicalizeLinkLocalV6Test, LeavesACanonicalAddressUnchanged) {
    const auto canonical = *IpAddress::FromString("fe80::1");
    EXPECT_EQ(detail::CanonicalizeLinkLocalV6(canonical), canonical);
}

#endif

}  // namespace reflector
