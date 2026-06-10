#include "reflector/ip_endpoint.h"

#include <gtest/gtest.h>

#include <format>
#include <unordered_set>
#include <netinet/in.h>
#include <sys/socket.h>

namespace reflector {

TEST(IpEndpointTest, EqualityComparesAddrAndPort) {
    const IpEndpoint a{IpAddress::LoopbackV4(), 8080};
    const IpEndpoint b{IpAddress::LoopbackV4(), 8080};

    EXPECT_EQ(a, b);
    EXPECT_NE(a, (IpEndpoint{IpAddress::LoopbackV4(), 80}));
    EXPECT_NE(a, (IpEndpoint{IpAddress::LoopbackV6(), 8080}));
}

TEST(IpEndpointTest, FormatsAsUrlAuthority) {
    EXPECT_EQ(std::format("{}", IpEndpoint{IpAddress::LoopbackV4(), 8080}), "127.0.0.1:8080");
    EXPECT_EQ(std::format("{}", IpEndpoint{IpAddress::LoopbackV6(), 8080}), "[::1]:8080");
}

TEST(IpEndpointTest, ToFromSockaddrRoundTripsV4) {
    const IpEndpoint original{IpAddress::FromV4Bytes(10, 1, 3, 80), 1461};
    sockaddr_storage storage{};
    const auto len = original.ToSockaddr(storage);
    EXPECT_EQ(len, sizeof(sockaddr_in));
    EXPECT_EQ(storage.ss_family, AF_INET);

    const auto parsed = IpEndpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&storage));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, original);
}

TEST(IpEndpointTest, ToFromSockaddrRoundTripsV6) {
    const auto addr = IpAddress::FromString("fe80::1");
    ASSERT_TRUE(addr.has_value());
    const IpEndpoint original{*addr, 36866};
    sockaddr_storage storage{};
    const auto len = original.ToSockaddr(storage);
    EXPECT_EQ(len, sizeof(sockaddr_in6));
    EXPECT_EQ(storage.ss_family, AF_INET6);

    const auto parsed = IpEndpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&storage));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, original);
}

TEST(IpEndpointTest, IsUsableAsHashKey) {
    std::unordered_set<IpEndpoint> set;
    set.insert({IpAddress::LoopbackV4(), 80});
    set.insert({IpAddress::LoopbackV4(), 80});  // duplicate
    set.insert({IpAddress::LoopbackV4(), 81});

    EXPECT_EQ(set.size(), 2u);
    EXPECT_TRUE(set.contains(IpEndpoint{IpAddress::LoopbackV4(), 80}));
}

} // namespace reflector
