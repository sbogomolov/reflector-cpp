#include "reflector/udp_socket.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <fcntl.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <format>
#include <string>
#include <sys/socket.h>
#include <utility>

using namespace reflector;

namespace {

IpAddress OtherLoopbackFor(IpAddress::Family family) {
    return family == IpAddress::Family::V6 ? IpAddress::LoopbackV4() : IpAddress::LoopbackV6();
}

IpAddress BoundIpAddress(const UdpSocket& socket) {
    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    if (getsockname(socket.Fd(), reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ADD_FAILURE() << "getsockname failed for fd " << socket.Fd() << ": " << std::strerror(errno);
        return LoopbackFor(socket.AddressFamily());
    }

    const auto ip = IpAddress::FromSockaddr(reinterpret_cast<const sockaddr*>(&address));
    if (!ip) {
        ADD_FAILURE() << "getsockname returned an unsupported address family";
        return LoopbackFor(socket.AddressFamily());
    }
    return *ip;
}

std::string FamilyName(const ::testing::TestParamInfo<IpAddress::Family>& info) {
    return std::format("{}", info.param);
}

class UdpSocketPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family> {};

INSTANTIATE_TEST_SUITE_P(
    Families,
    UdpSocketPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    FamilyName);

} // namespace

TEST_P(UdpSocketPerFamilyTest, ConstructsValidSocket) {
    UdpSocket sock{GetParam()};
    EXPECT_TRUE(sock.IsValid());
    EXPECT_GE(sock.Fd(), 0);
    EXPECT_EQ(sock.AddressFamily(), GetParam());
}

TEST_P(UdpSocketPerFamilyTest, ConstructsNonBlockingSocket) {
    UdpSocket sock{GetParam()};

    const auto flags = fcntl(sock.Fd(), F_GETFL, 0);
    ASSERT_GE(flags, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0);
}

TEST_P(UdpSocketPerFamilyTest, SetReuseAddrOnValidSocketSucceeds) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.SetReuseAddr(true));
}

TEST_P(UdpSocketPerFamilyTest, BindToEphemeralPortSucceeds) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.Bind(0));
}

TEST_P(UdpSocketPerFamilyTest, BindToLoopbackSucceeds) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.Bind(LoopbackFor(GetParam()), 0));
}

TEST_P(UdpSocketPerFamilyTest, SetInterfaceWithUnknownNameFails) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.SetInterface("nonexistent-iface-xyz"));
}

TEST_P(UdpSocketPerFamilyTest, BindRejectsAddressFromOtherFamily) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.Bind(OtherLoopbackFor(GetParam()), 0));
}

TEST_P(UdpSocketPerFamilyTest, SendToRejectsAddressFromOtherFamily) {
    UdpSocket sock{GetParam()};
    ASSERT_TRUE(sock.IsValid());

    const std::array payload{std::byte{0x01}};
    EXPECT_FALSE(sock.SendTo(payload, OtherLoopbackFor(GetParam()), 9));
}

TEST_P(UdpSocketPerFamilyTest, MoveConstructTransfersOwnershipFamilyAndBinding) {
    UdpSocket src{GetParam()};
    ASSERT_TRUE(src.IsValid());
    const auto port = BindLoopback(src);
    const auto ip = BoundIpAddress(src);
    const int fd = src.Fd();

    UdpSocket dst{std::move(src)};
    EXPECT_TRUE(dst.IsValid());
    EXPECT_EQ(dst.Fd(), fd);
    EXPECT_EQ(dst.AddressFamily(), GetParam());
    EXPECT_EQ(BoundIpAddress(dst), ip);
    EXPECT_EQ(BoundPort(dst), port);
    EXPECT_FALSE(src.IsValid()); // NOLINT(bugprone-use-after-move)
}

TEST_P(UdpSocketPerFamilyTest, MoveAssignTransfersOwnershipFamilyAndBinding) {
    UdpSocket src{GetParam()};
    UdpSocket dst{GetParam() == IpAddress::Family::V6 ? IpAddress::Family::V4 : IpAddress::Family::V6};
    ASSERT_TRUE(src.IsValid());
    ASSERT_TRUE(dst.IsValid());
    const auto port = BindLoopback(src);
    const auto ip = BoundIpAddress(src);
    const int fd = src.Fd();

    dst = std::move(src);
    EXPECT_TRUE(dst.IsValid());
    EXPECT_EQ(dst.Fd(), fd);
    EXPECT_EQ(dst.AddressFamily(), GetParam());
    EXPECT_EQ(BoundIpAddress(dst), ip);
    EXPECT_EQ(BoundPort(dst), port);
    EXPECT_FALSE(src.IsValid()); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SelfMoveAssignmentKeepsSocketValid) {
    UdpSocket sock{IpAddress::Family::V4};
    ASSERT_TRUE(sock.IsValid());

    auto& ref = sock;
    sock = std::move(ref);
    EXPECT_TRUE(sock.IsValid());
}

TEST(UdpSocketTest, SetBroadcastOnValidSocketSucceeds) {
    UdpSocket sock{IpAddress::Family::V4};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.SetBroadcast(true));
}

TEST(UdpSocketTest, SetBroadcastOnMovedFromSocketFails) {
    UdpSocket src{IpAddress::Family::V4};
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.SetBroadcast(true)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SetReuseAddrOnMovedFromSocketFails) {
    UdpSocket src{IpAddress::Family::V4};
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.SetReuseAddr(true)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, BindOnMovedFromSocketFails) {
    UdpSocket src{IpAddress::Family::V4};
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.Bind(0)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SendToOnMovedFromSocketFails) {
    UdpSocket src{IpAddress::Family::V4};
    UdpSocket dst{std::move(src)};

    const std::array payload{std::byte{0x01}};
    EXPECT_FALSE(src.SendTo(payload, IpAddress::LoopbackV4(), 9)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, CloseInvalidatesSocket) {
    UdpSocket sock{IpAddress::Family::V4};
    ASSERT_TRUE(sock.IsValid());

    sock.Close();
    EXPECT_FALSE(sock.IsValid());
    EXPECT_LT(sock.Fd(), 0);
}

TEST(UdpSocketTest, CloseIsIdempotent) {
    UdpSocket sock{IpAddress::Family::V4};
    sock.Close();
    sock.Close();
    EXPECT_FALSE(sock.IsValid());
}

TEST(UdpSocketTest, OperationsOnClosedSocketFail) {
    UdpSocket sock{IpAddress::Family::V4};
    sock.Close();

    EXPECT_FALSE(sock.SetBroadcast(true));
    EXPECT_FALSE(sock.SetReuseAddr(true));
    EXPECT_FALSE(sock.Bind(0));
}

TEST(UdpSocketTest, SetV6OnlySucceedsOnV6Socket) {
    UdpSocket sock{IpAddress::Family::V6};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.SetV6Only(true));
}

TEST(UdpSocketTest, SetV6OnlyFailsOnV4Socket) {
    UdpSocket sock{IpAddress::Family::V4};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.SetV6Only(true));
}

TEST(UdpSocketTest, SetMulticastInterfaceFailsOnV4Socket) {
    UdpSocket sock{IpAddress::Family::V4};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.SetMulticastInterface("nonexistent-iface-xyz"));
}

TEST(UdpSocketTest, SetMulticastInterfaceWithUnknownNameFailsOnV6Socket) {
    UdpSocket sock{IpAddress::Family::V6};
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.SetMulticastInterface("nonexistent-iface-xyz"));
}
