#include "reflector/udp_socket.h"

#include <gtest/gtest.h>

#include <fcntl.h>

#include <array>
#include <cstddef>
#include <utility>

using namespace reflector;

TEST(UdpSocketTest, DefaultConstructsValidSocket) {
    UdpSocket sock;
    EXPECT_TRUE(sock.IsValid());
    EXPECT_GE(sock.Fd(), 0);
}

TEST(UdpSocketTest, DefaultConstructsNonBlockingSocket) {
    UdpSocket sock;

    const auto flags = fcntl(sock.Fd(), F_GETFL, 0);
    ASSERT_GE(flags, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0);
}

TEST(UdpSocketTest, MoveConstructTransfersOwnership) {
    UdpSocket src;
    ASSERT_TRUE(src.IsValid());

    UdpSocket dst{std::move(src)};
    EXPECT_TRUE(dst.IsValid());
    EXPECT_FALSE(src.IsValid()); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, MoveAssignTransfersOwnership) {
    UdpSocket src;
    UdpSocket dst;
    ASSERT_TRUE(src.IsValid());
    ASSERT_TRUE(dst.IsValid());

    dst = std::move(src);
    EXPECT_TRUE(dst.IsValid());
    EXPECT_FALSE(src.IsValid()); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SelfMoveAssignmentKeepsSocketValid) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());

    auto& ref = sock;
    sock = std::move(ref);
    EXPECT_TRUE(sock.IsValid());
}

TEST(UdpSocketTest, SetBroadcastOnValidSocketSucceeds) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.SetBroadcast(true));
}

TEST(UdpSocketTest, SetBroadcastOnMovedFromSocketFails) {
    UdpSocket src;
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.SetBroadcast(true)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SetReuseAddrOnValidSocketSucceeds) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.SetReuseAddr(true));
}

TEST(UdpSocketTest, SetReuseAddrOnMovedFromSocketFails) {
    UdpSocket src;
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.SetReuseAddr(true)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, BindToEphemeralPortSucceeds) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());
    EXPECT_TRUE(sock.Bind(0));
}

TEST(UdpSocketTest, BindOnMovedFromSocketFails) {
    UdpSocket src;
    UdpSocket dst{std::move(src)};

    EXPECT_FALSE(src.Bind(0)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SendToOnMovedFromSocketFails) {
    UdpSocket src;
    UdpSocket dst{std::move(src)};

    const std::array payload{std::byte{0x01}};
    EXPECT_FALSE(src.SendTo(payload, IpAddress::Loopback(), 9)); // NOLINT(bugprone-use-after-move)
}

TEST(UdpSocketTest, SetInterfaceWithUnknownNameFails) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());
    EXPECT_FALSE(sock.SetInterface("nonexistent-iface-xyz"));
}

TEST(UdpSocketTest, CloseInvalidatesSocket) {
    UdpSocket sock;
    ASSERT_TRUE(sock.IsValid());

    sock.Close();
    EXPECT_FALSE(sock.IsValid());
    EXPECT_LT(sock.Fd(), 0);
}

TEST(UdpSocketTest, CloseIsIdempotent) {
    UdpSocket sock;
    sock.Close();
    sock.Close();
    EXPECT_FALSE(sock.IsValid());
}

TEST(UdpSocketTest, OperationsOnClosedSocketFail) {
    UdpSocket sock;
    sock.Close();

    EXPECT_FALSE(sock.SetBroadcast(true));
    EXPECT_FALSE(sock.SetReuseAddr(true));
    EXPECT_FALSE(sock.Bind(0));
}
