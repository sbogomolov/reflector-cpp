#include "reflector/tcp_socket.h"

#include "reflector/ip_address.h"
#include "reflector/ip_endpoint.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>

namespace reflector {
namespace {

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out(text.size());
    std::memcpy(out.data(), text.data(), text.size());
    return out;
}

bool WaitFor(int fd, short events, int timeout_ms = 1000) {
    pollfd pfd{.fd = fd, .events = events, .revents = 0};
    return ::poll(&pfd, 1, timeout_ms) > 0;
}
bool WaitReadable(int fd) { return WaitFor(fd, POLLIN); }
bool WaitWritable(int fd) { return WaitFor(fd, POLLOUT); }

// Move-assigns through two distinct references so a self-assignment call site (`MoveAssignInPlace(s, s)`)
// doesn't trip -Wself-move while still exercising operator='s `this != &other` guard.
void MoveAssignInPlace(TcpSocket& dst, TcpSocket& src) { dst = std::move(src); }

// ---- TcpSocket over real loopback, parameterized over IPv4 / IPv6 ----

class TcpSocketFamilyTest : public ::testing::TestWithParam<IpAddress::Family> {
protected:
    IpAddress Loopback() const {
        return GetParam() == IpAddress::Family::V6 ? IpAddress::LoopbackV6() : IpAddress::LoopbackV4();
    }

    struct Pair {
        TcpSocket client;
        TcpSocket server;
    };

    // Listen / Connect / Accept / FinishConnect on loopback, returning the established client+server.
    std::optional<Pair> EstablishedPair() {
        auto listener = TcpSocket::Listen({Loopback(), 0});
        if (!listener) {
            return std::nullopt;
        }
        const auto local = listener->LocalEndpoint();
        if (!local) {
            return std::nullopt;
        }
        auto client = TcpSocket::Connect(*local, {Loopback(), 0});
        if (!client || !WaitReadable(listener->Fd())) {
            return std::nullopt;
        }
        auto server = listener->Accept();
        if (!server || !WaitWritable(client->Fd()) || client->FinishConnect() != IoStatus::Ok) {
            return std::nullopt;
        }
        return Pair{std::move(*client), std::move(*server)};
    }
};

INSTANTIATE_TEST_SUITE_P(Families, TcpSocketFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const auto& family_info) { return family_info.param == IpAddress::Family::V6 ? "V6" : "V4"; });

TEST_P(TcpSocketFamilyTest, ListenAssignsAnEphemeralPort) {
    auto listener = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(listener.has_value());
    const auto local = listener->LocalEndpoint();
    ASSERT_TRUE(local.has_value());
    EXPECT_EQ(local->addr, Loopback());
    EXPECT_NE(local->port, 0);
}

TEST_P(TcpSocketFamilyTest, MoveTransfersTheFdAndInvalidatesTheSource) {
    auto opened = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(opened.has_value());
    TcpSocket listener = std::move(*opened);
    const int fd = listener.Fd();

    const TcpSocket moved = std::move(listener);
    EXPECT_EQ(moved.Fd(), fd);
    EXPECT_TRUE(moved.IsValid());
    EXPECT_FALSE(listener.IsValid());     // NOLINT(bugprone-use-after-move) — asserting the moved-from state
    EXPECT_FALSE(listener.WantsWrite());  // NOLINT(bugprone-use-after-move) — and it requests nothing from the dispatcher
}

TEST_P(TcpSocketFamilyTest, MoveConstructionTransfersConnectingState) {
    auto listener = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(listener.has_value());
    const auto local = listener->LocalEndpoint();
    ASSERT_TRUE(local.has_value());

    auto client = TcpSocket::Connect(*local, {Loopback(), 0});
    ASSERT_TRUE(client.has_value());
    ASSERT_TRUE(client->IsConnecting());

    const TcpSocket moved = std::move(*client);
    EXPECT_TRUE(moved.IsConnecting());     // connecting_ followed the move
    EXPECT_TRUE(moved.WantsWrite());
    EXPECT_FALSE(client->IsConnecting());  // NOLINT(bugprone-use-after-move)
}

TEST_P(TcpSocketFamilyTest, MoveAssignmentTransfersFdAndClosesDestination) {
    auto dst = TcpSocket::Listen({Loopback(), 0});
    auto src = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(dst.has_value() && src.has_value());
    const int dst_old_fd = dst->Fd();
    const int src_fd = src->Fd();
    ASSERT_NE(dst_old_fd, src_fd);

    *dst = std::move(*src);
    EXPECT_EQ(dst->Fd(), src_fd);                     // dst adopted src's fd
    EXPECT_TRUE(dst->IsValid());
    EXPECT_FALSE(src->IsValid());                     // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(::fcntl(dst_old_fd, F_GETFD), -1);      // dst's previous fd was closed (no leak)
    EXPECT_EQ(errno, EBADF);
}

TEST_P(TcpSocketFamilyTest, SelfMoveAssignmentIsANoOp) {
    auto sock = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(sock.has_value());
    const int fd = sock->Fd();

    MoveAssignInPlace(*sock, *sock);  // operator='s `this != &other` guard keeps the fd intact
    EXPECT_TRUE(sock->IsValid());
    EXPECT_EQ(sock->Fd(), fd);
    EXPECT_NE(::fcntl(fd, F_GETFD), -1);  // not closed
}

TEST_P(TcpSocketFamilyTest, ConnectStartsConnectingThenFinishConnectEstablishes) {
    auto listener = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(listener.has_value());
    const auto local = listener->LocalEndpoint();
    ASSERT_TRUE(local.has_value());

    auto client = TcpSocket::Connect(*local, {Loopback(), 0});
    ASSERT_TRUE(client.has_value());
    EXPECT_TRUE(client->IsConnecting());  // the CONNECTING start, asserted directly (not laundered through a helper)
    EXPECT_TRUE(client->WantsWrite());    // connecting wants the writable edge

    ASSERT_TRUE(WaitReadable(listener->Fd()));
    auto server = listener->Accept();
    ASSERT_TRUE(server.has_value());
    EXPECT_FALSE(server->IsConnecting());  // an accepted socket is established by construction
    EXPECT_FALSE(server->WantsWrite());

    ASSERT_TRUE(WaitWritable(client->Fd()));
    EXPECT_EQ(client->FinishConnect(), IoStatus::Ok);
    EXPECT_FALSE(client->IsConnecting());  // the connecting -> established transition, asserted
    EXPECT_FALSE(client->WantsWrite());    // nothing buffered once established
}

TEST_P(TcpSocketFamilyTest, ForwardsBytesAndSurfacesEof) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    const auto msg = Bytes("hello dial");
    EXPECT_EQ(pair->client.Send(msg), SendStatus::Ok);

    ASSERT_TRUE(WaitReadable(pair->server.Fd()));
    std::byte buf[64];
    const auto read = pair->server.Read(buf);
    EXPECT_EQ(read.status, IoStatus::Ok);
    EXPECT_EQ(read.bytes, msg.size());

    // Peer closes -> the other side reads EOF.
    pair->client.Close();
    ASSERT_TRUE(WaitReadable(pair->server.Fd()));
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::Closed);
}

TEST_P(TcpSocketFamilyTest, ReadOnIdleSocketWouldBlock) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());
    std::byte buf[16];
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::WouldBlock);
}

TEST_P(TcpSocketFamilyTest, SendBuffersTheTailAndFlushDrainsItInOrder) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // Every byte sent carries a continuing 0..255 ramp, so the receiver can verify exact ORDER and
    // content — not merely the byte count.
    uint8_t next = 0;
    auto next_chunk = [&next](size_t size) {
        std::vector<std::byte> c(size);
        for (std::byte& b : c) {
            b = std::byte{next++};
        }
        return c;
    };
    std::vector<std::byte> sent;

    // The server never reads, so keep sending until the kernel buffer fills and Send must buffer a tail.
    while (!pair->client.WantsWrite()) {
        const auto chunk = next_chunk(4 * 1024);
        ASSERT_EQ(pair->client.Send(chunk), SendStatus::Ok);
        sent.insert(sent.end(), chunk.begin(), chunk.end());
        ASSERT_LT(sent.size(), 16u * 1024u * 1024u) << "kernel buffer never filled";
    }
    // A few more small sends with the buffer already non-empty exercise the append-in-order path (Send skips
    // the write-through and the tail follows the backlog) — kept well under MAX_SEND_BUFFER alongside the
    // already-buffered tail.
    for (int i = 0; i < 3; ++i) {
        const auto chunk = next_chunk(512);
        ASSERT_EQ(pair->client.Send(chunk), SendStatus::Ok);
        sent.insert(sent.end(), chunk.begin(), chunk.end());
    }

    // Drain: flush the client tail and read everything on the server until both are exhausted.
    std::vector<std::byte> received;
    std::vector<std::byte> buf(64 * 1024);
    for (int guard = 0; guard < 1000000 && (pair->client.WantsWrite() || received.size() < sent.size());
         ++guard) {
        if (pair->client.WantsWrite()) {
            ASSERT_NE(pair->client.Flush(), SendStatus::Error);
        }
        const auto read = pair->server.Read(buf);
        if (read.status == IoStatus::Ok) {
            received.insert(received.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(read.bytes));
        } else if (read.status == IoStatus::WouldBlock) {
            if (pair->client.WantsWrite()) {
                WaitWritable(pair->client.Fd());
            } else {
                WaitReadable(pair->server.Fd());
            }
        } else {
            break;  // Closed/Error — unexpected
        }
    }
    EXPECT_EQ(received, sent);                 // exact bytes, in order — not just the count
    EXPECT_FALSE(pair->client.WantsWrite());   // fully drained
}

TEST_P(TcpSocketFamilyTest, SendBeyondCapAborts) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // The server never reads: once the kernel buffer fills, the send buffer fills with each chunk until the
    // next would exceed the cap -> Send returns Overflow (the owner drops the connection).
    const std::vector<std::byte> chunk(8 * 1024, std::byte{0x42});
    for (int i = 0; i < 100000; ++i) {
        const auto status = pair->client.Send(chunk);
        if (status == SendStatus::Overflow) {
            SUCCEED();
            return;
        }
        ASSERT_EQ(status, SendStatus::Ok);
    }
    FAIL() << "Send never overflowed the cap";
}

TEST_P(TcpSocketFamilyTest, AcceptWithNoPendingConnectionReturnsNullopt) {
    auto listener = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(listener.has_value());
    EXPECT_FALSE(listener->Accept().has_value());  // EAGAIN on a non-blocking listener — not an error
}

TEST_P(TcpSocketFamilyTest, PeerEndpointMatchesTheOtherSidesLocalEndpoint) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());
    const auto client_local = pair->client.LocalEndpoint();
    const auto client_peer = pair->client.PeerEndpoint();
    const auto server_local = pair->server.LocalEndpoint();
    const auto server_peer = pair->server.PeerEndpoint();
    ASSERT_TRUE(client_local && client_peer && server_local && server_peer);
    EXPECT_EQ(*client_peer, *server_local);
    EXPECT_EQ(*server_peer, *client_local);
}

TEST_P(TcpSocketFamilyTest, ConnectToARefusedPortFails) {
    // Bind then close a listener to obtain a loopback port with nothing listening on it.
    auto listener = TcpSocket::Listen({Loopback(), 0});
    ASSERT_TRUE(listener.has_value());
    const auto dead = listener->LocalEndpoint();
    ASSERT_TRUE(dead.has_value());
    listener->Close();

    // The refusal surfaces either synchronously (Connect -> nullopt, common on loopback) or, if the
    // connect started, on the writable edge as FinishConnect -> Error with connecting_ left set.
    auto client = TcpSocket::Connect(*dead, {Loopback(), 0});
    if (!client.has_value()) {
        SUCCEED() << "refused synchronously at connect()";
        return;
    }
    EXPECT_TRUE(client->IsConnecting());
    ASSERT_TRUE(WaitWritable(client->Fd()));  // poll returns on POLLERR too
    EXPECT_EQ(client->FinishConnect(), IoStatus::Error);
    EXPECT_TRUE(client->IsConnecting());  // only a successful FinishConnect clears the flag
}

TEST_P(TcpSocketFamilyTest, ReadReturnsErrorOnResetDistinctFromClosed) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // SO_LINGER with a zero timeout makes close() send an RST instead of an orderly FIN, so the peer's
    // next Read sees a fatal error rather than EOF — exercising IoStatus::Error vs IoStatus::Closed.
    const linger reset_on_close{.l_onoff = 1, .l_linger = 0};
    ASSERT_EQ(::setsockopt(pair->client.Fd(), SOL_SOCKET, SO_LINGER, &reset_on_close, sizeof(reset_on_close)), 0);
    pair->client.Close();

    ASSERT_TRUE(WaitReadable(pair->server.Fd()));
    std::byte buf[16];
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::Error);  // RST -> Error, never Closed
}

// SO_BINDTODEVICE (Linux) needs CAP_NET_RAW, so the egress-pinned Connect sits behind the root fixture
// (runs as root under docker; skipped on an unprivileged plain ctest).
class TcpSocketRequiresRootTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "egress-pin (SO_BINDTODEVICE / IP_BOUND_IF) needs privilege";
        }
    }
};

TEST_F(TcpSocketRequiresRootTest, EgressPinnedConnectReachesLoopback) {
    const unsigned ifindex = if_nametoindex(std::string(LoopbackInterface()).c_str());
    ASSERT_NE(ifindex, 0u);

    auto listener = TcpSocket::Listen({IpAddress::LoopbackV4(), 0});
    ASSERT_TRUE(listener.has_value());
    const auto local = listener->LocalEndpoint();
    ASSERT_TRUE(local.has_value());

    // ifindex != 0 exercises PinEgress (SO_BINDTODEVICE / IP_BOUND_IF); pinned to lo, the loopback
    // connect still completes.
    auto client = TcpSocket::Connect(*local, {IpAddress::LoopbackV4(), 0}, ifindex);
    ASSERT_TRUE(client.has_value());

    ASSERT_TRUE(WaitReadable(listener->Fd()));
    auto server = listener->Accept();
    ASSERT_TRUE(server.has_value());
    ASSERT_TRUE(WaitWritable(client->Fd()));
    EXPECT_EQ(client->FinishConnect(), IoStatus::Ok);
}

} // namespace
} // namespace reflector
