#include "reflector/tcp_socket.h"

#include "mocks/fake_interface.h"
#include "reflector/interface.h"
#include "reflector/ip_address.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <array>
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

namespace {

using namespace reflector;

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

// The name of a host interface whose IPv6 source resolves to a link-local address, or empty when
// none exists (the link-local tests then skip). macOS lo0 always carries fe80::1; in the docker
// gate the container's eth0 carries one.
std::string FindLinkLocalInterfaceName() {
    auto* names = ::if_nameindex();
    if (names == nullptr) {
        return {};
    }
    std::string found;
    for (auto* entry = names; entry->if_index != 0 && entry->if_name != nullptr; ++entry) {
        const Interface candidate{entry->if_name};
        const auto v6 = candidate.SourceAddress(IpAddress::Family::V6);
        if (candidate.IsValid() && v6 && v6->IsLinkLocal()) {
            found = entry->if_name;
            break;
        }
    }
    ::if_freenameindex(names);
    return found;
}

} // namespace

namespace reflector {

// ---- TcpSocket over real loopback, parameterized over IPv4 / IPv6 ----

class TcpSocketFamilyTest : public ::testing::TestWithParam<IpAddress::Family> {
protected:
    // Defaults to loopback sources for both families, so Listen(iface, GetParam()) binds loopback.
    FakeInterface iface;

    IpAddress Loopback() const {
        return GetParam() == IpAddress::Family::V6 ? IpAddress::LoopbackV6() : IpAddress::LoopbackV4();
    }

    struct Pair {
        TcpSocket client;
        TcpSocket server;
    };

    // Listen / Connect / Accept / FinishConnect on loopback, returning the established client+server.
    std::optional<Pair> EstablishedPair() {
        auto listener = TcpSocket::Listen(iface, GetParam());
        if (!listener) {
            return std::nullopt;
        }
        const auto& local = listener->LocalEndpoint();
        auto client = TcpSocket::Connect(local);
        if (!client || !WaitReadable(listener->Fd())) {
            return std::nullopt;
        }
        auto server = listener->Accept();
        if (!server || !WaitWritable(client->Fd()) || !client->FinishConnect()) {
            return std::nullopt;
        }
        return Pair{std::move(*client), std::move(*server)};
    }
};

INSTANTIATE_TEST_SUITE_P(Families, TcpSocketFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const auto& family_info) { return family_info.param == IpAddress::Family::V6 ? "V6" : "V4"; });

TEST_P(TcpSocketFamilyTest, ListenAssignsAnEphemeralPort) {
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    const auto& local = listener->LocalEndpoint();
    EXPECT_EQ(local.addr, Loopback());
    EXPECT_NE(local.port, 0);
    EXPECT_FALSE(listener->PeerEndpoint().has_value());  // a listener has no connected peer
}

TEST_P(TcpSocketFamilyTest, ListenBindsTheRequestedPort) {
    // Find a free port by binding ephemeral first; the probe is closed before the explicit bind,
    // and SO_REUSEADDR covers the lingering TIME_WAIT state (same pattern as the refused-connect
    // test below).
    auto probe = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(probe.has_value());
    const uint16_t port = probe->LocalEndpoint().port;
    probe->Close();

    auto listener = TcpSocket::Listen(iface, GetParam(), port);
    ASSERT_TRUE(listener.has_value());
    EXPECT_EQ(listener->LocalEndpoint().port, port);
}

TEST_P(TcpSocketFamilyTest, ListenWithoutSourceAddressFails) {
    const FakeInterface empty{"empty0", 0, {}};  // no source address for either family
    CaptureStdout([&] {  // swallow the expected "no source address" error; nullopt is the contract
        EXPECT_FALSE(TcpSocket::Listen(empty, GetParam()).has_value());
    });
}

TEST_P(TcpSocketFamilyTest, MoveTransfersTheFdAndInvalidatesTheSource) {
    auto opened = TcpSocket::Listen(iface, GetParam());
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
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    const auto& local = listener->LocalEndpoint();

    auto client = TcpSocket::Connect(local);
    ASSERT_TRUE(client.has_value());
    ASSERT_TRUE(client->IsConnecting());

    const TcpSocket moved = std::move(*client);
    EXPECT_TRUE(moved.IsConnecting());     // connecting_ followed the move
    EXPECT_TRUE(moved.WantsWrite());
    EXPECT_FALSE(client->IsConnecting());  // NOLINT(bugprone-use-after-move)
}

TEST_P(TcpSocketFamilyTest, MoveAssignmentTransfersFdAndClosesDestination) {
    auto dst = TcpSocket::Listen(iface, GetParam());
    auto src = TcpSocket::Listen(iface, GetParam());
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
    auto sock = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(sock.has_value());
    const int fd = sock->Fd();

    MoveAssignInPlace(*sock, *sock);  // operator='s `this != &other` guard keeps the fd intact
    EXPECT_TRUE(sock->IsValid());
    EXPECT_EQ(sock->Fd(), fd);
    EXPECT_NE(::fcntl(fd, F_GETFD), -1);  // not closed
}

TEST_P(TcpSocketFamilyTest, ConnectStartsConnectingThenFinishConnectEstablishes) {
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    const auto& local = listener->LocalEndpoint();

    auto client = TcpSocket::Connect(local);
    ASSERT_TRUE(client.has_value());
    EXPECT_TRUE(client->IsConnecting());  // the CONNECTING start, asserted directly (not laundered through a helper)
    EXPECT_TRUE(client->WantsWrite());    // connecting wants the writable edge

    ASSERT_TRUE(WaitReadable(listener->Fd()));
    auto server = listener->Accept();
    ASSERT_TRUE(server.has_value());
    EXPECT_FALSE(server->IsConnecting());  // an accepted socket is established by construction
    EXPECT_FALSE(server->WantsWrite());

    ASSERT_TRUE(WaitWritable(client->Fd()));
    EXPECT_TRUE(client->FinishConnect());
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

    pair->client.Close();
    ASSERT_TRUE(WaitReadable(pair->server.Fd()));
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::Closed);
}

TEST_P(TcpSocketFamilyTest, ShutdownSendsFinButKeepsTheFdOpen) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // Shutdown half-closes (sends a FIN) so the peer reads EOF, but unlike Close() it keeps the fd: the
    // owner can shut a connection down promptly yet leave RAII to close the descriptor later.
    pair->client.Shutdown();
    EXPECT_TRUE(pair->client.IsValid());  // fd still owned
    ASSERT_TRUE(WaitReadable(pair->server.Fd()));
    std::byte buf[16];
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::Closed);
}

TEST_P(TcpSocketFamilyTest, ShutdownOnAnUnconnectedSocketIsHarmless) {
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    listener->Shutdown();  // ENOTCONN on a never-connected socket -> best-effort no-op, fd still valid
    EXPECT_TRUE(listener->IsValid());
}

TEST_P(TcpSocketFamilyTest, ReadOnIdleSocketWouldBlock) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());
    std::byte buf[16];
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::WouldBlock);
}

// A zero-length Read must report WouldBlock, never Closed — recv() of 0 bytes returns 0, the same as an
// orderly EOF. The DIAL forward path Reads into the receive buffer's free tail, which is empty when the
// buffer is full; misreading that as a peer close would abort the connection. Proven against a socket that
// has ACTUALLY received a FIN: the empty Read still says WouldBlock, and the real EOF survives for the next
// non-empty Read.
TEST_P(TcpSocketFamilyTest, EmptySpanReadIsWouldBlockNotEof) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    pair->client.Close();  // peer sends FIN -> a genuine EOF is now pending on the server side
    ASSERT_TRUE(WaitReadable(pair->server.Fd()));

    EXPECT_EQ(pair->server.Read(std::span<std::byte>{}).status, IoStatus::WouldBlock);  // not Closed
    std::byte buf[16];
    EXPECT_EQ(pair->server.Read(buf).status, IoStatus::Closed);  // the pending EOF is still there to read
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
            ASSERT_TRUE(pair->client.Flush());
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

// ---- Scatter-gather Send ----

// The AppendUnsent boundary-walk is private; this fixture is TcpSocket's friend — the named
// `reflector::TcpSocketTest` the friend declaration refers to (an anonymous-namespace fixture
// would be a different class and get no access) — and exposes the walk for a chosen
// `already_sent`, since a live socket can't be steered onto an exact chunk seam.
class TcpSocketTest : public ::testing::Test {
protected:
    static bool AppendUnsent(StreamBuffer& buf, std::span<const std::span<const std::byte>> chunks,
        size_t already_sent) {
        return TcpSocket::AppendUnsent(buf, chunks, already_sent);
    }
};

// AppendUnsent is the heart of the scatter Send: after a partial sendmsg it buffers the bytes past
// `already_sent`, walked across the chunk boundary. A live socket can't be made to partial on an exact seam
// (kernel partial-write slop), so each boundary — inside the header, exactly on the header/body seam, inside
// the body — is driven here with a chosen count, no socket involved.
TEST_F(TcpSocketTest, WalksTheHeaderBodyBoundaryForEveryPartialCount) {
    std::array<std::byte, 10> header_storage;
    for (size_t i = 0; i < header_storage.size(); ++i) {
        header_storage[i] = std::byte{static_cast<uint8_t>(0x10 + i)};
    }
    std::array<std::byte, 20> body_storage;
    for (size_t i = 0; i < body_storage.size(); ++i) {
        body_storage[i] = std::byte{static_cast<uint8_t>(0x20 + i)};
    }
    const std::array<std::span<const std::byte>, 2> chunks{
        std::span<const std::byte>{header_storage}, std::span<const std::byte>{body_storage}};

    auto expect_tail_from = [&](size_t already_sent) {
        std::vector<std::byte> want;
        for (const std::span<const std::byte> chunk : chunks) {
            want.insert(want.end(), chunk.begin(), chunk.end());
        }
        want.erase(want.begin(), want.begin() + static_cast<std::ptrdiff_t>(already_sent));

        StreamBuffer buf{1024};
        ASSERT_TRUE(AppendUnsent(buf, chunks, already_sent));
        const std::span<const std::byte> got = buf.View();
        EXPECT_EQ(std::vector<std::byte>(got.begin(), got.end()), want) << "already_sent=" << already_sent;
    };

    expect_tail_from(0);   // WouldBlock: nothing sent -> the whole header then body
    expect_tail_from(4);   // part of the header sent -> header[4:] then body
    expect_tail_from(10);  // header exactly fully sent -> exactly the body (not re-emitted, not dropped)
    expect_tail_from(15);  // full header + part of the body -> body[5:]
    expect_tail_from(30);  // everything sent -> nothing buffered
}

TEST_F(TcpSocketTest, ReportsOverflowWhenTheTailDoesNotFit) {
    std::array<std::byte, 10> header_storage{};
    std::array<std::byte, 20> body_storage{};
    const std::array<std::span<const std::byte>, 2> chunks{
        std::span<const std::byte>{header_storage}, std::span<const std::byte>{body_storage}};

    StreamBuffer too_small{25};  // below the 30-byte total
    EXPECT_FALSE(AppendUnsent(too_small, chunks, 0));  // the 30-byte tail does not fit (a chunk Append fails)

    StreamBuffer fits{25};
    EXPECT_TRUE(AppendUnsent(fits, chunks, 6));  // a 24-byte tail (6 already sent) fits
    EXPECT_EQ(fits.Size(), 24u);
}

TEST_F(TcpSocketTest, HandlesEmptyChunksInTheWalk) {
    const std::array<std::byte, 4> body_storage{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::span<const std::byte> empty{};
    const std::span<const std::byte> body{body_storage};
    // Leading and trailing empty chunks contribute nothing and must not shift the boundary walk.
    const std::array<std::span<const std::byte>, 3> chunks{empty, body, empty};

    StreamBuffer buf{64};
    ASSERT_TRUE(AppendUnsent(buf, chunks, 1));  // one body byte already sent
    const std::span<const std::byte> got = buf.View();
    const std::vector<std::byte> want(body_storage.begin() + 1, body_storage.end());
    EXPECT_EQ(std::vector<std::byte>(got.begin(), got.end()), want);
}

TEST_P(TcpSocketFamilyTest, ScatterSendDeliversHeaderThenBodyInOrder) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    const std::vector<std::byte> header = Bytes("HEADER-");
    const std::vector<std::byte> body = Bytes("body-payload");
    const std::array<std::span<const std::byte>, 2> chunks{
        std::span<const std::byte>{header}, std::span<const std::byte>{body}};
    ASSERT_EQ(pair->client.Send(chunks), SendStatus::Ok);
    EXPECT_FALSE(pair->client.WantsWrite());  // loopback takes the few bytes at once — nothing buffered

    std::vector<std::byte> expected = header;
    expected.insert(expected.end(), body.begin(), body.end());

    std::vector<std::byte> received;
    std::vector<std::byte> buf(256);
    while (received.size() < expected.size() && WaitReadable(pair->server.Fd())) {
        const IoResult read = pair->server.Read(buf);
        ASSERT_EQ(read.status, IoStatus::Ok);
        received.insert(received.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(read.bytes));
    }
    EXPECT_EQ(received, expected);  // header first, then body — one ordered message
}

TEST_P(TcpSocketFamilyTest, ScatterSendBehindABacklogDrainsInOrder) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // Every byte is a continuing 0..255 ramp, so the receiver verifies exact ORDER and content across the
    // backlog/header/body seams — not merely the count.
    uint8_t next = 0;
    auto ramp = [&next](size_t size) {
        std::vector<std::byte> c(size);
        for (std::byte& b : c) {
            b = std::byte{next++};
        }
        return c;
    };
    std::vector<std::byte> sent;

    // Back the socket's own send buffer up first (the server never reads), so the scatter Send below appends
    // behind a non-empty backlog rather than writing through — deterministic on every platform, unlike forcing
    // a kernel-level partial (Linux receive-buffer autotuning makes "kernel full" a moving target).
    while (!pair->client.WantsWrite()) {
        const auto chunk = ramp(4 * 1024);
        ASSERT_EQ(pair->client.Send(std::span<const std::byte>{chunk}), SendStatus::Ok);
        sent.insert(sent.end(), chunk.begin(), chunk.end());
        ASSERT_LT(sent.size(), 16u * 1024u * 1024u) << "kernel buffer never filled";
    }

    // The scatter Send queues header+body behind the backlog, in order (already_sent==0, append-only path).
    const auto header = ramp(40);
    const auto body = ramp(2048);
    const std::array<std::span<const std::byte>, 2> chunks{
        std::span<const std::byte>{header}, std::span<const std::byte>{body}};
    ASSERT_EQ(pair->client.Send(chunks), SendStatus::Ok);
    EXPECT_TRUE(pair->client.WantsWrite());
    sent.insert(sent.end(), header.begin(), header.end());
    sent.insert(sent.end(), body.begin(), body.end());

    // Drain: flush the client tail and read on the server until both are exhausted; bytes must match exactly.
    std::vector<std::byte> received;
    std::vector<std::byte> buf(64 * 1024);
    for (int guard = 0; guard < 1000000 && (pair->client.WantsWrite() || received.size() < sent.size());
         ++guard) {
        if (pair->client.WantsWrite()) {
            ASSERT_TRUE(pair->client.Flush());
        }
        const IoResult read = pair->server.Read(buf);
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
    EXPECT_EQ(received, sent);                 // exact bytes, in order across every seam
    EXPECT_FALSE(pair->client.WantsWrite());   // fully drained
}

TEST_P(TcpSocketFamilyTest, ScatterSendCoalescesMoreChunksThanTheIovecCapInOrder) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // More non-empty chunks than the iovec holds (MAX_SEND_CHUNKS): the first batch rides one sendmsg, the
    // rest fall through to the send buffer (a nonzero already_sent landing on a chunk boundary, wired through
    // the real Send). All must arrive in order. Storage is filled fully before any span is taken, so the
    // spans never dangle across a vector realloc.
    std::vector<std::vector<std::byte>> storage;
    std::vector<std::byte> expected;
    for (int i = 0; i < 12; ++i) {  // > MAX_SEND_CHUNKS (8)
        storage.push_back(Bytes("chunk" + std::to_string(i) + "/"));
        expected.insert(expected.end(), storage.back().begin(), storage.back().end());
    }
    std::vector<std::span<const std::byte>> chunks;
    for (const std::vector<std::byte>& s : storage) {
        chunks.push_back(std::span<const std::byte>{s});
    }
    ASSERT_EQ(pair->client.Send(chunks), SendStatus::Ok);

    std::vector<std::byte> received;
    std::vector<std::byte> buf(1024);
    for (int guard = 0; guard < 1000000 && received.size() < expected.size(); ++guard) {
        if (pair->client.WantsWrite()) {
            ASSERT_TRUE(pair->client.Flush());
        }
        const IoResult read = pair->server.Read(buf);
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
    EXPECT_EQ(received, expected);
}

TEST_P(TcpSocketFamilyTest, ScatterSendBeyondCapAborts) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());

    // Persistently fill the kernel so every scatter Send buffers; the send buffer then fills until a Send's
    // tail would exceed the 8KB cap -> Overflow (the owner aborts). The scatter analogue of SendBeyondCapAborts,
    // exercising the scatter Send's overflow path on a live socket.
    const std::array<std::byte, 4096> filler{};
    while (true) {
#if defined(__linux__)
        const ssize_t w = ::send(pair->client.Fd(), filler.data(), filler.size(), MSG_NOSIGNAL);
#else
        const ssize_t w = ::send(pair->client.Fd(), filler.data(), filler.size(), 0);
#endif
        if (w > 0) {
            continue;
        }
        ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
        if (!WaitFor(pair->client.Fd(), POLLOUT, 100)) {
            break;
        }
    }

    const std::vector<std::byte> header = Bytes("H:");
    const std::vector<std::byte> body = Bytes(std::string(4096, 'b'));
    const std::array<std::span<const std::byte>, 2> chunks{
        std::span<const std::byte>{header}, std::span<const std::byte>{body}};
    for (int i = 0; i < 100000; ++i) {
        const SendStatus status = pair->client.Send(chunks);
        if (status == SendStatus::Overflow) {
            SUCCEED();
            return;
        }
        ASSERT_EQ(status, SendStatus::Ok);
    }
    FAIL() << "scatter Send never overflowed the cap";
}

TEST_P(TcpSocketFamilyTest, AcceptWithNoPendingConnectionReturnsNullopt) {
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    EXPECT_FALSE(listener->Accept().has_value());  // EAGAIN on a non-blocking listener — not an error
}

TEST_P(TcpSocketFamilyTest, PeerEndpointMatchesTheOtherSidesLocalEndpoint) {
    auto pair = EstablishedPair();
    ASSERT_TRUE(pair.has_value());
    const auto& client_local = pair->client.LocalEndpoint();
    const auto& client_peer = pair->client.PeerEndpoint();
    const auto& server_local = pair->server.LocalEndpoint();
    const auto& server_peer = pair->server.PeerEndpoint();
    ASSERT_TRUE(client_peer.has_value() && server_peer.has_value());
    EXPECT_EQ(*client_peer, server_local);
    EXPECT_EQ(*server_peer, client_local);
}

TEST_P(TcpSocketFamilyTest, ConnectToARefusedPortFails) {
    // Bind then close a listener to obtain a loopback port with nothing listening on it.
    auto listener = TcpSocket::Listen(iface, GetParam());
    ASSERT_TRUE(listener.has_value());
    const auto dead = listener->LocalEndpoint();
    listener->Close();

    // The refusal surfaces either synchronously (Connect -> nullopt, common on loopback) or, if the
    // connect started, on the writable edge as FinishConnect -> Error with connecting_ left set.
    auto client = TcpSocket::Connect(dead);
    if (!client) {
        SUCCEED() << "refused synchronously at connect()";
        return;
    }
    EXPECT_TRUE(client->IsConnecting());
    ASSERT_TRUE(WaitWritable(client->Fd()));  // poll returns on POLLERR too
    EXPECT_FALSE(client->FinishConnect());
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
    const Interface loopback{LoopbackInterface()};
    ASSERT_TRUE(loopback.IsValid());

    auto listener = TcpSocket::Listen(loopback, IpAddress::Family::V4);
    ASSERT_TRUE(listener.has_value());
    const auto& local = listener->LocalEndpoint();

    // A nonzero-index interface exercises PinEgress (SO_BINDTODEVICE / IP_BOUND_IF); pinned to lo,
    // the loopback connect still completes.
    auto client = TcpSocket::Connect(local, &loopback);
    ASSERT_TRUE(client.has_value());

    ASSERT_TRUE(WaitReadable(listener->Fd()));
    auto server = listener->Accept();
    ASSERT_TRUE(server.has_value());
    ASSERT_TRUE(WaitWritable(client->Fd()));
    EXPECT_TRUE(client->FinishConnect());
}

// ---- link-local IPv6: the scope-id pass-through ----

// Binding a link-local source needs the interface index as the sockaddr scope id — the kernel
// refuses the bind without it — so this fails if Listen drops the scope. Needs no privilege
// (the address is already assigned); skipped only when no interface carries a link-local source.
TEST(TcpSocketLinkLocalTest, ListenScopesTheLinkLocalBind) {
    const auto name = FindLinkLocalInterfaceName();
    if (name.empty()) {
        GTEST_SKIP() << "no interface with a link-local IPv6 source";
    }
    const Interface iface{name};
    ASSERT_TRUE(iface.IsValid());

    auto listener = TcpSocket::Listen(iface, IpAddress::Family::V6);
    ASSERT_TRUE(listener.has_value());
    EXPECT_EQ(listener->LocalEndpoint().addr, *iface.SourceAddress(IpAddress::Family::V6));
    EXPECT_NE(listener->LocalEndpoint().port, 0);
}

// The full link-local round trip: Connect scopes both the source bind and the link-local
// destination with the egress interface's index. Root-gated because the nonzero index also
// triggers the egress pin (SO_BINDTODEVICE needs CAP_NET_RAW on Linux).
TEST_F(TcpSocketRequiresRootTest, LinkLocalConnectCompletesWithEgressScope) {
    const auto name = FindLinkLocalInterfaceName();
    if (name.empty()) {
        GTEST_SKIP() << "no interface with a link-local IPv6 source";
    }
    const Interface iface{name};
    ASSERT_TRUE(iface.IsValid());

    auto listener = TcpSocket::Listen(iface, IpAddress::Family::V6);
    ASSERT_TRUE(listener.has_value());

    auto client = TcpSocket::Connect(listener->LocalEndpoint(), &iface);
    ASSERT_TRUE(client.has_value());
    ASSERT_TRUE(WaitReadable(listener->Fd()));
    auto server = listener->Accept();
    ASSERT_TRUE(server.has_value());
    ASSERT_TRUE(WaitWritable(client->Fd()));
    EXPECT_TRUE(client->FinishConnect());
}

} // namespace reflector
