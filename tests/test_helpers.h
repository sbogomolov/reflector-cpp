#pragma once

#include "reflector/dispatcher.h"
#include "reflector/logger.h"
#include "reflector/packet.h"
#include "reflector/packet_capture_socket.h"
#include "reflector/udp_socket.h"
#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace reflector {

class ScopedMinLogLevel {
public:
    explicit ScopedMinLogLevel(LogLevel level) noexcept : previous_{Logger::MinLevel()} {
        Logger::SetMinLevel(level);
    }

    ~ScopedMinLogLevel() noexcept {
        Logger::SetMinLevel(previous_);
    }

private:
    LogLevel previous_;
};

template <typename Fn>
std::string CaptureStdout(Fn&& fn) {
    testing::internal::CaptureStdout();
    std::forward<Fn>(fn)();
    std::fflush(stdout);
    return testing::internal::GetCapturedStdout();
}

struct PacketCounter {
    void OnPacket(const Packet&) { ++count; }

    int count = 0;
};

struct PacketRecorder {
    void OnPacket(const Packet& packet) {
        ++count;
        payload.assign(packet.payload.begin(), packet.payload.end());
        source_ip = packet.header.source_ip;
    }

    int count = 0;
    std::vector<std::byte> payload;
    std::optional<IpAddress> source_ip;
};

inline Packet MakePacket(IpAddress source_ip = IpAddress::FromV4Bytes(192, 0, 2, 1),
    uint16_t source_port = 12345, uint16_t dest_port = 9) {
    return Packet{
        .header = PacketHeader{
            .source_ip = source_ip,
            .dest_ip = source_ip.IsV4() ? IpAddress::BroadcastV4() : IpAddress::AllNodesLinkLocalV6(),
            .source_port = source_port,
            .dest_port = dest_port,
        },
        .payload = {},
    };
}

inline IpAddress LoopbackFor(IpAddress::Family family) {
    return family == IpAddress::Family::V6 ? IpAddress::LoopbackV6() : IpAddress::LoopbackV4();
}

inline uint16_t BoundPort(const UdpSocket& socket) {
    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    if (getsockname(socket.Fd(), reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ADD_FAILURE() << "getsockname failed for fd " << socket.Fd() << ": " << std::strerror(errno);
        return 0;
    }
    if (address.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
}

inline uint16_t BindLoopback(UdpSocket& socket, uint16_t port = 0) {
    EXPECT_TRUE(socket.SetReuseAddr(true));
    EXPECT_TRUE(socket.Bind(LoopbackFor(socket.AddressFamily()), port));
    const auto bound_port = BoundPort(socket);
    EXPECT_NE(bound_port, 0);
    return bound_port;
}

inline std::vector<uint16_t> FreeLoopbackPorts(size_t count, IpAddress::Family family) {
    std::vector<UdpSocket> sockets;
    std::vector<uint16_t> ports;
    sockets.reserve(count);
    ports.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        auto& socket = sockets.emplace_back(family);
        EXPECT_TRUE(socket.SetReuseAddr(true));
        EXPECT_TRUE(socket.Bind(LoopbackFor(family), 0));
        ports.push_back(BoundPort(socket));
    }

    return ports;
}

inline uint16_t FreeLoopbackPort(IpAddress::Family family) {
    const auto ports = FreeLoopbackPorts(1, family);
    return ports.front();
}

// Loopback interface name varies by OS; "lo" on Linux, "lo0" on macOS.
inline std::string_view LoopbackInterface() noexcept {
#if defined(__APPLE__)
    return "lo0";
#else
    return "lo";
#endif
}

// Opens a real PacketCaptureSocket on the loopback interface to probe whether the running
// user has the privileges needed (CAP_NET_RAW on Linux, bpf-group / root on macOS). Tests
// that need real capture call this in SetUp and GTEST_SKIP if it returns false. Cached:
// the probe is destructive enough (open + close) that we only want to pay it once per run.
inline bool HasPacketCapturePrivileges() {
    static const bool cached = [] {
        bool valid = false;
        (void)CaptureStdout([&] {
            PacketCaptureSocket probe{LoopbackInterface()};
            valid = probe.IsValid();
        });
        return valid;
    }();
    return cached;
}

// Wraps a SOCK_DGRAM socketpair into a PacketCaptureSocket-shaped object so tests can
// register against the dispatcher and then call DispatchPacket directly via the friend
// declarations. SOCK_DGRAM (rather than pipe()) preserves message boundaries — Linux's
// AF_PACKET delivers one frame per recv, and the socketpair mimics that. The read end
// is non-blocking to match production.
struct TestCaptureSocket {
    int write_fd = -1;
    PacketCaptureSocket socket;

    explicit TestCaptureSocket(std::string_view interface = "test") : socket{MakeSocket(interface)} {}

    TestCaptureSocket(const TestCaptureSocket&) = delete;
    TestCaptureSocket& operator=(const TestCaptureSocket&) = delete;

    ~TestCaptureSocket() {
        if (write_fd >= 0) {
            ::close(write_fd);
        }
    }

private:
    PacketCaptureSocket MakeSocket(std::string_view interface) {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
            ADD_FAILURE() << "socketpair() failed: " << std::strerror(errno);
            return PacketCaptureSocket::ForTesting(interface, -1);
        }
        if (::fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) {
            ADD_FAILURE() << "fcntl(O_NONBLOCK) failed: " << std::strerror(errno);
            ::close(fds[0]);
            ::close(fds[1]);
            return PacketCaptureSocket::ForTesting(interface, -1);
        }
        write_fd = fds[1];
        return PacketCaptureSocket::ForTesting(interface, fds[0]);
    }
};

struct LoopbackReceiver {
    UdpSocket socket;
    PacketRecorder recorder;

    explicit LoopbackReceiver(uint16_t port, IpAddress::Family family) : socket{family} {
        BindLoopback(socket, port);
    }

    [[nodiscard]] uint16_t Port() const { return BoundPort(socket); }

    // Polls the socket for one datagram and records it. Returns true if a packet arrived.
    bool PollOnce(std::chrono::milliseconds timeout) {
        pollfd pfd{.fd = socket.Fd(), .events = POLLIN, .revents = 0};
        const auto ready = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
        if (ready <= 0) {
            return false;
        }

        std::vector<std::byte> buffer(64 * 1024);
        sockaddr_storage source{};
        socklen_t source_size = sizeof(source);
        const auto bytes = ::recvfrom(socket.Fd(), buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&source), &source_size);
        if (bytes <= 0) {
            return false;
        }
        const auto source_ip = IpAddress::FromSockaddr(reinterpret_cast<const sockaddr*>(&source));
        Packet packet{
            .header = PacketHeader{
                .source_ip = source_ip.value_or(LoopbackFor(socket.AddressFamily())),
                .dest_ip = LoopbackFor(socket.AddressFamily()),
            },
            .payload = std::span<const std::byte>{buffer.data(), static_cast<size_t>(bytes)},
        };
        recorder.OnPacket(packet);
        return true;
    }
};

} // namespace reflector
