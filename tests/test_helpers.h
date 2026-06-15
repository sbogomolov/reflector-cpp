#pragma once

#include "mocks/fake_interface.h"
#include "reflector/config/config.h"
#include "reflector/interface.h"
#include "reflector/ip_address.h"
#include "reflector/logger.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"
#include "reflector/packet_dispatcher.h"
#include "reflector/raw_socket.h"
#include "reflector/util/narrow_cast.h"

#include "util/udp_socket.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if !defined(__linux__)
#include <net/bpf.h>
#endif

namespace reflector {

// Builds a Config programmatically for tests, bypassing TOML parsing. Declared a friend of
// Config so it can populate the otherwise file-only fields directly.
class TestConfigBuilder {
public:
    TestConfigBuilder& Add(WolConfig wol) {
        config_.wol_configs_.push_back(std::move(wol));
        return *this;
    }

    TestConfigBuilder& Add(MdnsConfig mdns) {
        config_.mdns_configs_.push_back(std::move(mdns));
        return *this;
    }

    TestConfigBuilder& Add(SsdpConfig ssdp) {
        config_.ssdp_configs_.push_back(std::move(ssdp));
        return *this;
    }

    [[nodiscard]] Config Build() const { return config_; }

private:
    Config config_;
};

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
        source_ip = packet.header.source.addr;
    }

    int count = 0;
    std::vector<std::byte> payload;
    std::optional<IpAddress> source_ip;
};

// Counts packets and, on each dispatch, resets the registration pointed at by
// `registration_to_reset` (if any). Used to exercise the dispatcher's behaviour when a
// callback drops its own (or another) registration mid-dispatch. `reset_result` captures
// the return value of Reset() so callers can assert on it.
struct UnregisteringPacketCounter {
    void OnPacket(const Packet&) {
        ++count;
        if (registration_to_reset != nullptr && registration_to_reset->IsValid()) {
            reset_result = registration_to_reset->Reset();
        }
    }

    PacketDispatcher::Registration* registration_to_reset = nullptr;
    bool reset_result = false;
    int count = 0;
};

inline Packet MakePacket(IpAddress source_ip = IpAddress::FromV4Bytes(192, 0, 2, 1),
    uint16_t source_port = 12345, uint16_t dest_port = 9, uint8_t ttl = 64) {
    return Packet{
        .header = PacketHeader{
            .source = {source_ip, source_port},
            .dest = {source_ip.IsV4() ? IpAddress::BroadcastV4() : IpAddress::AllNodesLinkLocalV6(), dest_port},
            .ttl = ttl,
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
    EXPECT_TRUE(socket.Bind({LoopbackFor(socket.AddressFamily()), port}));
    const auto bound_port = BoundPort(socket);
    EXPECT_NE(bound_port, 0);
    return bound_port;
}

// Loopback interface name varies by OS; "lo" on Linux, "lo0" on macOS and FreeBSD.
inline std::string_view LoopbackInterface() noexcept {
#if defined(__linux__)
    return "lo";
#else
    return "lo0";
#endif
}

// Opens a real RawSocket on the loopback interface to probe whether the running
// user has the privileges needed (CAP_NET_RAW on Linux, bpf-group / root on macOS). Tests
// that need real capture call this in SetUp and GTEST_SKIP if it returns false. Cached:
// the probe is destructive enough (open + close) that we only want to pay it once per run.
inline bool HasPacketCapturePrivileges() {
    static const bool cached = [] {
        bool valid = false;
        CaptureStdout([&] {
            const Interface loopback{LoopbackInterface()};
            RawSocket probe{loopback};
            valid = probe.IsValid();
        });
        return valid;
    }();
    return cached;
}

// Protocol constants used by the frame helpers below. Kept here so any test that builds
// or inspects raw Ethernet frames has a single source of truth.
constexpr uint16_t IPV4_ETHERTYPE = 0x0800;
constexpr uint16_t IPV6_ETHERTYPE = 0x86dd;
constexpr uint16_t ARP_ETHERTYPE = 0x0806;
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr uint8_t IPV6_NEXT_HOPOPT = 0;

inline void AppendBytes(std::vector<std::byte>& out, std::span<const std::byte> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

inline void AppendU16Be(std::vector<std::byte>& out, uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

inline void AppendIpv4(std::vector<std::byte>& out, const IpAddress& ip) {
    AppendBytes(out, std::span{ip.Bytes().data(), 4});
}

inline void AppendIpv6(std::vector<std::byte>& out, const IpAddress& ip) {
    AppendBytes(out, ip.Bytes());
}

inline void AppendMac(std::vector<std::byte>& out, const MacAddress& mac) {
    AppendBytes(out, mac.Bytes());
}

inline std::vector<std::byte> MakeBytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value & 0xff));
    }
    return bytes;
}

// Builds an Ethernet/IPv4/IPv6 + UDP frame byte-by-byte for tests that need to drive
// the RawSocket parser end-to-end (either via the friend ParseFrame hook in
// RawSocketTest, or via TestCaptureSocket::WriteFrame for full PollOnce flow).
struct FrameBuilder {
    std::vector<std::byte> bytes;

    void AppendEthernet(const MacAddress& dst, const MacAddress& src, uint16_t ethertype) {
        AppendMac(bytes, dst);
        AppendMac(bytes, src);
        AppendU16Be(bytes, ethertype);
    }

    void AppendLoopback(uint32_t family) {
        std::byte buf[4];
        std::memcpy(buf, &family, sizeof(family));
        AppendBytes(bytes, std::span{buf, 4});
    }

    void AppendIPv4Header(const IpAddress& src, const IpAddress& dst, uint8_t protocol,
        uint16_t total_length, uint16_t flags_fragment = 0, uint8_t ihl_words = 5, uint8_t ttl = 64) {
        bytes.push_back(static_cast<std::byte>((4u << 4) | (ihl_words & 0x0f))); // version+IHL
        bytes.push_back(std::byte{0x00});                                         // DSCP/ECN
        AppendU16Be(bytes, total_length);                                         // total length
        AppendU16Be(bytes, 0);                                                    // identification
        AppendU16Be(bytes, flags_fragment);                                       // flags + fragment offset
        bytes.push_back(static_cast<std::byte>(ttl));                             // TTL
        bytes.push_back(static_cast<std::byte>(protocol));                        // protocol
        AppendU16Be(bytes, 0);                                                    // header checksum (ignored)
        AppendIpv4(bytes, src);
        AppendIpv4(bytes, dst);
        // Pad to ihl_words * 4 bytes if requested IHL is larger than the minimum 20.
        const size_t want = static_cast<size_t>(ihl_words) * 4;
        const size_t have = 20;
        if (want > have) {
            bytes.insert(bytes.end(), want - have, std::byte{0});
        }
    }

    void AppendIPv6Header(const IpAddress& src, const IpAddress& dst, uint8_t next_header,
        uint16_t payload_length, uint8_t version = 6, uint8_t hop_limit = 64) {
        bytes.push_back(static_cast<std::byte>(version << 4));                    // version + traffic class hi
        bytes.push_back(std::byte{0x00});                                         // traffic class lo + flow hi
        AppendU16Be(bytes, 0);                                                    // flow lo
        AppendU16Be(bytes, payload_length);                                       // payload length
        bytes.push_back(static_cast<std::byte>(next_header));                     // next header
        bytes.push_back(static_cast<std::byte>(hop_limit));                       // hop limit
        AppendIpv6(bytes, src);
        AppendIpv6(bytes, dst);
    }

    void AppendUdp(uint16_t src_port, uint16_t dst_port, uint16_t udp_length) {
        AppendU16Be(bytes, src_port);
        AppendU16Be(bytes, dst_port);
        AppendU16Be(bytes, udp_length);
        AppendU16Be(bytes, 0); // checksum (ignored)
    }

    void AppendPayload(std::span<const std::byte> payload) {
        AppendBytes(bytes, payload);
    }
};

// Wraps a SOCK_DGRAM socketpair into a RawSocket-shaped object so tests can
// either: (a) register against the dispatcher and synthesize Packets via the friend
// DispatchPacket hook, or (b) write real Ethernet frame bytes through WriteFrame and let
// the production Receive/ParseFrame path consume them end-to-end. SOCK_DGRAM (rather than
// pipe()) preserves message boundaries — Linux's AF_PACKET delivers one frame per recv,
// and the socketpair mimics that. The read end is non-blocking to match production.
struct TestCaptureSocket {
    int write_fd = -1;
    // Declared before `socket`: the socket keeps a reference to it for its lifetime. Empty
    // addresses, matching what a test-only socket used to resolve (nothing).
    FakeInterface iface;
    RawSocket socket;

    explicit TestCaptureSocket(std::string_view interface = "test")
            : iface{interface, 0, {}}, socket{MakeSocket()} {}

    TestCaptureSocket(const TestCaptureSocket&) = delete;
    TestCaptureSocket& operator=(const TestCaptureSocket&) = delete;

    ~TestCaptureSocket() {
        if (write_fd >= 0) {
            ::close(write_fd);
        }
    }

    // Sends one Ethernet frame to the capture socket in the format the production Receive
    // expects. Linux: raw bytes (AF_PACKET delivers one frame per recv). macOS: prepend a
    // synthesized bpf_hdr and BPF_WORDALIGN-pad so Receive's bpf_hdr walker consumes one
    // record per call.
    bool WriteFrame(std::span<const std::byte> frame) {
        return WriteRaw(EncodeFrame(frame));
    }

#if !defined(__linux__)
    // Packs multiple frames into a single BPF batch so one read() returns all of them and
    // Receive's batch walker steps through them on successive calls. macOS-only because
    // Linux's AF_PACKET preserves message boundaries — a Linux multi-frame "batch" would
    // need separate datagrams, which is just multiple WriteFrame calls.
    bool WriteFrameBatch(std::span<const std::span<const std::byte>> frames) {
        std::vector<std::byte> batch;
        for (const auto& frame : frames) {
            const auto encoded = EncodeFrame(frame);
            AppendBytes(batch, encoded);
        }
        return WriteRaw(batch);
    }

    // Writes one frame whose bpf_hdr reports more original bytes (bh_datalen) than were captured
    // (bh_caplen = frame.size()), as BPF does when a packet is too big for the capture buffer.
    bool WriteTruncatedFrame(std::span<const std::byte> frame, uint32_t original_length) {
        return WriteRaw(EncodeFrame(frame, original_length));
    }
#endif

private:
    RawSocket MakeSocket() {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
            ADD_FAILURE() << "socketpair() failed: " << std::strerror(errno);
            return RawSocket::ForTesting(iface, -1);
        }
        if (::fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) {
            ADD_FAILURE() << "fcntl(O_NONBLOCK) failed: " << std::strerror(errno);
            ::close(fds[0]);
            ::close(fds[1]);
            return RawSocket::ForTesting(iface, -1);
        }
        write_fd = fds[1];
        return RawSocket::ForTesting(iface, fds[0]);
    }

    static std::vector<std::byte> EncodeFrame(std::span<const std::byte> frame) {
        return EncodeFrame(frame, narrow_cast<uint32_t>(frame.size()));
    }

    // original_length sets bh_datalen; pass a value larger than frame.size() to model a frame BPF
    // truncated to fit the buffer. Ignored on Linux, which has no bpf_hdr.
    static std::vector<std::byte> EncodeFrame(std::span<const std::byte> frame, [[maybe_unused]] uint32_t original_length) {
#if !defined(__linux__)
        bpf_hdr header{};
        header.bh_hdrlen = static_cast<u_short>(BPF_WORDALIGN(sizeof(bpf_hdr)));
        header.bh_caplen = static_cast<bpf_u_int32>(frame.size());
        header.bh_datalen = static_cast<bpf_u_int32>(original_length);
        const auto record_size = BPF_WORDALIGN(header.bh_hdrlen + frame.size());
        std::vector<std::byte> buffer(record_size, std::byte{0});
        std::memcpy(buffer.data(), &header, sizeof(header));
        std::memcpy(buffer.data() + header.bh_hdrlen, frame.data(), frame.size());
        return buffer;
#else
        return std::vector<std::byte>{frame.begin(), frame.end()};
#endif
    }

    bool WriteRaw(std::span<const std::byte> bytes) {
        if (write_fd < 0) {
            return false;
        }
        const auto n = ::write(write_fd, bytes.data(), bytes.size());
        return n == static_cast<ssize_t>(bytes.size());
    }
};

struct LoopbackReceiver {
    UdpSocket socket;
    PacketRecorder recorder;

    explicit LoopbackReceiver(uint16_t port, IpAddress::Family family) : socket{family} {
        BindLoopback(socket, port);
    }

    [[nodiscard]] uint16_t Port() const { return BoundPort(socket); }

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
                .source = {source_ip.value_or(LoopbackFor(socket.AddressFamily()))},
                .dest = {LoopbackFor(socket.AddressFamily())},
            },
            .payload = std::span<const std::byte>{buffer.data(), static_cast<size_t>(bytes)},
        };
        recorder.OnPacket(packet);
        return true;
    }
};

} // namespace reflector
