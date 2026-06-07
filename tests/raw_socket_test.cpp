#include "reflector/raw_socket.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"
#include "util/udp_socket.h"

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <net/if.h>
#include <optional>
#include <poll.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr auto WAIT_BUDGET = std::chrono::milliseconds{2000};
constexpr auto POLL_SLICE_MS = 100;
constexpr uint16_t INJECT_SRC_PORT = 40000;
constexpr uint16_t INJECT_DST_PORT = 40009;

// Creates a connected virtual-interface pair for the test's lifetime (veth on Linux, feth on
// macOS) so a frame injected on the first interface is received on the second. Needs root
// (interface creation is CAP_NET_ADMIN), so IsValid() is false otherwise — and on any setup
// failure — for callers to GTEST_SKIP. We shell out to ip/ifconfig because there is no portable
// syscall for macOS feth peering. Only interfaces we created are torn down.
class InterfacePair {
public:
    InterfacePair() {
        if (geteuid() != 0) {
            return;  // interface creation needs root
        }
#if defined(__linux__)
        // veth names are arbitrary, so make them unique per process to avoid colliding with an
        // existing interface.
        const auto suffix = std::to_string(getpid());
        inject_ = "rflv" + suffix + "a";
        receive_ = "rflv" + suffix + "b";
        if (!Run("ip link add " + inject_ + " type veth peer name " + receive_)) {
            return;
        }
        created_ = true;  // one command creates the pair; deleting `inject_` removes both
        // Manual link-locals with nodad so both ends are usable immediately, no DAD wait; the
        // inject side also needs IPv4 for the broadcast test.
        valid_ = Run("ip addr add 10.99.0.1/24 dev " + inject_)
            && Run("ip -6 addr add fe80::1/64 dev " + inject_ + " nodad")
            && Run("ip -6 addr add fe80::2/64 dev " + receive_ + " nodad")
            && Run("ip link set " + inject_ + " up")
            && Run("ip link set " + receive_ + " up");
#elif defined(__APPLE__)
        // feth interfaces are numbered; let the kernel assign the next free unit (its name is
        // printed by `ifconfig feth create`) so we never collide with an existing feth.
        inject_ = RunCapture("ifconfig feth create");
        if (inject_.empty()) {
            return;
        }
        created_inject_ = true;
        receive_ = RunCapture("ifconfig feth create");
        if (receive_.empty()) {
            Destroy();
            return;
        }
        created_receive_ = true;
        // feth has no automatic IPv6 link-local, so assign one on each end explicitly: the inject
        // side for a correctly-scoped source for ff02::, the receive side so a link-local-scoped
        // multicast join can resolve to it.
        valid_ = Run("ifconfig " + inject_ + " peer " + receive_)
            && Run("ifconfig " + inject_ + " inet 10.99.0.1/24 up")
            && Run("ifconfig " + inject_ + " inet6 fe80::1 prefixlen 64")
            && Run("ifconfig " + receive_ + " up")
            && Run("ifconfig " + receive_ + " inet6 fe80::2 prefixlen 64");
#endif
        if (!valid_) {
            Destroy();
        }
    }

    InterfacePair(const InterfacePair&) = delete;
    InterfacePair& operator=(const InterfacePair&) = delete;

    ~InterfacePair() { Destroy(); }

    [[nodiscard]] bool IsValid() const noexcept { return valid_; }
    [[nodiscard]] const std::string& InjectInterface() const noexcept { return inject_; }
    [[nodiscard]] const std::string& ReceiveInterface() const noexcept { return receive_; }

private:
    static bool Run(const std::string& command) {
        // POSIX std::system returns the wait status; a command that exits 0 yields 0.
        return std::system((command + " >/dev/null 2>&1").c_str()) == 0;
    }

#if defined(__APPLE__)
    // Runs `command` and returns its stdout with trailing whitespace trimmed (empty on failure) —
    // used to capture the interface name `ifconfig feth create` prints.
    static std::string RunCapture(const std::string& command) {
        std::string output;
        FILE* pipe = ::popen((command + " 2>/dev/null").c_str(), "r");
        if (pipe == nullptr) {
            return output;
        }
        char chunk[256];
        while (std::fgets(chunk, sizeof(chunk), pipe) != nullptr) {
            output += chunk;
        }
        ::pclose(pipe);
        while (!output.empty() && std::isspace(static_cast<unsigned char>(output.back()))) {
            output.pop_back();
        }
        return output;
    }
#endif

    void Destroy() {
#if defined(__linux__)
        if (created_) {
            Run("ip link del " + inject_);
        }
#elif defined(__APPLE__)
        if (created_inject_) {
            Run("ifconfig " + inject_ + " destroy");
        }
        if (created_receive_) {
            Run("ifconfig " + receive_ + " destroy");
        }
#endif
    }

    // assigned at construction (unique per process / kernel-assigned)
    std::string inject_;
    std::string receive_;
#if defined(__linux__)
    bool created_ = false;
#elif defined(__APPLE__)
    bool created_inject_ = false;
    bool created_receive_ = false;
#endif
    bool valid_ = false;
};

// Polls `receiver` for one UDP datagram and asserts its payload matches `expected`.
void ExpectReceived(reflector::UdpSocket& receiver, std::span<const std::byte> expected) {
    pollfd pfd{.fd = receiver.Fd(), .events = POLLIN, .revents = 0};
    ASSERT_GT(::poll(&pfd, 1, static_cast<int>(WAIT_BUDGET.count())), 0) << "no datagram arrived";
    std::array<std::byte, 2048> buffer{};
    const auto received = ::recv(receiver.Fd(), buffer.data(), buffer.size(), 0);
    ASSERT_GT(received, 0);
    EXPECT_EQ(std::vector<std::byte>(buffer.begin(), buffer.begin() + received),
        std::vector<std::byte>(expected.begin(), expected.end()));
}

} // namespace

namespace reflector {

class RawSocketTest : public ::testing::Test {
protected:
    RawSocket socket{RawSocket::ForTesting("test", -1)};

#if defined(__APPLE__)
    using LinkType = RawSocket::LinkType;
    void SetLinkType(LinkType link_type) noexcept { socket.link_type_ = link_type; }
#endif

    std::optional<Packet> Parse(std::span<const std::byte> frame) noexcept {
        return socket.ParseFrame(frame);
    }

    // Swallows logger output during the parse so failure-path tests stay quiet on stdout.
    std::optional<Packet> ParseQuietly(std::span<const std::byte> frame) {
        std::optional<Packet> result;
        CaptureStdout([&] { result = socket.ParseFrame(frame); });
        return result;
    }

    // Sets the socket's resolved source addresses directly (the fixture is a friend) so CanSend's
    // per-family gating is testable without a real interface that happens to have the right mix.
    void SetSource(std::optional<IpAddress> v4, std::optional<IpAddress> v6) noexcept {
        socket.addresses_.v4 = std::move(v4);
        socket.addresses_.v6 = std::move(v6);
    }
};

TEST_F(RawSocketTest, ParsesEthernetIpv4Udp) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::FromV4Bytes(192, 0, 2, 1);
    const auto dst_ip = IpAddress::FromV4Bytes(192, 0, 2, 255);
    const auto payload = MakeBytes({0xde, 0xad, 0xbe, 0xef});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV4_ETHERTYPE);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()),
        /*flags_fragment=*/0, /*ihl_words=*/5, /*ttl=*/200);
    f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source.addr, src_ip);
    EXPECT_EQ(packet->header.dest.addr, dst_ip);
    EXPECT_EQ(packet->header.source.port, 12345);
    EXPECT_EQ(packet->header.dest.port, 9);
    EXPECT_EQ(packet->header.ttl, 200);
    EXPECT_EQ(packet->header.source_mac, src_mac);
    EXPECT_EQ(packet->header.dest_mac, dst_mac);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), payload);
}

TEST_F(RawSocketTest, ParsesEthernetIpv6Udp) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::LoopbackV6();
    const auto dst_ip = IpAddress::AllNodesLinkLocalV6();
    const auto payload = MakeBytes({0x01, 0x02, 0x03});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV6_ETHERTYPE);
    f.AppendIPv6Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*payload_length=*/static_cast<uint16_t>(8 + payload.size()), /*version=*/6, /*hop_limit=*/100);
    f.AppendUdp(5353, 5353, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source.addr, src_ip);
    EXPECT_EQ(packet->header.dest.addr, dst_ip);
    EXPECT_EQ(packet->header.source.port, 5353);
    EXPECT_EQ(packet->header.dest.port, 5353);
    EXPECT_EQ(packet->header.ttl, 100);
    EXPECT_EQ(packet->header.source_mac, src_mac);
    EXPECT_EQ(packet->header.dest_mac, dst_mac);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), payload);
}

TEST_F(RawSocketTest, TrimsPayloadToUdpLength) {
    const auto src_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const auto dst_mac = *MacAddress::FromString("11:22:33:44:55:66");
    const auto src_ip = IpAddress::FromV4Bytes(10, 0, 0, 1);
    const auto dst_ip = IpAddress::FromV4Bytes(10, 0, 0, 2);
    const auto declared = MakeBytes({0xaa, 0xbb});
    const auto trailer = MakeBytes({0xcc, 0xdd, 0xee});

    FrameBuilder f;
    f.AppendEthernet(dst_mac, src_mac, IPV4_ETHERTYPE);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + declared.size() + trailer.size()));
    f.AppendUdp(1, 2, static_cast<uint16_t>(8 + declared.size()));
    f.AppendPayload(declared);
    f.AppendPayload(trailer);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()), declared);
}

TEST_F(RawSocketTest, RejectsFrameShorterThanEthernetHeader) {
    const auto frame = MakeBytes({0x00, 0x01, 0x02});

    EXPECT_FALSE(ParseQuietly(frame).has_value());
}

TEST_F(RawSocketTest, RejectsUnknownEthertype) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, ARP_ETHERTYPE);
    f.bytes.resize(64, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4FrameTruncatedBeforeHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.bytes.insert(f.bytes.end(), 10, std::byte{0});  // only 10 bytes of IP, need 20

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4WithWrongVersion) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, 8);
    f.bytes[14] = std::byte{(6u << 4) | 5u};  // version=6, IHL=5

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4WithIhlTooSmall) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, 8);
    f.bytes[14] = std::byte{(4u << 4) | 4u};  // IHL=4 → 16-byte header, below minimum

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4FragmentWithMfFlag) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP,
        /*total_length=*/28, /*flags_fragment=*/0x2000);  // MF set
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4FragmentWithNonZeroOffset) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP,
        /*total_length=*/28, /*flags_fragment=*/0x0001);  // offset=1
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4NonUdpProtocol) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), /*protocol=*/6 /*TCP*/, 28);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv6WithWrongVersion) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP,
        /*payload_length=*/8, /*version=*/4);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv6ExtensionHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IPV6_NEXT_HOPOPT,
        /*payload_length=*/16);
    f.bytes.insert(f.bytes.end(), 16, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsFrameTruncatedBeforeUdpHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/24);
    f.bytes.insert(f.bytes.end(), 4, std::byte{0});  // only 4 of the 8 UDP-header bytes

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsUdpLengthBelowHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/4);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsUdpLengthExceedingL4Size) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/64);  // claims much more than actually present

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4TotalLengthBelowHeader) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/10);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv4TotalLengthExceedingCapturedFrame) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/200);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

// total_length=28 declares only the UDP header (20 + 8); udp_length=20 claims 12 bytes
// of data the IP datagram says don't exist. Twelve trailing Ethernet-pad bytes follow.
// Without trimming l4 by total_length the parser would extract those 12 padding bytes
// as the UDP payload.
TEST_F(RawSocketTest, RejectsIpv4UdpLengthExceedingIpDatagram) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::AnyV4(), IpAddress::AnyV4(), IP_PROTO_UDP, /*total_length=*/28);
    f.AppendUdp(1, 2, /*udp_length=*/20);
    f.bytes.resize(f.bytes.size() + 12, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsIpv6PayloadLengthExceedingCapturedFrame) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP, /*payload_length=*/200);
    f.AppendUdp(1, 2, 8);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

// Mirror of RejectsIpv4UdpLengthExceedingIpDatagram for IPv6: payload_length=8 covers
// just the UDP header, udp_length=20 claims 12 bytes that aren't in the IPv6 payload.
TEST_F(RawSocketTest, RejectsIpv6UdpLengthExceedingIpDatagram) {
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV6_ETHERTYPE);
    f.AppendIPv6Header(IpAddress::AnyV6(), IpAddress::AnyV6(), IP_PROTO_UDP, /*payload_length=*/8);
    f.AppendUdp(1, 2, /*udp_length=*/20);
    f.bytes.resize(f.bytes.size() + 12, std::byte{0});

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, Ipv4SourceEnablesIpv4AndRefusesIpv6Send) {
    SetSource(IpAddress::FromV4Bytes(192, 0, 2, 1), std::nullopt);

    EXPECT_TRUE(socket.CanSend(IpAddress::Family::V4));
    EXPECT_FALSE(socket.CanSend(IpAddress::Family::V6));

    // No IPv6 source: the send path's family gate refuses before reaching any syscall. (A
    // successful V4 send needs a real raw socket — see the RequiresRoot inject tests below.)
    const std::array payload{std::byte{0xde}, std::byte{0xad}};
    CaptureStdout([&] {  // swallow the expected "no source" error; the bool is the contract
        EXPECT_FALSE(socket.SendUdpMulticastDatagram(
            {IpAddress::AllNodesLinkLocalV6(), 9}, 9, payload, /*ttl=*/64));
    });
}

TEST_F(RawSocketTest, Ipv6SourceEnablesIpv6AndRefusesIpv4Send) {
    SetSource(std::nullopt, *IpAddress::FromString("fe80::1"));

    EXPECT_FALSE(socket.CanSend(IpAddress::Family::V4));
    EXPECT_TRUE(socket.CanSend(IpAddress::Family::V6));

    const std::array payload{std::byte{0xde}, std::byte{0xad}};
    CaptureStdout([&] {
        EXPECT_FALSE(socket.SendUdpBroadcastDatagram(9, 9, payload, /*ttl=*/64));
    });
}

TEST_F(RawSocketTest, SourceAddressReportsConfiguredSourcePerFamily) {
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V4), std::nullopt);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V6), std::nullopt);

    SetSource(IpAddress::FromV4Bytes(192, 0, 2, 7), *IpAddress::FromString("fe80::1"));
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V4), IpAddress::FromV4Bytes(192, 0, 2, 7));
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V6), *IpAddress::FromString("fe80::1"));

    SetSource(std::nullopt, std::nullopt);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V4), std::nullopt);
    EXPECT_EQ(socket.SourceAddress(IpAddress::Family::V6), std::nullopt);
}

// A non-multicast group is rejected by the kernel (EINVAL on both platforms) and surfaced as
// false — the deterministic, root-free failure case. (A successful join needs a real
// multicast-capable interface; that's the RequiresRoot veth test below. Joining a *valid* group
// on this fd-less test socket isn't deterministic — interface index 0 falls back to the host's
// default interface — so it isn't asserted here.)
TEST_F(RawSocketTest, JoinMulticastGroupRejectsNonMulticastAddress) {
    CaptureStdout([&] {  // swallow the expected error logs; the bool is the contract
        EXPECT_FALSE(socket.JoinMulticastGroup(IpAddress::LoopbackV4()));
        EXPECT_FALSE(socket.JoinMulticastGroup(IpAddress::LoopbackV6()));
    });
}

#if defined(__APPLE__)
// DLT_NULL is macOS-only — on Linux AF_PACKET delivers Ethernet frames for every
// interface, lo included, so the parser never encounters loopback framing there.
TEST_F(RawSocketTest, ParsesLoopbackIpv4UdpWithZeroMacs) {
    SetLinkType(LinkType::Loopback);
    const auto src_ip = IpAddress::LoopbackV4();
    const auto dst_ip = IpAddress::LoopbackV4();
    const auto payload = MakeBytes({0xff});

    FrameBuilder f;
    f.AppendLoopback(AF_INET);
    f.AppendIPv4Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
    f.AppendUdp(40000, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source.addr, src_ip);
    EXPECT_EQ(packet->header.dest.addr, dst_ip);
    EXPECT_EQ(packet->header.source.port, 40000);
    EXPECT_EQ(packet->header.dest.port, 9);
    // DLT_NULL frames carry no L2 — both MACs report as all-zeros.
    EXPECT_EQ(packet->header.source_mac, MacAddress{});
    EXPECT_EQ(packet->header.dest_mac, MacAddress{});
}

TEST_F(RawSocketTest, ParsesLoopbackIpv6Udp) {
    SetLinkType(LinkType::Loopback);
    const auto src_ip = IpAddress::LoopbackV6();
    const auto dst_ip = IpAddress::LoopbackV6();
    const auto payload = MakeBytes({0x10, 0x20});

    FrameBuilder f;
    f.AppendLoopback(AF_INET6);
    f.AppendIPv6Header(src_ip, dst_ip, IP_PROTO_UDP,
        /*payload_length=*/static_cast<uint16_t>(8 + payload.size()));
    f.AppendUdp(1234, 5678, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);

    const auto packet = Parse(f.bytes);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source.addr, src_ip);
    EXPECT_EQ(packet->header.dest.addr, dst_ip);
    EXPECT_EQ(packet->header.source.port, 1234);
    EXPECT_EQ(packet->header.dest.port, 5678);
}

TEST_F(RawSocketTest, RejectsFrameShorterThanLoopbackHeader) {
    SetLinkType(LinkType::Loopback);
    const auto frame = MakeBytes({0x02, 0x00});

    EXPECT_FALSE(ParseQuietly(frame).has_value());
}

TEST_F(RawSocketTest, RejectsLoopbackWithUnsupportedFamily) {
    SetLinkType(LinkType::Loopback);
    FrameBuilder f;
    f.AppendLoopback(/*AF_UNIX-ish*/ 1);

    EXPECT_FALSE(ParseQuietly(f.bytes).has_value());
}

TEST_F(RawSocketTest, RejectsTooLongInterfaceName) {
    const std::string too_long(IFNAMSIZ, 'x');  // IFNAMSIZ chars: one over the usable max
    CaptureStdout([&] {  // swallow the rejection log; IsValid() is the contract
        const RawSocket oversized{too_long};
        EXPECT_FALSE(oversized.IsValid());
    });
}

// Packs N bpf_hdr-prefixed frames into a single batch (one read returns all of them),
// then verifies Receive() walks them one at a time. Mirrors what
// RawSocketRequiresRootTest::DrainsBatchedFramesFromOneRead exercises against
// real BPF + loopback, but without needing capture privileges — the test stages bytes
// directly via TestCaptureSocket::WriteFrameBatch.
TEST(RawSocketBatchTest, ReceiveWalksMultiFrameBpfBatch) {
    TestCaptureSocket capture;
    constexpr int frame_count = 4;
    const auto payload = MakeBytes({0xab, 0xcd});

    std::vector<std::vector<std::byte>> frame_storage;
    std::vector<std::span<const std::byte>> frame_spans;
    frame_storage.reserve(frame_count);
    frame_spans.reserve(frame_count);
    for (int i = 0; i < frame_count; ++i) {
        FrameBuilder f;
        f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
        f.AppendIPv4Header(IpAddress::FromV4Bytes(192, 0, 2, 1), IpAddress::BroadcastV4(),
            IP_PROTO_UDP, /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
        f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
        f.AppendPayload(payload);
        frame_storage.push_back(std::move(f.bytes));
        frame_spans.emplace_back(frame_storage.back());
    }
    ASSERT_TRUE(capture.WriteFrameBatch(frame_spans));

    int received = 0;
    bool observed_buffered = false;
    for (int i = 0; i < frame_count; ++i) {
        const auto packet = capture.socket.Receive();
        ASSERT_TRUE(packet.has_value()) << "missing packet " << (i + 1);
        ++received;
        if (capture.socket.HasBufferedData()) {
            observed_buffered = true;
        }
    }

    EXPECT_EQ(received, frame_count);
    EXPECT_TRUE(observed_buffered)
        << "Expected the buffer walker to leave bytes between frames — got single-frame reads";
    EXPECT_FALSE(capture.socket.Receive().has_value())
        << "Expected no more frames after draining the batch";
}

TEST(RawSocketBatchTest, ReceiveAdvancesPastUnparseableFrameInBatch) {
    TestCaptureSocket capture;
    const auto payload = MakeBytes({0xab, 0xcd});

    auto build_udp = [&](uint16_t source_port) {
        FrameBuilder f;
        f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
        f.AppendIPv4Header(IpAddress::FromV4Bytes(192, 0, 2, 1), IpAddress::BroadcastV4(),
            IP_PROTO_UDP, /*total_length=*/static_cast<uint16_t>(20 + 8 + payload.size()));
        f.AppendUdp(source_port, 9, static_cast<uint16_t>(8 + payload.size()));
        f.AppendPayload(payload);
        return std::move(f.bytes);
    };

    // ARP-ethertype frame: well-framed at the bpf_hdr level so the walker can advance,
    // but ParseFrame rejects it. The walker must still surface the frame that follows.
    FrameBuilder bad;
    bad.AppendEthernet(MacAddress{}, MacAddress{}, ARP_ETHERTYPE);
    bad.bytes.resize(64, std::byte{0});

    std::vector<std::vector<std::byte>> storage;
    storage.push_back(build_udp(11111));
    storage.push_back(std::move(bad.bytes));
    storage.push_back(build_udp(22222));
    std::vector<std::span<const std::byte>> spans{storage[0], storage[1], storage[2]};
    ASSERT_TRUE(capture.WriteFrameBatch(spans));

    const auto first = capture.socket.Receive();
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->header.source.port, 11111);

    CaptureStdout([&] {
        EXPECT_FALSE(capture.socket.Receive().has_value());
    });

    const auto last = capture.socket.Receive();
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(last->header.source.port, 22222);
}

// A frame BPF truncated to fit the buffer (bh_datalen > bh_caplen) is dropped with a warning,
// not parsed from its partial bytes.
TEST(RawSocketBatchTest, ReceiveDropsBpfTruncatedFrame) {
    TestCaptureSocket capture;
    const auto payload = MakeBytes({0xab, 0xcd});
    FrameBuilder f;
    f.AppendEthernet(MacAddress{}, MacAddress{}, IPV4_ETHERTYPE);
    f.AppendIPv4Header(IpAddress::FromV4Bytes(192, 0, 2, 1), IpAddress::BroadcastV4(),
        IP_PROTO_UDP, static_cast<uint16_t>(20 + 8 + payload.size()));
    f.AppendUdp(12345, 9, static_cast<uint16_t>(8 + payload.size()));
    f.AppendPayload(payload);
    // The frame's real length was far larger than what BPF captured.
    ASSERT_TRUE(capture.WriteTruncatedFrame(f.bytes, 70000));

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(capture.socket.Receive().has_value());
    });
    EXPECT_NE(output.find("oversized frame"), std::string::npos) << output;
}
#endif  // defined(__APPLE__)

#if defined(__linux__)
// recv(MSG_TRUNC) reports an oversized frame's real length, so Receive drops it (with a warning)
// instead of parsing the truncated bytes that fit the buffer.
TEST(RawSocketReceiveTest, DropsFrameLargerThanReceiveBuffer) {
    TestCaptureSocket capture;
    const std::vector<std::byte> frame(5000, std::byte{0xff}); // exceeds the 4 KiB receive buffer
    ASSERT_TRUE(capture.WriteFrame(frame));

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(capture.socket.Receive().has_value());
    });
    EXPECT_NE(output.find("oversized frame"), std::string::npos) << output;
}
#endif  // defined(__linux__)

class RawSocketRequiresRootTest : public ::testing::Test {
protected:
    std::optional<RawSocket> socket;
    UdpSocket listener_socket{IpAddress::Family::V4};
    uint16_t listener_port = 0;
    UdpSocket sender_socket{IpAddress::Family::V4};

    void SetUp() override {
        if (!HasPacketCapturePrivileges()) {
            GTEST_SKIP() << "RawSocket on " << LoopbackInterface()
                << " requires CAP_NET_RAW (Linux) or bpf group / root (macOS)";
        }
        socket.emplace(LoopbackInterface());
        ASSERT_TRUE(socket->IsValid());
        listener_port = BindLoopback(listener_socket);
    }

    // The loopback interface carries unrelated UDP traffic too; drain Receive() until we
    // see one matching our test's dest_port or the budget is exhausted. Uses poll() between
    // EAGAIN returns to avoid spinning.
    std::optional<Packet> ReceiveOurDatagram(std::chrono::milliseconds budget = WAIT_BUDGET) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            auto packet = socket->Receive();
            if (packet) {
                if (packet->header.dest.port == listener_port
                        && packet->header.dest.addr == IpAddress::LoopbackV4()) {
                    return packet;
                }
                continue;
            }
            pollfd pfd{.fd = socket->Fd(), .events = POLLIN, .revents = 0};
            ::poll(&pfd, 1, POLL_SLICE_MS);
        }
        return std::nullopt;
    }
};

TEST_F(RawSocketRequiresRootTest, ReceivesLoopbackUdpDatagram) {
    const std::array payload{std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    ASSERT_TRUE(sender_socket.SendTo(payload, {IpAddress::LoopbackV4(), listener_port}));

    const auto packet = ReceiveOurDatagram();
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->header.source.addr, IpAddress::LoopbackV4());
    EXPECT_EQ(packet->header.dest.addr, IpAddress::LoopbackV4());
    EXPECT_EQ(packet->header.dest.port, listener_port);
    EXPECT_NE(packet->header.source.port, 0);
    EXPECT_EQ(std::vector<std::byte>(packet->payload.begin(), packet->payload.end()),
        std::vector<std::byte>(payload.begin(), payload.end()));
}

// Sends a burst of datagrams faster than we drain so the kernel batches multiple
// bpf_hdr-prefixed frames into one read(). On macOS, asserts that at least one Receive()
// left userland-buffered data behind — that's the only direct coverage of the multi-frame
// walk in Receive(). On Linux this just verifies the burst is delivered (AF_PACKET has no
// userland buffering, so the walk doesn't apply).
TEST_F(RawSocketRequiresRootTest, DrainsBatchedFramesFromOneRead) {
    constexpr int packet_count = 8;
    const std::array payload{std::byte{0xab}, std::byte{0xcd}};
    for (int i = 0; i < packet_count; ++i) {
        ASSERT_TRUE(sender_socket.SendTo(payload, {IpAddress::LoopbackV4(), listener_port}));
    }

#if defined(__APPLE__)
    bool observed_buffered_read = false;
#endif
    for (int i = 0; i < packet_count; ++i) {
        const auto packet = ReceiveOurDatagram();
        ASSERT_TRUE(packet.has_value()) << "missing packet " << (i + 1);
#if defined(__APPLE__)
        if (socket->HasBufferedData()) {
            observed_buffered_read = true;
        }
#endif
    }

#if defined(__APPLE__)
    EXPECT_TRUE(observed_buffered_read)
        << "Expected at least one Receive() to leave userland-buffered data behind — "
           "the macOS multi-frame BPF batch walk was not exercised";
#endif
}

TEST_F(RawSocketRequiresRootTest, ResolvesInterfaceIndexAndAddresses) {
    EXPECT_NE(socket->InterfaceIndex(), 0u);
    // Loopback always has 127.0.0.1, so the v4 source resolves and survives a refresh.
    EXPECT_TRUE(socket->CanSend(IpAddress::Family::V4));
    socket->RefreshAddresses();
    EXPECT_TRUE(socket->CanSend(IpAddress::Family::V4));
}

// Injects on the real loopback socket and asserts the kernel accepted the frame for transmission:
// the source address resolves, BuildUdpFrame/BuildLoopbackUdpFrame produce a frame, and the
// sendto/write syscall takes it. This is the only direct test of the actual macOS BPF write path
// — macOS won't loop the frame back for a reception check (see below) — so it runs on both
// platforms. Frame-byte correctness is covered by the frame-builder tests.
TEST_F(RawSocketRequiresRootTest, InjectsUdpDatagram) {
    const std::array payload{std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}};

    EXPECT_TRUE(socket->SendUdpBroadcastDatagram(INJECT_DST_PORT, INJECT_SRC_PORT,
        payload, /*ttl=*/64));
}

// Round-trips the injected datagram: the broadcast frame loops back on lo and the same socket
// captures it (the BPF filter drops only the outgoing copy, so the looped-back broadcast
// survives), verifying the on-the-wire frame's source/destination and payload.
//
// Linux only — compiled out of the macOS build rather than skipped at runtime: macOS never loops
// BPF-injected frames on lo0 back to the input path (the same reason pcap_inject on lo0 is a no-op
// there; confirmed that neither a UDP socket nor the injecting BPF device itself observes them), so
// this can never run there. The macOS inject path is asserted by InjectsUdpDatagram above and its
// framing by the frame-builder tests.
#if defined(__linux__)
TEST_F(RawSocketRequiresRootTest, CapturesInjectedDatagramOnLoopback) {
    const std::array payload{std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}};

    ASSERT_TRUE(socket->SendUdpBroadcastDatagram(INJECT_DST_PORT, INJECT_SRC_PORT,
        payload, /*ttl=*/64));

    // lo carries unrelated traffic too; drain until we see the frame we just injected.
    const auto deadline = std::chrono::steady_clock::now() + WAIT_BUDGET;
    std::optional<Packet> captured;
    while (!captured && std::chrono::steady_clock::now() < deadline) {
        auto packet = socket->Receive();
        if (packet && packet->header.source.port == INJECT_SRC_PORT
                && packet->header.dest.addr == IpAddress::BroadcastV4()) {
            captured = std::move(packet);
            break;
        }
        if (!packet) {
            pollfd pfd{.fd = socket->Fd(), .events = POLLIN, .revents = 0};
            ::poll(&pfd, 1, POLL_SLICE_MS);
        }
    }

    ASSERT_TRUE(captured.has_value()) << "did not capture the injected frame";
    EXPECT_EQ(captured->header.source.addr, IpAddress::LoopbackV4());  // lo's cached v4 source
    EXPECT_EQ(captured->header.dest.addr, IpAddress::BroadcastV4());
    EXPECT_EQ(captured->header.dest.port, INJECT_DST_PORT);
    EXPECT_EQ(std::vector<std::byte>(captured->payload.begin(), captured->payload.end()),
        std::vector<std::byte>(payload.begin(), payload.end()));
}
#endif

// Injects on one interface of a virtual pair and confirms the datagram arrives on the other,
// validating SendUdpDatagram's framing and source selection on a real (non-loopback) interface.
// Cross-platform: veth on Linux, feth on macOS. Needs root for interface creation, so it carries
// the "root" label and skips otherwise; run with `sudo ctest -L root` (or a privileged container
// with NET_ADMIN).
//
// IPv4 is received with a RawSocket capture on the peer; the kernel drops an IPv4 datagram whose
// source is one of our own addresses arriving over the wire (a local "martian"), so a UDP socket
// can't see it without privileged sysctl overrides, but a capture taps below IP. IPv6 multicast
// isn't subject to that check, so it uses a real UDP socket — which additionally validates the
// checksum, since the kernel drops bad-checksum UDP.
class RawSocketInterfacePairRequiresRootTest : public ::testing::Test {
protected:
    InterfacePair pair;

    void SetUp() override {
        if (!pair.IsValid()) {
            GTEST_SKIP() << "creating a veth/feth pair requires root (CAP_NET_ADMIN)";
        }
    }

    // Re-resolves the injector's addresses until the requested family has a usable source,
    // waiting out IPv6 DAD (the freshly-assigned address is briefly tentative).
    static void WaitForSource(RawSocket& injector, IpAddress::Family family) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (!injector.CanSend(family) && std::chrono::steady_clock::now() < deadline) {
            ::poll(nullptr, 0, POLL_SLICE_MS);  // brief wait for the address to leave DAD
            injector.RefreshAddresses();
        }
    }

    // Drains `peer` until it captures the datagram we injected (matched by source port and
    // destination), or the budget runs out. lo and real interfaces carry unrelated traffic too.
    static std::optional<Packet> CaptureInjected(RawSocket& peer, const IpAddress& dest_ip) {
        const auto deadline = std::chrono::steady_clock::now() + WAIT_BUDGET;
        while (std::chrono::steady_clock::now() < deadline) {
            auto frame = peer.Receive();
            if (frame && frame->header.source.port == INJECT_SRC_PORT
                    && frame->header.dest.addr == dest_ip) {
                return frame;
            }
            if (!frame) {
                pollfd pfd{.fd = peer.Fd(), .events = POLLIN, .revents = 0};
                ::poll(&pfd, 1, POLL_SLICE_MS);
            }
        }
        return std::nullopt;
    }

    // Waits for the receive interface to have a DAD-complete IPv6 link-local address (a
    // freshly-created feth/veth needs one before a link-local-scoped multicast join succeeds on
    // it). Returns false if none appears within the budget.
    [[nodiscard]] bool WaitForReceiverLinkLocal() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (std::chrono::steady_clock::now() < deadline) {
#if defined(__linux__)
            const auto addresses =
                ResolveInterfaceAddresses(if_nametoindex(pair.ReceiveInterface().c_str()));
#elif defined(__APPLE__)
            const auto addresses = ResolveInterfaceAddresses(pair.ReceiveInterface());
#endif
            if (addresses.v6 && addresses.v6->IsLinkLocal()) {
                return true;
            }
            ::poll(nullptr, 0, POLL_SLICE_MS);
        }
        return false;
    }
};

TEST_F(RawSocketInterfacePairRequiresRootTest, InjectsIpv4BroadcastCapturedOnPeer) {
    RawSocket injector{pair.InjectInterface()};
    ASSERT_TRUE(injector.IsValid());
    ASSERT_TRUE(injector.CanSend(IpAddress::Family::V4));
    RawSocket peer{pair.ReceiveInterface()};
    ASSERT_TRUE(peer.IsValid());

    const std::array payload{std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}};
    ASSERT_TRUE(injector.SendUdpBroadcastDatagram(INJECT_DST_PORT, INJECT_SRC_PORT,
        payload, /*ttl=*/64));

    const auto captured = CaptureInjected(peer, IpAddress::BroadcastV4());
    ASSERT_TRUE(captured.has_value()) << "peer did not capture the injected broadcast";
    EXPECT_EQ(captured->header.dest.port, INJECT_DST_PORT);
    EXPECT_EQ(std::vector<std::byte>(captured->payload.begin(), captured->payload.end()),
        std::vector<std::byte>(payload.begin(), payload.end()));
}

TEST_F(RawSocketInterfacePairRequiresRootTest, InjectsIpv6MulticastReceivedByUdpSocket) {
    RawSocket injector{pair.InjectInterface()};
    ASSERT_TRUE(injector.IsValid());
    WaitForSource(injector, IpAddress::Family::V6);
    ASSERT_TRUE(injector.CanSend(IpAddress::Family::V6)) << "no usable IPv6 source after DAD";

    // The join needs the peer's link-local to be DAD-complete.
    ASSERT_TRUE(WaitForReceiverLinkLocal()) << "receive interface never got an IPv6 link-local";

    UdpSocket receiver{IpAddress::Family::V6};
    ASSERT_TRUE(receiver.SetReuseAddr(true));
    ASSERT_TRUE(receiver.Bind(0));
    ASSERT_TRUE(receiver.JoinMulticastGroup(IpAddress::AllNodesLinkLocalV6(),
        pair.ReceiveInterface()));

    const std::array payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    ASSERT_TRUE(injector.SendUdpMulticastDatagram({IpAddress::AllNodesLinkLocalV6(), BoundPort(receiver)},
        INJECT_SRC_PORT, payload, /*ttl=*/64));

    ExpectReceived(receiver, payload);
}

// Joins the mDNS groups on a real multicast-capable interface: both families succeed, and a
// repeat join of the same group is idempotent (the kernel's EADDRINUSE is swallowed). The inject
// interface carries both an IPv4 and an IPv6 link-local address, so it can join either family.
// (On a veth pair multicast is delivered regardless of membership, so this asserts the join
// *succeeds*, not that it gates reception — the latter only matters on real NICs.)
TEST_F(RawSocketInterfacePairRequiresRootTest, JoinsMulticastGroupsIdempotently) {
    RawSocket socket{pair.InjectInterface()};
    ASSERT_TRUE(socket.IsValid());
    WaitForSource(socket, IpAddress::Family::V6);  // wait out DAD on the link-local

    EXPECT_TRUE(socket.JoinMulticastGroup(IpAddress::MdnsGroupV4()));
    EXPECT_TRUE(socket.JoinMulticastGroup(IpAddress::MdnsGroupV6()));
    EXPECT_TRUE(socket.JoinMulticastGroup(IpAddress::MdnsGroupV4()));
    EXPECT_TRUE(socket.JoinMulticastGroup(IpAddress::MdnsGroupV6()));
}

} // namespace reflector
