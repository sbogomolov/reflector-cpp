#include "raw_socket.h"

#include "error.h"
#include "frame_builder.h"
#include "ip_address.h"
#include "mac_address.h"
#include "util/byte_order.h"

#include <array>
#include <arpa/inet.h>
#include <bit>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <tuple>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

#if !defined(__APPLE__) && !defined(__linux__)
#error "RawSocket only supports macOS and Linux"
#endif

#if defined(__linux__)
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
// Added to the UAPI in Linux 4.20; define it if the build's kernel headers predate that.
// The setsockopt still fails at runtime on a pre-4.20 kernel, which RawSocket treats as fatal.
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif
#elif defined(__APPLE__)
#include <net/bpf.h>
#include <net/ethernet.h>
#include <sys/uio.h>
#endif

namespace reflector {

namespace {

// Classic BPF programs that accept IPv4 UDP or IPv6 UDP only (no VLAN tag, no IPv6
// extension headers). Direction filtering is handled at the socket level rather than in
// the program: Linux sets PACKET_IGNORE_OUTGOING and macOS clears BIOCSSEESENT (on
// Ethernet), so the kernel never feeds us our own injected frames. Both prevent two
// reflector entries with mirrored interface pairs (entry A: eth0 → eth1, entry B: eth1 →
// eth0) from ping-ponging the same frame: without this, B's capture on eth1 would pick up
// A's egress and re-reflect it back to eth0, where A would in turn pick up B's egress, ad
// infinitum.
struct BpfInsn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

// Non-const so the kernel APIs (sock_filter* / bpf_insn*) accept .data() without
// const_cast. The surrounding anonymous namespace gives internal linkage; no caller
// mutates them and the kernel only reads.
// Ethernet UDP filter: accept IPv4/IPv6 UDP only. Direction filtering is done at the
// socket level (see above), not here, so this is a plain protocol classifier shared by
// both platforms.
//
//   0: ldh  [12]                load ethertype
//   1: jeq  0x0800, jt=3, jf=0  if IPv4, jump to 5 (IPv4 path); else fall through
//   2: jeq  0x86dd, jt=0, jf=5  if IPv6, fall through; else jump to 8 (drop)
//   3: ldb  [20]                load IPv6 next-header
//   4: jeq  17, jt=2, jf=3      if UDP, jump to 7 (accept); else jump to 8 (drop)
//   5: ldb  [23]                load IPv4 protocol
//   6: jeq  17, jt=0, jf=1      if UDP, fall through to 7 (accept); else jump to 8 (drop)
//   7: ret  0xffffffff          accept
//   8: ret  0                   drop
std::array<BpfInsn, 9> ETHERNET_UDP_FILTER{{
    {0x0028,  0,  0, 0x0000000c}, // BPF_LD|BPF_H|BPF_ABS, offset 12 (ethertype)
    {0x0015,  3,  0, 0x00000800}, // BPF_JMP|BPF_JEQ|BPF_K, k=0x0800 (IPv4)
    {0x0015,  0,  5, 0x000086dd}, // BPF_JMP|BPF_JEQ|BPF_K, k=0x86dd (IPv6)
    {0x0030,  0,  0, 0x00000014}, // BPF_LD|BPF_B|BPF_ABS, offset 20 (IPv6 next-header)
    {0x0015,  2,  3, 0x00000011}, // BPF_JMP|BPF_JEQ|BPF_K, k=17 (UDP)
    {0x0030,  0,  0, 0x00000017}, // BPF_LD|BPF_B|BPF_ABS, offset 23 (IPv4 protocol)
    {0x0015,  0,  1, 0x00000011}, // BPF_JMP|BPF_JEQ|BPF_K, k=17 (UDP)
    {0x0006,  0,  0, 0xffffffff}, // BPF_RET|BPF_K, accept
    {0x0006,  0,  0, 0x00000000}, // BPF_RET|BPF_K, drop
}};

#if defined(__APPLE__)
// DLT_NULL framing: 4-byte address family in host byte order (BSD loopback driver
// convention), then the IP packet. The data layout is host-endian, but the classic
// BPF VM's BPF_LD|BPF_W|BPF_ABS always interprets the loaded 4 bytes as big-endian
// regardless of host: on a little-endian host, AF_INET written to memory as
// 02 00 00 00 is loaded by the VM as 0x02000000, so the jeq constant must be
// byteswapped to match. HostAfToBpfBe does that at compile time; on the
// hypothetical big-endian build it's a no-op (data and load agree).
//
//   0: ldw  [0]                   load family word
//   1: jeq  AF_INET,  jt=3, jf=0  if IPv4, jump to 5; else fall through
//   2: jeq  AF_INET6, jt=0, jf=5  if IPv6, fall through; else jump to 8 (drop)
//   3: ldb  [10]                  load IPv6 next-header (4-byte family + 6 into header)
//   4: jeq  17, jt=2, jf=3        if UDP, jump to 7 (accept); else jump to 8 (drop)
//   5: ldb  [13]                  load IPv4 protocol (4-byte family + 9 into header)
//   6: jeq  17, jt=0, jf=1        if UDP, fall through to 7 (accept); else jump to 8 (drop)
//   7: ret  0xffffffff            accept
//   8: ret  0                     drop
constexpr uint32_t HostAfToBpfBe(uint32_t af) noexcept {
    return std::endian::native == std::endian::little ? std::byteswap(af) : af;
}
constexpr uint32_t DLT_NULL_AF_INET_BE = HostAfToBpfBe(AF_INET);
constexpr uint32_t DLT_NULL_AF_INET6_BE = HostAfToBpfBe(AF_INET6);
std::array<BpfInsn, 9> LOOPBACK_UDP_FILTER{{
    {0x0020,  0,  0, 0x00000000},          // BPF_LD|BPF_W|BPF_ABS, offset 0 (family)
    {0x0015,  3,  0, DLT_NULL_AF_INET_BE}, // BPF_JMP|BPF_JEQ|BPF_K, AF_INET
    {0x0015,  0,  5, DLT_NULL_AF_INET6_BE},// BPF_JMP|BPF_JEQ|BPF_K, AF_INET6
    {0x0030,  0,  0, 0x0000000a},          // BPF_LD|BPF_B|BPF_ABS, offset 10 (IPv6 next-header)
    {0x0015,  2,  3, 0x00000011},          // BPF_JMP|BPF_JEQ|BPF_K, k=17 (UDP)
    {0x0030,  0,  0, 0x0000000d},          // BPF_LD|BPF_B|BPF_ABS, offset 13 (IPv4 protocol)
    {0x0015,  0,  1, 0x00000011},          // BPF_JMP|BPF_JEQ|BPF_K, k=17 (UDP)
    {0x0006,  0,  0, 0xffffffff},          // BPF_RET|BPF_K, accept
    {0x0006,  0,  0, 0x00000000},          // BPF_RET|BPF_K, drop
}};
#endif

// Sized for one frame at a typical Ethernet MTU plus headers. The reflected traffic
// classes (WoL, mDNS, SSDP) all fit comfortably below this; oversized datagrams would
// be IP-fragmented and our parser drops fragments anyway. Used by the Linux production
// constructor and by the test-only ForTesting constructor on both platforms; macOS
// production instead sizes the buffer from BPF's own preferred size via BIOCGBLEN.
constexpr size_t DEFAULT_RECEIVE_BUFFER_SIZE = 4 * 1024;

// The frame to send is assembled into a stack buffer this size. Same rationale as the receive
// buffer: one datagram at a typical MTU plus headers, with headroom; the traffic we emit (WoL,
// later mDNS/SSDP) stays well under it and we don't fragment. BuildUdpFrame fails cleanly if a
// caller ever exceeds it.
constexpr size_t SEND_BUFFER_SIZE = 4 * 1024;

#if defined(__APPLE__)
// DLT_NULL framing: 4 bytes of address family in host byte order, then the IP packet.
constexpr size_t LOOPBACK_FAMILY_SIZE = 4;
#endif

constexpr size_t ETHERNET_HEADER_SIZE = 14;
constexpr size_t ETHERTYPE_OFFSET = 12;
// Use *_ETHERTYPE names (not ETHERTYPE_IPV*) because macOS <net/ethernet.h> defines
// ETHERTYPE_IPV6 as a macro, which would macro-expand our identifier here into garbage.
constexpr uint16_t IPV4_ETHERTYPE = 0x0800;
constexpr uint16_t IPV6_ETHERTYPE = 0x86dd;
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr size_t IPV4_MIN_HEADER_SIZE = 20;
constexpr size_t IPV6_HEADER_SIZE = 40;
constexpr size_t UDP_HEADER_SIZE = 8;

} // namespace

RawSocket::RawSocket(std::string_view interface)
        : logger_{std::format("RawSocket:{}", interface)}
        , interface_{interface} {
    // Guard before any name lookup: if_nametoindex (and BPF's BIOCSETIF) copy into a fixed
    // IFNAMSIZ buffer, so an over-long name would be silently truncated and could match the
    // wrong interface.
    if (interface_.size() >= IFNAMSIZ) {
        logger_.Error("Interface name \"{}\" is too long (max {} characters)", interface_, IFNAMSIZ - 1);
        return;
    }

    interface_index_ = if_nametoindex(interface_.c_str());
    if (interface_index_ == 0) {
        logger_.Error("Cannot resolve interface index: {}", Error::FromErrno());
        return;
    }

#if defined(__linux__)
    fd_ = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (fd_ < 0) {
        logger_.Error("Cannot open AF_PACKET socket: {}", Error::FromErrno());
        return;
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(interface_index_);
    if (bind(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        logger_.Error("Cannot bind AF_PACKET socket to interface: {}", Error::FromErrno());
        Close();
        return;
    }

    sock_fprog program{
        .len = ETHERNET_UDP_FILTER.size(),
        .filter = reinterpret_cast<sock_filter*>(ETHERNET_UDP_FILTER.data()),
    };
    if (setsockopt(fd_, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) != 0) {
        logger_.Error("Cannot attach BPF UDP filter: {}", Error::FromErrno());
        Close();
        return;
    }

    // Stop the kernel from handing this capture socket our own injected frames — the
    // loop-prevention counterpart to macOS's BIOCSSEESENT=0 (see the filter note above).
    // Fatal if unsupported (kernel < 4.20): a capture socket that re-receives its own
    // injections would let mirrored reflector entries ping-pong a frame forever.
    const int ignore_outgoing = 1;
    if (setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing,
            sizeof(ignore_outgoing)) != 0) {
        logger_.Error("Cannot set PACKET_IGNORE_OUTGOING: {}", Error::FromErrno());
        Close();
        return;
    }

    receive_buffer_.resize(DEFAULT_RECEIVE_BUFFER_SIZE);

    logger_.Debug("Opened AF_PACKET socket fd {} on interface", fd_);

#elif defined(__APPLE__)
    for (int n = 0; n < 256 && fd_ < 0; ++n) {
        const auto path = std::format("/dev/bpf{}", n);
        fd_ = open(path.c_str(), O_RDWR);
        if (fd_ < 0 && errno != EBUSY) {
            logger_.Error("Cannot open {}: {}", path, Error::FromErrno());
            return;
        }
    }
    if (fd_ < 0) {
        logger_.Error("Cannot open any /dev/bpfN device");
        return;
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, interface_.c_str(), sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd_, BIOCSETIF, &ifr) != 0) {
        logger_.Error("Cannot bind BPF to interface: {}", Error::FromErrno());
        Close();
        return;
    }

    u_int dlt = 0;
    if (ioctl(fd_, BIOCGDLT, &dlt) != 0) {
        logger_.Error("Cannot query BPF link type: {}", Error::FromErrno());
        Close();
        return;
    }
    if (dlt == DLT_EN10MB) {
        link_type_ = LinkType::Ethernet;
    } else if (dlt == DLT_NULL) {
        link_type_ = LinkType::Loopback;
    } else {
        logger_.Error("BPF link type {} is not supported (need DLT_EN10MB or DLT_NULL)", dlt);
        Close();
        return;
    }

    u_int immediate = 1;
    if (ioctl(fd_, BIOCIMMEDIATE, &immediate) != 0) {
        logger_.Error("Cannot set BIOCIMMEDIATE: {}", Error::FromErrno());
        Close();
        return;
    }

    // Suppress locally-generated frames on Ethernet links: stops two mirrored reflector
    // entries (A: eth0 → eth1, B: eth1 → eth0) from ping-ponging each other's egress. The
    // same-interface case (source_if == target_if) is already rejected by WolConfig::Verify.
    //
    // Skip on DLT_NULL. The BSD loopback driver only taps once per frame, on the
    // input path inside dlil_input_packet_list — lo_output has no output-side tap.
    // That single delivery is always tagged outbound (the local stack generated it),
    // so default BPF (BPF_D_INOUT) accepts it; setting SEESENT=0 (= BPF_D_IN) would
    // drop every frame the driver gives us and silence lo0 entirely. BIOCSDIRECTION
    // isn't an escape hatch — same ioctl, same kernel handler, just a wider value
    // set. Linux doesn't need this gate: PACKET_IGNORE_OUTGOING on its AF_PACKET socket
    // drops the egress copy, collapsing lo's egress+ingress duplication to the ingress
    // copy.
    if (link_type_ == LinkType::Ethernet) {
        u_int see_sent = 0;
        if (ioctl(fd_, BIOCSSEESENT, &see_sent) != 0) {
            logger_.Error("Cannot clear BIOCSSEESENT: {}", Error::FromErrno());
            Close();
            return;
        }
    }

    // Different link types need different filter programs because the byte offsets to the
    // ethertype / IP protocol fields differ. Both programs accept IPv4 UDP and IPv6 UDP
    // only; everything else is dropped in-kernel before reaching userland.
    auto& filter = link_type_ == LinkType::Ethernet ? ETHERNET_UDP_FILTER : LOOPBACK_UDP_FILTER;
    bpf_program program{
        .bf_len = static_cast<u_int>(filter.size()),
        .bf_insns = reinterpret_cast<bpf_insn*>(filter.data()),
    };
    if (ioctl(fd_, BIOCSETF, &program) != 0) {
        logger_.Error("Cannot attach BPF UDP filter: {}", Error::FromErrno());
        Close();
        return;
    }

    u_int blen = 0;
    if (ioctl(fd_, BIOCGBLEN, &blen) != 0) {
        logger_.Error("Cannot query BPF buffer length: {}", Error::FromErrno());
        Close();
        return;
    }
    receive_buffer_.resize(blen);

    if (fcntl(fd_, F_SETFL, O_NONBLOCK) != 0) {
        logger_.Error("Cannot set BPF socket non-blocking: {}", Error::FromErrno());
        Close();
        return;
    }

    logger_.Debug("Opened BPF fd {} on interface (buffer {} bytes)", fd_, blen);
#endif

    RefreshAddresses();
}

RawSocket::RawSocket(TestingTag, std::string_view interface, int owned_fd) noexcept
        : logger_{std::format("RawSocket:{}", interface)}
        , interface_{interface}
        , fd_{owned_fd} {
    // Production sizes receive_buffer_ during setup (constant on Linux, BIOCGBLEN on macOS);
    // tests skip that path, so use the same default the Linux production uses — enough for
    // one full-MTU frame plus headers.
    receive_buffer_.resize(DEFAULT_RECEIVE_BUFFER_SIZE);
}

RawSocket RawSocket::ForTesting(std::string_view interface, int owned_fd) {
    return RawSocket{TestingTag{}, interface, owned_fd};
}

std::unique_ptr<RawSocket> RawSocket::ForTestingPtr(std::string_view interface, int owned_fd) {
    return std::unique_ptr<RawSocket>(new RawSocket{TestingTag{}, interface, owned_fd});
}

RawSocket::~RawSocket() noexcept {
    Close();
}

bool RawSocket::CanSend(IpAddress::Family family) const noexcept {
    return (family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6).has_value();
}

void RawSocket::RefreshAddresses() noexcept {
#if defined(__linux__)
    addresses_ = ResolveInterfaceAddresses(interface_index_);
#elif defined(__APPLE__)
    addresses_ = ResolveInterfaceAddresses(interface_);
#endif
    // logger_ is prefixed with the interface name, so this ties name (prefix) and index together.
    logger_.Debug("Resolved addresses (index {}): MAC {}, IPv4 {}, IPv6 {}", interface_index_,
        addresses_.mac, addresses_.v4 ? addresses_.v4->ToString() : "none",
        addresses_.v6 ? addresses_.v6->ToString() : "none");
}

bool RawSocket::SendUdpDatagram(IpAddress dst_ip, uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept {
    const auto family = dst_ip.AddressFamily();
    const auto& source = family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6;
    if (!source.has_value()) {
        logger_.Error("Cannot send to {}: interface has no source address for that family",
            dst_ip.ToString());
        return false;
    }

    std::array<std::byte, SEND_BUFFER_SIZE> frame{};
#if defined(__linux__)
    const size_t length = BuildUdpFrame(MulticastMacFor(dst_ip), addresses_.mac, *source, dst_ip,
        src_port, dst_port, payload, ttl, frame);
#elif defined(__APPLE__)
    const size_t length = link_type_ == LinkType::Loopback
        ? BuildLoopbackUdpFrame(*source, dst_ip, src_port, dst_port, payload, ttl, frame)
        : BuildUdpFrame(MulticastMacFor(dst_ip), addresses_.mac, *source, dst_ip, src_port,
              dst_port, payload, ttl, frame);
#endif
    if (length == 0) {
        logger_.Error("Cannot build egress frame for {} ({}-byte payload)", dst_ip.ToString(),
            payload.size());
        return false;
    }

#if defined(__linux__)
    // SOCK_RAW carries the full L2 frame, so the kernel only needs the egress interface; the
    // destination MAC already lives in the frame, so sll_addr/sll_halen stay zero.
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = static_cast<int>(interface_index_);
    const auto sent = sendto(fd_, frame.data(), length, 0,
        reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
#elif defined(__APPLE__)
    const auto sent = write(fd_, frame.data(), length);
#endif
    if (sent < 0 || static_cast<size_t>(sent) != length) {
        logger_.Error("Cannot inject datagram to {}: {}", dst_ip.ToString(), Error::FromErrno());
        return false;
    }
    return true;
}

#if defined(__APPLE__)
bool RawSocket::HasBufferedData() const noexcept {
    return receive_buffer_offset_ < receive_buffer_filled_;
}

void RawSocket::ClearBuffer() noexcept {
    receive_buffer_filled_ = 0;
    receive_buffer_offset_ = 0;
}
#endif

void RawSocket::Close() noexcept {
    if (fd_ >= 0) {
        logger_.Debug("Closing capture socket fd {}", fd_);
        close(fd_);
        fd_ = -1;
    }
#if defined(__APPLE__)
    ClearBuffer();
#endif
}

std::optional<Packet> RawSocket::Receive() noexcept {
    if (fd_ < 0) {
        return std::nullopt;
    }

#if defined(__linux__)
    ssize_t bytes;
    do {
        bytes = recv(fd_, receive_buffer_.data(), receive_buffer_.size(), 0);
    } while (bytes < 0 && errno == EINTR);
    if (bytes < 0) {
        if (IsWouldBlockErrno(errno)) {
            return std::nullopt;
        }
        logger_.Error("Cannot receive frame: {}", Error::FromErrno());
        return std::nullopt;
    }
    return ParseFrame({receive_buffer_.data(), static_cast<size_t>(bytes)});

#elif defined(__APPLE__)
    if (receive_buffer_offset_ >= receive_buffer_filled_) {
        ssize_t bytes;
        do {
            bytes = read(fd_, receive_buffer_.data(), receive_buffer_.size());
        } while (bytes < 0 && errno == EINTR);
        if (bytes < 0) {
            if (IsWouldBlockErrno(errno)) {
                return std::nullopt;
            }
            logger_.Error("Cannot receive frame: {}", Error::FromErrno());
            return std::nullopt;
        }
        if (bytes == 0) {
            return std::nullopt;
        }
        receive_buffer_filled_ = static_cast<size_t>(bytes);
        receive_buffer_offset_ = 0;
    }

    if (receive_buffer_offset_ + sizeof(bpf_hdr) > receive_buffer_filled_) {
        logger_.Error("BPF batch truncated: {} bytes remaining, need at least {} for header",
            receive_buffer_filled_ - receive_buffer_offset_, sizeof(bpf_hdr));
        receive_buffer_offset_ = receive_buffer_filled_;
        return std::nullopt;
    }
    bpf_hdr header{};
    std::memcpy(&header, receive_buffer_.data() + receive_buffer_offset_, sizeof(header));

    const auto frame_offset = receive_buffer_offset_ + header.bh_hdrlen;
    const auto frame_end = frame_offset + header.bh_caplen;
    if (frame_end > receive_buffer_filled_) {
        logger_.Error("BPF frame extends past batch end (frame_end {} > filled {})",
            frame_end, receive_buffer_filled_);
        receive_buffer_offset_ = receive_buffer_filled_;
        return std::nullopt;
    }
    receive_buffer_offset_ = BPF_WORDALIGN(frame_offset + header.bh_caplen);

    return ParseFrame({receive_buffer_.data() + frame_offset, header.bh_caplen});
#endif
}

std::optional<Packet> RawSocket::ParseFrame(std::span<const std::byte> frame) noexcept {
    uint16_t ethertype = 0;
    MacAddress source_mac{};
    MacAddress dest_mac{};
    std::span<const std::byte> l3;

#if defined(__APPLE__)
    if (link_type_ == LinkType::Loopback) {
        // DLT_NULL: 4-byte address family in host byte order, then the IP packet. No L2,
        // so MACs stay default-constructed (all zeros) — same shape we see on Linux's lo.
        if (frame.size() < LOOPBACK_FAMILY_SIZE) {
            logger_.Error("Frame too short for DLT_NULL header: {} bytes", frame.size());
            return std::nullopt;
        }
        uint32_t family = 0;
        std::memcpy(&family, frame.data(), sizeof(family));
        if (family == AF_INET) {
            ethertype = IPV4_ETHERTYPE;
        } else if (family == AF_INET6) {
            ethertype = IPV6_ETHERTYPE;
        } else {
            logger_.Error("DLT_NULL frame with unsupported address family {}", family);
            return std::nullopt;
        }
        l3 = frame.subspan(LOOPBACK_FAMILY_SIZE);
    } else
#endif
    {
        if (frame.size() < ETHERNET_HEADER_SIZE) {
            logger_.Error("Frame too short for Ethernet header: {} bytes", frame.size());
            return std::nullopt;
        }
        ethertype = ReadU16Be(frame.subspan<ETHERTYPE_OFFSET, 2>());
        dest_mac = MacAddress::FromBytes(frame.subspan<0, 6>());
        source_mac = MacAddress::FromBytes(frame.subspan<6, 6>());
        l3 = frame.subspan(ETHERNET_HEADER_SIZE);
    }

    auto parse_l3 = [&]() -> std::optional<std::tuple<IpAddress, IpAddress, uint8_t, std::span<const std::byte>>> {
        if (ethertype == IPV4_ETHERTYPE) {
            if (l3.size() < IPV4_MIN_HEADER_SIZE) {
                logger_.Error("IPv4 payload too short for header: {} bytes", l3.size());
                return std::nullopt;
            }
            const auto version_ihl = std::to_integer<uint8_t>(l3[0]);
            if ((version_ihl >> 4) != 4) {
                logger_.Error("IPv4 ethertype with version field {}", version_ihl >> 4);
                return std::nullopt;
            }
            const auto ihl_words = version_ihl & 0x0f;
            const auto header_size = static_cast<size_t>(ihl_words) * 4;
            if (header_size < IPV4_MIN_HEADER_SIZE || l3.size() < header_size) {
                logger_.Error("IPv4 IHL {} words yields header size {} (l3 size {})",
                    ihl_words, header_size, l3.size());
                return std::nullopt;
            }
            const auto flags_fragment = ReadU16Be(l3.subspan<6, 2>());
            // MF set or fragment offset non-zero indicates a fragment; reassembly is out of scope.
            if ((flags_fragment & 0x3fff) != 0) {
                logger_.Debug("Dropping IPv4 fragment (flags/offset {:#x})", flags_fragment);
                return std::nullopt;
            }
            if (std::to_integer<uint8_t>(l3[9]) != IP_PROTO_UDP) {
                logger_.Error("IPv4 protocol {} reached parser; BPF filter should have dropped it",
                    std::to_integer<uint8_t>(l3[9]));
                return std::nullopt;
            }
            // Trim by IPv4 total_length so trailing bytes (Ethernet pad, BPF capture
            // slack) don't get fed to UDP — otherwise a frame with a lying udp_length
            // could pull padding into the payload.
            const auto total_length = ReadU16Be(l3.subspan<2, 2>());
            if (total_length < header_size || total_length > l3.size()) {
                logger_.Error("IPv4 total_length {} invalid (header_size {}, l3 size {})",
                    total_length, header_size, l3.size());
                return std::nullopt;
            }
            return std::tuple{
                IpAddress::FromV4Bytes(l3.subspan<12, 4>()),
                IpAddress::FromV4Bytes(l3.subspan<16, 4>()),
                std::to_integer<uint8_t>(l3[8]),  // TTL
                l3.subspan(header_size, total_length - header_size),
            };
        }
        if (ethertype == IPV6_ETHERTYPE) {
            if (l3.size() < IPV6_HEADER_SIZE) {
                logger_.Error("IPv6 payload too short for header: {} bytes", l3.size());
                return std::nullopt;
            }
            const auto version = std::to_integer<uint8_t>(l3[0]) >> 4;
            if (version != 6) {
                logger_.Error("IPv6 ethertype with version field {}", version);
                return std::nullopt;
            }
            const auto next_header = std::to_integer<uint8_t>(l3[6]);
            // Extension headers (Fragment, Hop-by-Hop, Routing, ...) all fail this check.
            if (next_header != IP_PROTO_UDP) {
                logger_.Debug("Dropping IPv6 packet with next-header {} (extension header or non-UDP)", next_header);
                return std::nullopt;
            }
            // Trim by payload_length for the same reason as IPv4 total_length above.
            const auto payload_length = ReadU16Be(l3.subspan<4, 2>());
            if (IPV6_HEADER_SIZE + payload_length > l3.size()) {
                logger_.Error("IPv6 payload_length {} exceeds captured size (l3 size {})",
                    payload_length, l3.size());
                return std::nullopt;
            }
            return std::tuple{
                IpAddress::FromV6Bytes(l3.subspan<8, 16>()),
                IpAddress::FromV6Bytes(l3.subspan<24, 16>()),
                std::to_integer<uint8_t>(l3[7]),  // hop limit
                l3.subspan(IPV6_HEADER_SIZE, payload_length),
            };
        }
        logger_.Error("Frame ethertype {:#x} reached parser; BPF filter should have dropped it", ethertype);
        return std::nullopt;
    };

    const auto l3_parsed = parse_l3();
    if (!l3_parsed) {
        return std::nullopt;
    }
    const auto& [source_ip, dest_ip, ttl, l4] = *l3_parsed;

    if (l4.size() < UDP_HEADER_SIZE) {
        logger_.Error("L4 payload too short for UDP header: {} bytes", l4.size());
        return std::nullopt;
    }
    const auto source_port = ReadU16Be(l4.subspan<0, 2>());
    const auto dest_port = ReadU16Be(l4.subspan<2, 2>());
    const auto udp_length = ReadU16Be(l4.subspan<4, 2>());
    if (udp_length < UDP_HEADER_SIZE || udp_length > l4.size()) {
        logger_.Warning("UDP length {} invalid (header min {}, l4 size {})",
            udp_length, UDP_HEADER_SIZE, l4.size());
        return std::nullopt;
    }
    const auto payload = l4.subspan(UDP_HEADER_SIZE, udp_length - UDP_HEADER_SIZE);

    return Packet{
        .header = PacketHeader{
            .source_ip = source_ip,
            .dest_ip = dest_ip,
            .source_port = source_port,
            .dest_port = dest_port,
            .ttl = ttl,
            .source_mac = source_mac,
            .dest_mac = dest_mac,
        },
        .payload = payload,
    };
}

} // namespace reflector
