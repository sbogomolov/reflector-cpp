#include "frame_builder.h"

#include "checksum.h"
#include "logger.h"
#include "util/byte_order.h"

#include <cassert>
#include <cstring>
#include <sys/socket.h>

namespace reflector {

namespace {

// TODO: harmonize these protocol size/format constants across the codebase. The MAC size,
// Ethernet/IPv4/IPv6/UDP header sizes, ethertypes, and UDP protocol number are duplicated here
// and in the raw_socket parser, and appear as bare literals elsewhere (e.g. MacAddress's 6).
// Define each once in a shared header and use it throughout.
constexpr size_t ETHERNET_HEADER_SIZE = 14;
constexpr size_t LOOPBACK_HEADER_SIZE = 4;
constexpr size_t IPV4_HEADER_SIZE = 20;
constexpr size_t IPV6_HEADER_SIZE = 40;
constexpr size_t UDP_HEADER_SIZE = 8;
constexpr size_t MAC_SIZE = 6;
constexpr uint16_t IPV4_ETHERTYPE = 0x0800;
constexpr uint16_t IPV6_ETHERTYPE = 0x86dd;
constexpr std::byte UDP_PROTOCOL{17};
constexpr size_t MAX_UDP_LENGTH = 0xffff;

Logger& GetLogger() noexcept {
    static Logger logger{"FrameBuilder"};
    return logger;
}

// Total frame size for a datagram whose IP header begins after an `l2_size`-byte L2 header, or
// 0 (after logging why) if the datagram would overflow the 16-bit UDP length / IPv4
// total_length fields, or if `out_size` cannot hold the frame.
size_t CheckedFrameSize(size_t l2_size, bool v4, size_t payload_size, size_t out_size) noexcept {
    const size_t ip_size = v4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    const size_t udp_length = UDP_HEADER_SIZE + payload_size;
    if (udp_length > MAX_UDP_LENGTH || (v4 && ip_size + udp_length > MAX_UDP_LENGTH)) {
        GetLogger().Error("Cannot build UDP frame: {}-byte payload overflows the UDP length field", payload_size);
        return 0;
    }
    const size_t frame_size = l2_size + ip_size + udp_length;
    if (out_size < frame_size) {
        GetLogger().Error("Cannot build UDP frame: {}-byte buffer too small for {}-byte frame", out_size, frame_size);
        return 0;
    }
    return frame_size;
}

// Writes the IPv4/IPv6 header and UDP datagram (headers zeroed, fields and checksums filled)
// into `out`, which begins at the IP header. The caller writes the preceding L2 header and has
// already bounds-checked the whole frame via UdpFrameSize.
void WriteIpUdp(IpAddress src_ip, IpAddress dst_ip, uint16_t src_port, uint16_t dst_port,
    std::span<const std::byte> payload, uint8_t ttl, std::span<std::byte> out) noexcept {
    const bool v4 = src_ip.IsV4();
    const size_t ip_size = v4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    const size_t udp_off = ip_size;
    const size_t payload_off = udp_off + UDP_HEADER_SIZE;
    const size_t udp_length = UDP_HEADER_SIZE + payload.size();

    std::memset(out.data(), 0, ip_size + UDP_HEADER_SIZE);
    if (!payload.empty()) {
        std::memcpy(out.data() + payload_off, payload.data(), payload.size());
    }

    if (v4) {
        out[0] = std::byte{0x45};  // version 4, IHL 5 (no options)
        WriteU16Be(static_cast<uint16_t>(ip_size + udp_length), out.subspan(2));  // total length
        out[8] = std::byte{ttl};  // TTL
        out[9] = UDP_PROTOCOL;  // protocol
        std::memcpy(out.data() + 12, src_ip.Bytes().data(), 4);
        std::memcpy(out.data() + 16, dst_ip.Bytes().data(), 4);
        WriteU16Be(Ipv4HeaderChecksum(out.subspan(0, IPV4_HEADER_SIZE)), out.subspan(10));
    } else {
        out[0] = std::byte{0x60};  // version 6, zero traffic class / flow label
        WriteU16Be(static_cast<uint16_t>(udp_length), out.subspan(4));  // payload length
        out[6] = UDP_PROTOCOL;  // next header
        out[7] = std::byte{ttl};  // hop limit
        std::memcpy(out.data() + 8, src_ip.Bytes().data(), 16);
        std::memcpy(out.data() + 24, dst_ip.Bytes().data(), 16);
    }

    WriteU16Be(src_port, out.subspan(udp_off));
    WriteU16Be(dst_port, out.subspan(udp_off + 2));
    WriteU16Be(static_cast<uint16_t>(udp_length), out.subspan(udp_off + 4));
    WriteU16Be(UdpChecksum(src_ip, dst_ip, out.subspan(udp_off, udp_length)), out.subspan(udp_off + 6));
}

} // namespace

MacAddress MulticastMacFor(IpAddress address) noexcept {
    const auto& bytes = address.Bytes();
    MacAddress::ByteArray mac{};
    if (address.IsV4()) {
        if (address == IpAddress::BroadcastV4()) {
            mac.fill(std::byte{0xff});
        } else {
            mac[0] = std::byte{0x01};
            mac[1] = std::byte{0x00};
            mac[2] = std::byte{0x5e};
            mac[3] = bytes[1] & std::byte{0x7f};  // top bit cleared: only the low 23 address bits map
            mac[4] = bytes[2];
            mac[5] = bytes[3];
        }
    } else {
        mac[0] = std::byte{0x33};
        mac[1] = std::byte{0x33};
        mac[2] = bytes[12];
        mac[3] = bytes[13];
        mac[4] = bytes[14];
        mac[5] = bytes[15];
    }
    return MacAddress{mac};
}

size_t BuildUdpFrame(
    MacAddress dst_mac,
    MacAddress src_mac,
    IpAddress src_ip,
    IpAddress dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    std::span<const std::byte> payload,
    uint8_t ttl,
    std::span<std::byte> out) noexcept {
    assert(src_ip.AddressFamily() == dst_ip.AddressFamily());
    const size_t frame_size = CheckedFrameSize(ETHERNET_HEADER_SIZE, src_ip.IsV4(), payload.size(), out.size());
    if (frame_size == 0) {
        return 0;
    }

    std::memcpy(out.data(), dst_mac.Bytes().data(), MAC_SIZE);
    std::memcpy(out.data() + MAC_SIZE, src_mac.Bytes().data(), MAC_SIZE);
    WriteU16Be(src_ip.IsV4() ? IPV4_ETHERTYPE : IPV6_ETHERTYPE, out.subspan(12));
    WriteIpUdp(src_ip, dst_ip, src_port, dst_port, payload, ttl, out.subspan(ETHERNET_HEADER_SIZE));
    return frame_size;
}

#if defined(__APPLE__)
size_t BuildLoopbackUdpFrame(
    IpAddress src_ip,
    IpAddress dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    std::span<const std::byte> payload,
    uint8_t ttl,
    std::span<std::byte> out) noexcept {
    assert(src_ip.AddressFamily() == dst_ip.AddressFamily());
    const size_t frame_size = CheckedFrameSize(LOOPBACK_HEADER_SIZE, src_ip.IsV4(), payload.size(), out.size());
    if (frame_size == 0) {
        return 0;
    }

    // DLT_NULL: 4-byte address family in host byte order, matching the capture path.
    const uint32_t family = src_ip.IsV4() ? static_cast<uint32_t>(AF_INET) : static_cast<uint32_t>(AF_INET6);
    std::memcpy(out.data(), &family, sizeof(family));
    WriteIpUdp(src_ip, dst_ip, src_port, dst_port, payload, ttl, out.subspan(LOOPBACK_HEADER_SIZE));
    return frame_size;
}
#endif

} // namespace reflector
