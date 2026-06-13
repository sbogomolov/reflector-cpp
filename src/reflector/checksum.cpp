#include "checksum.h"

#include "protocol_constants.h"
#include "util/byte_order.h"

#include <array>
#include <cassert>
#include <cstring>

namespace reflector {

namespace {

constexpr std::byte UDP_PROTOCOL{IP_PROTO_UDP};

// Sum 16-bit big-endian words into a 32-bit accumulator, padding a trailing odd byte with a
// zero low byte. `seed` lets callers chain segments (pseudo-header, then UDP header+payload).
uint32_t Accumulate(std::span<const std::byte> data, uint32_t seed) noexcept {
    uint32_t sum = seed;
    size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += ReadU16Be(data.subspan(i));
    }
    if (i < data.size()) {
        sum += std::to_integer<uint32_t>(data[i]) << 8;  // odd tail byte: high byte of a BE word
    }
    return sum;
}

// Fold carries into 16 bits and take the one's complement. Two folds suffice: after the
// first, the high half is at most 1, so the second always finishes the end-around carry.
// Same fixed two-step reduction as Linux's csum_fold / BSD's REDUCE + ADDCARRY.
uint16_t Fold(uint32_t sum) noexcept {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

} // namespace

uint16_t Ipv4HeaderChecksum(std::span<const std::byte> header) noexcept {
    return Fold(Accumulate(header, 0));
}

uint16_t UdpChecksum(const IpAddress& src, const IpAddress& dst, std::span<const std::byte> udp) noexcept {
    assert(src.AddressFamily() == dst.AddressFamily());
    const auto length = static_cast<uint16_t>(udp.size());

    uint32_t sum = 0;
    if (src.IsV4()) {
        // IPv4 pseudo-header: src(4) dst(4) zero(1) protocol(1) udp_length(2).
        std::array<std::byte, 12> pseudo{};
        std::memcpy(pseudo.data(), src.Bytes().data(), 4);
        std::memcpy(pseudo.data() + 4, dst.Bytes().data(), 4);
        pseudo[9] = UDP_PROTOCOL;
        WriteU16Be(length, std::span<std::byte>{pseudo.data() + 10, 2});
        sum = Accumulate(pseudo, sum);
    } else {
        // IPv6 pseudo-header: src(16) dst(16) udp_length(4) zero(3) next_header(1).
        std::array<std::byte, 40> pseudo{};
        std::memcpy(pseudo.data(), src.Bytes().data(), 16);
        std::memcpy(pseudo.data() + 16, dst.Bytes().data(), 16);
        WriteU16Be(length, std::span<std::byte>{pseudo.data() + 34, 2});
        pseudo[39] = UDP_PROTOCOL;
        sum = Accumulate(pseudo, sum);
    }

    const auto checksum = Fold(Accumulate(udp, sum));
    return checksum == 0 ? uint16_t{0xffff} : checksum;
}

} // namespace reflector
