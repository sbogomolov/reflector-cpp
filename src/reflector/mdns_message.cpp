#include "mdns_message.h"

#include <cstddef>

namespace {

// DNS header (RFC 1035 §4.1.1): a fixed 12-byte prefix. The QR bit is the most significant bit of
// the 16-bit flags field at bytes 2-3 — i.e. the top bit of byte 2 in network order.
constexpr size_t DNS_HEADER_SIZE = 12;
constexpr size_t FLAGS_HIGH_OFFSET = 2;
constexpr std::byte QR_BIT{0x80};

} // namespace

namespace reflector {

std::optional<MdnsMessageKind> ClassifyMdnsMessage(std::span<const std::byte> payload) noexcept {
    if (payload.size() < DNS_HEADER_SIZE) {
        return std::nullopt;
    }
    const bool is_response = (payload[FLAGS_HIGH_OFFSET] & QR_BIT) != std::byte{0};
    return is_response ? MdnsMessageKind::Response : MdnsMessageKind::Query;
}

} // namespace reflector
