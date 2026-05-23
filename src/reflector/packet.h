#pragma once

#include "ip_address.h"
#include "mac_address.h"
#include "util/delegate.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

struct PacketHeader {
    IpAddress source_ip;
    IpAddress dest_ip;
    uint16_t source_port = 0;
    uint16_t dest_port = 0;
    uint8_t ttl = 0;  // IPv4 TTL / IPv6 hop limit, as captured
    MacAddress source_mac{};
    MacAddress dest_mac{};
};

struct Packet {
    PacketHeader header;
    // Non-owning view into the reused receive buffer. Valid only for the duration
    // of the dispatching callback; copy the bytes if you need to retain them.
    std::span<const std::byte> payload;
};

struct PacketFilter {
    std::optional<IpAddress> source_ip = std::nullopt;
    std::optional<IpAddress> dest_ip = std::nullopt;
    std::optional<uint16_t> source_port = std::nullopt;
    std::optional<uint16_t> dest_port = std::nullopt;
    std::optional<MacAddress> source_mac = std::nullopt;
    std::optional<MacAddress> dest_mac = std::nullopt;

    // True if `packet` satisfies every set field; an unset (nullopt) field matches anything.
    [[nodiscard]] bool Matches(const Packet& packet) const noexcept {
        if (source_ip && *source_ip != packet.header.source_ip) {
            return false;
        }
        if (dest_ip && *dest_ip != packet.header.dest_ip) {
            return false;
        }
        if (source_port && *source_port != packet.header.source_port) {
            return false;
        }
        if (dest_port && *dest_port != packet.header.dest_port) {
            return false;
        }
        if (source_mac && *source_mac != packet.header.source_mac) {
            return false;
        }
        if (dest_mac && *dest_mac != packet.header.dest_mac) {
            return false;
        }
        return true;
    }
};

using PacketCallback = Delegate<void(const Packet&)>;

} // namespace reflector
