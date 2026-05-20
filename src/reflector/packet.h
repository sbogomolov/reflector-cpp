#pragma once

#include "ip_address.h"
#include "mac_address.h"
#include "util/delegate.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

// TODO: consider not eagerly parsing the packet header. Store the raw frame as a span
// and provide getters that lazily extract IPs/ports/MACs on demand. Saves parsing work
// when callbacks read only a subset of fields, and lets future code reach into the L2/L3
// header bytes directly if needed.
struct PacketHeader {
    IpAddress source_ip;
    IpAddress dest_ip;
    uint16_t source_port = 0;
    uint16_t dest_port = 0;
    MacAddress source_mac;
    MacAddress dest_mac;
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
};

using PacketCallback = Delegate<void(const Packet&)>;

} // namespace reflector
