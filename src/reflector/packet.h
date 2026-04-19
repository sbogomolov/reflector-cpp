#pragma once

#include "ip_address.h"
#include "util/delegate.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace reflector {

struct PacketHeader {
    IpAddress source_ip = IpAddress::Any();
    uint16_t source_port = 0;
};

struct Packet {
    PacketHeader header;
    // Valid only for the duration of the dispatching callback; never store this span.
    std::span<const std::byte> payload;
};

struct PacketFilter {
    IpAddress source_ip = IpAddress::Any();
    uint16_t source_port = 0;
};

using PacketCallback = Delegate<void(const Packet&)>;

} // namespace reflector
