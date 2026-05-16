#pragma once

#include "ip_address.h"
#include "util/delegate.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace reflector {

struct PacketHeader {
    IpAddress source_ip;
    uint16_t source_port = 0;
};

struct Packet {
    PacketHeader header;
    // Non-owning view into the dispatcher's reused receive buffer. Valid only for the duration
    // of the dispatching callback; copy the bytes if you need to retain them.
    std::span<const std::byte> payload;
};

struct PacketFilter {
    // An unset source_ip matches packets from any source address.
    std::optional<IpAddress> source_ip;
    uint16_t source_port = 0;
};

using PacketCallback = Delegate<void(const Packet&)>;

} // namespace reflector
