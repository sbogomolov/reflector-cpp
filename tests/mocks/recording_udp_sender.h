#pragma once

#include "reflector/ip_address.h"
#include "reflector/udp_sender.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace reflector {

// Recording fake UdpSender: substitutes for a real socket on the send side so reflector logic
// is exercised without injecting a frame on the wire. CanSend is configurable per family;
// SendUdpDatagram records its arguments (or fails when `fail_send` is set, to drive the
// send-failure branch).
struct RecordingUdpSender : UdpSender {
    struct Sent {
        std::vector<std::byte> payload;
        uint16_t src_port;
        uint16_t dst_port;
        IpAddress dst_ip;
        uint8_t ttl;
    };

    [[nodiscard]] bool CanSend(IpAddress::Family family) const noexcept override {
        return family == IpAddress::Family::V4 ? can_send_v4 : can_send_v6;
    }

    [[nodiscard]] bool SendUdpDatagram(IpAddress dst_ip, uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        if (fail_send) {
            return false;
        }
        sent.push_back(Sent{
            .payload = std::vector<std::byte>{payload.begin(), payload.end()},
            .src_port = src_port,
            .dst_port = dst_port,
            .dst_ip = dst_ip,
            .ttl = ttl,
        });
        return true;
    }

    bool can_send_v4 = true;
    bool can_send_v6 = true;
    bool fail_send = false;
    std::vector<Sent> sent;
};

} // namespace reflector
