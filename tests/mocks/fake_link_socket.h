#pragma once

#include "reflector/ip_address.h"
#include "reflector/link_socket.h"
#include "reflector/packet.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

// Combined LinkSocket fake standing in for a per-interface socket on both sides, so reflector and
// wiring logic run with no real fd or injected frame. Receive() never yields — packets are pushed
// through a FakePacketDispatcher instead. CanSend is configurable per family; SendUdpDatagram
// records its arguments (or fails when `fail_send` is set, to drive the send-failure branch).
// InterfaceIndex is configurable and RefreshAddresses is counted, for tests that drive
// address-change routing.
struct FakeLinkSocket : LinkSocket {
    struct Sent {
        std::vector<std::byte> payload;
        uint16_t src_port;
        uint16_t dst_port;
        IpAddress dst_ip;
        uint8_t ttl;
    };

    [[nodiscard]] bool IsValid() const noexcept override { return valid; }
    [[nodiscard]] int Fd() const noexcept override { return fd; }
    [[nodiscard]] std::optional<Packet> Receive() noexcept override { return std::nullopt; }
#if defined(__APPLE__)
    [[nodiscard]] bool HasBufferedData() const noexcept override { return false; }
    void ClearBuffer() noexcept override {}
#endif

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

    [[nodiscard]] unsigned InterfaceIndex() const noexcept override { return interface_index; }
    void RefreshAddresses() noexcept override { ++refresh_count; }

    bool valid = true;
    int fd = -1;
    bool can_send_v4 = true;
    bool can_send_v6 = true;
    bool fail_send = false;
    unsigned interface_index = 0;
    unsigned refresh_count = 0;
    std::vector<Sent> sent;
};

} // namespace reflector
