#pragma once

#include "reflector/ip_address.h"
#include "reflector/link_socket.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

// Combined LinkSocket fake standing in for a per-interface socket on both sides, so reflector and
// wiring logic run with no real fd or injected frame. Receive() never yields — packets are pushed
// through a FakePacketDispatcher instead. CanSend is configurable per family; the Send* methods
// record their arguments (or fail when `fail_send` is set, to drive the send-failure branch).
// InterfaceIndex is configurable and RefreshAddresses is counted, for tests that drive
// address-change routing.
struct FakeLinkSocket : LinkSocket {
    // A recorded send. Multicast/broadcast derive the L2 destination from dst_ip, so dst_mac stays
    // nullopt (we deliberately don't recompute it here); a unicast send carries its explicit dst MAC.
    struct Sent {
        std::vector<std::byte> payload;
        uint16_t src_port;
        uint16_t dst_port;
        IpAddress dst_ip;
        std::optional<MacAddress> dst_mac;
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

    [[nodiscard]] bool SendUdpDatagram(MacAddress dst_mac, IpAddress dst_ip, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(dst_ip, dst_mac, dst_port, src_port, payload, ttl);
    }

    [[nodiscard]] bool SendUdpMulticastDatagram(IpAddress group, uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(group, std::nullopt, dst_port, src_port, payload, ttl);
    }

    [[nodiscard]] bool SendUdpBroadcastDatagram(uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(IpAddress::BroadcastV4(), std::nullopt, dst_port, src_port, payload, ttl);
    }

    [[nodiscard]] bool JoinMulticastGroup(IpAddress group) noexcept override {
        if (fail_join) {
            return false;
        }
        joined_groups.push_back(group);
        return true;
    }

    [[nodiscard]] std::optional<IpAddress> SourceAddress(IpAddress::Family family) const noexcept override {
        return family == IpAddress::Family::V4 ? source_v4 : source_v6;
    }

    [[nodiscard]] unsigned InterfaceIndex() const noexcept override { return interface_index; }
    void RefreshAddresses() noexcept override { ++refresh_count; }

    bool valid = true;
    int fd = -1;
    bool can_send_v4 = true;
    bool can_send_v6 = true;
    bool fail_send = false;
    bool fail_join = false;
    unsigned interface_index = 0;
    unsigned refresh_count = 0;
    std::optional<IpAddress> source_v4 = IpAddress::LoopbackV4();
    std::optional<IpAddress> source_v6 = IpAddress::LoopbackV6();
    std::vector<Sent> sent;                  // every send; dst_mac engaged only for unicast
    std::vector<IpAddress> joined_groups;

private:
    // All three Send* overloads funnel here; dst_mac is engaged only for an explicit unicast
    // destination (multicast/broadcast pass nullopt). Honors `fail_send`.
    [[nodiscard]] bool RecordSend(IpAddress dst_ip, std::optional<MacAddress> dst_mac, uint16_t dst_port,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) {
        if (fail_send) {
            return false;
        }
        sent.push_back(Sent{
            .payload = std::vector<std::byte>{payload.begin(), payload.end()},
            .src_port = src_port,
            .dst_port = dst_port,
            .dst_ip = dst_ip,
            .dst_mac = dst_mac,
            .ttl = ttl,
        });
        return true;
    }
};

} // namespace reflector
