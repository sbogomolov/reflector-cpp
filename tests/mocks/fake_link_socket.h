#pragma once

#include "fake_interface.h"
#include "reflector/ip_address.h"
#include "reflector/link_socket.h"
#include "reflector/mac_address.h"
#include "reflector/packet.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace reflector {

// Combined LinkSocket fake standing in for a per-interface socket on both sides, so reflector and
// wiring logic run with no real fd or injected frame. Receive() never yields — packets are pushed
// through a FakePacketDispatcher instead. The Send* methods record their arguments (or fail when
// `fail_send` is set, to drive the send-failure branch). The fake owns its Interface (a production
// socket borrows an Application-owned one); tests reach it via `iface` to set addresses or count
// refreshes, and stamp an index through the ctor.
struct FakeLinkSocket : LinkSocket {
    explicit FakeLinkSocket(std::string_view name = "fake0", unsigned index = 0)
            : iface{name, index} {}

    // Borrowing ctor: GetInterface() returns `borrowed_interface` instead of the owned `iface`,
    // mirroring how a production socket borrows an Application-owned Interface.
    explicit FakeLinkSocket(const Interface& borrowed_interface) : borrowed{&borrowed_interface} {}

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
#endif

    [[nodiscard]] bool SendUdpDatagram(MacAddress dst_mac, const IpEndpoint& dst,
        uint16_t src_port, std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(dst.addr, dst_mac, dst.port, src_port, payload, ttl);
    }

    [[nodiscard]] bool SendUdpMulticastDatagram(const IpEndpoint& dst, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(dst.addr, std::nullopt, dst.port, src_port, payload, ttl);
    }

    [[nodiscard]] bool SendUdpBroadcastDatagram(uint16_t dst_port, uint16_t src_port,
        std::span<const std::byte> payload, uint8_t ttl) noexcept override {
        return RecordSend(IpAddress::BroadcastV4(), std::nullopt, dst_port, src_port, payload, ttl);
    }

    [[nodiscard]] MulticastMembership JoinMulticastGroup(const IpAddress& group) noexcept override {
        if (fail_join) {
            return {};
        }
        joined_groups.push_back(group);
        return MakeMembership(group);
    }

    [[nodiscard]] const Interface& GetInterface() const noexcept override {
        return borrowed != nullptr ? *borrowed : iface;
    }

    FakeInterface iface;  // the owned identity; ignored when `borrowed` is set
    const Interface* borrowed = nullptr;
    bool valid = true;
    int fd = -1;
    bool fail_send = false;
    bool fail_join = false;
    std::vector<Sent> sent;                  // every send; dst_mac engaged only for unicast
    std::vector<IpAddress> joined_groups;    // every join, in order (append-only)
    std::vector<IpAddress> left_groups;      // every membership drop, in order (append-only)

private:
    // Records a membership drop (a MulticastMembership reset/destroyed).
    bool Unregister(const IpAddress& group) noexcept override {
        left_groups.push_back(group);
        return true;
    }

    // All three Send* overloads funnel here; dst_mac is engaged only for an explicit unicast
    // destination (multicast/broadcast pass nullopt).
    [[nodiscard]] bool RecordSend(const IpAddress& dst_ip, std::optional<MacAddress> dst_mac, uint16_t dst_port,
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
