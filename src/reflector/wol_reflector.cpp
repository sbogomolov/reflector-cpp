#include "wol_reflector.h"

#include "interface.h"
#include "util/delegate.h"

#include <cstring>
#include <format>
#include <string>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const WolConfig& config) {
    return std::format("WolReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
}

} // namespace

WolReflector::WolReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
    LinkSocket& target_socket, const WolConfig& config)
        : Reflector{LoggerName(config)}
        , target_socket_{target_socket} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(packet_dispatcher, source_socket, config);
}

bool WolReflector::ValidateConfig(const WolConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create wol reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void WolReflector::Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket, const WolConfig& config) {
    const auto& target_interface = target_socket_.GetInterface();
    if (config.RequiresIPv4() && !target_interface.CanSend(IpAddress::Family::V4)) {
        logger_.Error("Cannot create wol reflector \"{}\": target_if \"{}\" cannot send IPv4",
            config.name, config.target_if);
        return;
    }
    if (config.RequiresIPv6() && !target_interface.CanSend(IpAddress::Family::V6)) {
        logger_.Error("Cannot create wol reflector \"{}\": target_if \"{}\" cannot send IPv6",
            config.name, config.target_if);
        return;
    }

    reflects_v4_ = config.UsesIPv4() && target_interface.CanSend(IpAddress::Family::V4);
    reflects_v6_ = config.UsesIPv6() && target_interface.CanSend(IpAddress::Family::V6);

    target_mac_ = config.mac;
    std::fill_n(expected_magic_packet_.begin(), PREFIX_SIZE, std::byte{0xff});
    if (target_mac_) {
        BuildExpectedMagicPacket(*target_mac_);
    }

    registrations_.reserve(config.ports.size());

    for (const auto port : config.ports) {
        auto registration = packet_dispatcher.Register(source_socket, PacketFilter{.dest_port = port},
            CreateDelegate<&WolReflector::OnPacket>(this));
        if (!registration.IsValid()) {
            logger_.Error("Cannot create wol reflector \"{}\": registration failed for port {}",
                config.name, port);
            registrations_.clear();
            return;
        }
        registrations_.push_back(std::move(registration));
    }

    logger_.Info("Created wol reflector (IPv4: {}, IPv6: {})",
        reflects_v4_ ? "enabled" : "disabled",
        reflects_v6_ ? "enabled" : "disabled");
}

// The 6x 0xFF prefix + 16x target-MAC sequence must begin at payload offset 0. The AMD
// spec allows the sequence at any offset within a frame, but every real UDP WoL sender
// anchors it at the start of the datagram (a trailing SecureOn password is fine — extra
// bytes after the 102 are ignored here and forwarded as-is). Anchoring keeps the match a
// single memcmp and narrows what this reflector will re-broadcast onto target_if.
bool WolReflector::IsMagicPacket(std::span<const std::byte> payload) noexcept {
    if (payload.size() < MAGIC_PACKET_SIZE) {
        logger_.Debug("Ignoring wol packet: payload is too short: {} bytes", payload.size());
        return false;
    }

    if (target_mac_) {
        if (std::memcmp(payload.data(), expected_magic_packet_.data(), expected_magic_packet_.size()) != 0) {
            logger_.Debug("Ignoring wol packet: magic packet does not match expected MAC");
            return false;
        }
        return true;
    }

    if (!HasMagicPacketPrefix(payload)) {
        logger_.Debug("Ignoring wol packet: magic packet prefix is invalid");
        return false;
    }

    if (!HasRepeatedMac(payload)) {
        logger_.Debug("Ignoring wol packet: magic packet MAC repetitions are inconsistent");
        return false;
    }

    return true;
}

bool WolReflector::HasMagicPacketPrefix(std::span<const std::byte> payload) noexcept {
    return std::memcmp(payload.data(), expected_magic_packet_.data(), PREFIX_SIZE) == 0;
}

bool WolReflector::HasRepeatedMac(std::span<const std::byte> payload) noexcept {
    const auto* mac = payload.data() + PREFIX_SIZE;
    for (size_t repetition = 1; repetition < MAC_REPETITIONS; ++repetition) {
        const auto* repeated_mac = mac + repetition * MAC_SIZE;
        if (std::memcmp(mac, repeated_mac, MAC_SIZE) != 0) {
            return false;
        }
    }
    return true;
}

void WolReflector::BuildExpectedMagicPacket(MacAddress mac) noexcept {
    auto out = expected_magic_packet_.begin();
    out = std::fill_n(out, PREFIX_SIZE, std::byte{0xff});
    const auto& mac_bytes = mac.Bytes();
    for (size_t repetition = 0; repetition < MAC_REPETITIONS; ++repetition) {
        out = std::copy(mac_bytes.begin(), mac_bytes.end(), out);
    }
}

bool WolReflector::ReflectsFamily(IpAddress::Family family) const noexcept {
    return family == IpAddress::Family::V4 ? reflects_v4_ : reflects_v6_;
}

void WolReflector::OnPacket(const Packet& packet) noexcept {
    if (!IsMagicPacket(packet.payload)) {
        return;
    }

    const auto family = packet.header.source.addr.AddressFamily();
    if (!ReflectsFamily(family)) {
        logger_.Debug("Ignoring wol packet from {}: {} not handled",
            packet.header.source, family);
        return;
    }

    const auto port = packet.header.dest.port;
    // Fan the magic packet out to "everyone on the target link": the IPv4 limited broadcast, or the
    // IPv6 link-local all-nodes multicast group. Re-emit with the captured TTL / hop limit so the
    // reflected datagram preserves the sender's reach instead of resetting it.
    const bool v4 = family == IpAddress::Family::V4;
    const auto destination = v4 ? IpAddress::BroadcastV4() : IpAddress::AllNodesLinkLocalV6();
    const bool sent = v4
        ? target_socket_.SendUdpBroadcastDatagram(
              port, packet.header.source.port, packet.payload, packet.header.ttl)
        : target_socket_.SendUdpMulticastDatagram(
              {destination, port}, packet.header.source.port, packet.payload, packet.header.ttl);
    if (!sent) {
        logger_.Error("Cannot reflect wol packet from {} to {}:{}",
            packet.header.source, destination, port);
        return;
    }

    // The MAC comes from the payload, not the frame's L2 header: it names the device that
    // will wake, and IsMagicPacket has already validated the payload is long enough.
    const auto target = MacAddress::FromBytes(packet.payload.subspan<PREFIX_SIZE, MAC_SIZE>());
    logger_.Info("Reflected WoL packet for {} from {} to {}:{}",
        target, packet.header.source, destination, port);
}

} // namespace reflector
