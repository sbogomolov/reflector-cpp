#include "wol_reflector.h"
#include "util/delegate.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <string>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const WolListener& listener, const WolConfig& config) {
    return std::format("WolReflector:{}:{}", config.name, listener.AddressFamily());
}

} // namespace

WolReflector::WolReflector(WolListener& listener, const WolConfig& config)
        : logger_{LoggerName(listener, config)} {
    if (!ValidateConfig(config)) {
        return;
    }

    owned_sender_.emplace(config.target_if, listener.AddressFamily());
    sender_ = &*owned_sender_;
    Initialize(listener, config);
}

WolReflector::WolReflector(WolListener& listener, UdpLinkFanoutSender& sender, const WolConfig& config)
        : logger_{LoggerName(listener, config)}, sender_{&sender} {
    if (!ValidateConfig(config)) {
        return;
    }

    Initialize(listener, config);
}

WolReflector::~WolReflector() noexcept {
    Reset();
}

bool WolReflector::ValidateConfig(const WolConfig& config) {
    if (const auto error = config.Verify()) {
        logger_.Error("Cannot create wol reflector \"{}\": invalid config: {}", config.name, *error);
        return false;
    }
    return true;
}

void WolReflector::Initialize(WolListener& listener, const WolConfig& config) {
    if (!sender_ || !sender_->IsValid()) {
        logger_.Error("Cannot create wol reflector \"{}\": sender setup failed", config.name);
        return;
    }

    target_mac_ = config.mac;
    std::fill_n(expected_magic_packet_.begin(), PREFIX_SIZE, std::byte{0xff});
    if (target_mac_.has_value()) {
        BuildExpectedMagicPacket(*target_mac_);
    }

    registrations_.reserve(config.ports.size());

    for (const auto port : config.ports) {
        auto& port_handler = port_handlers_.emplace_back(this, port);
        const auto callback = CreateDelegate<&PortHandler::OnPacket>(&port_handler);
        auto registration = listener.Register(port, callback);
        if (!registration.IsValid()) {
            logger_.Error("Cannot create wol reflector \"{}\": registration failed for port {}",
                config.name, port);
            registrations_.clear();
            port_handlers_.clear();
            return;
        }
        registrations_.push_back(std::move(registration));
    }

    logger_.Info("Created wol reflector \"{}\" from interface \"{}\" to interface \"{}\"",
        config.name, config.source_if, config.target_if);
}

bool WolReflector::IsMagicPacket(std::span<const std::byte> payload) noexcept {
    if (payload.size() < MAGIC_PACKET_SIZE) {
        logger_.Debug("Ignoring wol packet: payload is too short: {} bytes", payload.size());
        return false;
    }

    // Fixed-MAC mode: compare the packet against the precomputed magic packet.
    if (target_mac_.has_value()) {
        if (std::memcmp(payload.data(), expected_magic_packet_.data(), expected_magic_packet_.size()) != 0) {
            logger_.Debug("Ignoring wol packet: magic packet does not match expected MAC");
            return false;
        }
        return true;
    }

    // Any-MAC mode: validate the generic WoL shape and accept whichever MAC is repeated.
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

void WolReflector::PortHandler::OnPacket(const Packet& packet) noexcept {
    parent->HandlePacket(packet, port);
}

void WolReflector::HandlePacket(const Packet& packet, uint16_t port) noexcept {
    if (!IsMagicPacket(packet.payload)) {
        return;
    }

    if (!sender_->Send(packet.payload, port)) {
        logger_.Error("Cannot reflect wol packet from {}:{} to {}:{}",
            packet.header.source_ip, packet.header.source_port, sender_->DestinationAddress(), port);
        return;
    }

    logger_.Info("Reflected wol packet from {}:{} to {}:{}",
        packet.header.source_ip, packet.header.source_port, sender_->DestinationAddress(), port);
}

void WolReflector::Reset() noexcept {
    registrations_.clear();
    port_handlers_.clear();
}

} // namespace reflector
