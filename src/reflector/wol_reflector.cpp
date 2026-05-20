#include "wol_reflector.h"
#include "util/delegate.h"

#include <cstring>
#include <format>
#include <string>
#include <utility>

namespace reflector {

namespace {

std::string LoggerName(const WolConfig& config) {
    return std::format("WolReflector:{}", config.name);
}

} // namespace

WolReflector::WolReflector(WolListener& listener, const WolConfig& config)
        : logger_{LoggerName(config)} {
    if (!ValidateConfig(config)) {
        return;
    }

    if (config.UsesIPv4()) {
        v4_sender_.emplace(config.target_if, IpAddress::Family::V4);
    }
    if (config.UsesIPv6()) {
        v6_sender_.emplace(config.target_if, IpAddress::Family::V6);
    }
    Initialize(listener, config);
}

WolReflector::WolReflector(WolListener& listener, const WolConfig& config,
    std::optional<UdpLinkFanoutSender> v4_sender, std::optional<UdpLinkFanoutSender> v6_sender)
        : logger_{LoggerName(config)}
        , v4_sender_{std::move(v4_sender)}
        , v6_sender_{std::move(v6_sender)} {
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
    const auto v4_ready = v4_sender_ && v4_sender_->IsValid();
    const auto v6_ready = v6_sender_ && v6_sender_->IsValid();
    if (config.RequiresIPv4() && !v4_ready) {
        logger_.Error("Cannot create wol reflector \"{}\": IPv4 sender setup failed", config.name);
        return;
    }
    if (config.RequiresIPv6() && !v6_ready) {
        logger_.Error("Cannot create wol reflector \"{}\": IPv6 sender setup failed", config.name);
        return;
    }

    // A family the config merely *uses* (Default uses both, but only requires v4) may have
    // failed setup — e.g. no IPv6 on target_if. Drop the optional so SenderFor returns
    // null for that family instead of dispatching to a sender that always returns false.
    if (!v4_ready) {
        v4_sender_.reset();
    }
    if (!v6_ready) {
        v6_sender_.reset();
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

    logger_.Info("Created wol reflector \"{}\" from interface \"{}\" to interface \"{}\" (IPv4: {}, IPv6: {})",
        config.name, config.source_if, config.target_if,
        v4_sender_ ? "enabled" : "disabled",
        v6_sender_ ? "enabled" : "disabled");
}

bool WolReflector::IsMagicPacket(std::span<const std::byte> payload) noexcept {
    if (payload.size() < MAGIC_PACKET_SIZE) {
        logger_.Debug("Ignoring wol packet: payload is too short: {} bytes", payload.size());
        return false;
    }

    if (target_mac_.has_value()) {
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

void WolReflector::PortHandler::OnPacket(const Packet& packet) noexcept {
    parent->HandlePacket(packet, port);
}

UdpLinkFanoutSender* WolReflector::SenderFor(IpAddress::Family family) noexcept {
    auto& sender = family == IpAddress::Family::V4 ? v4_sender_ : v6_sender_;
    return sender ? &*sender : nullptr;
}

void WolReflector::HandlePacket(const Packet& packet, uint16_t port) noexcept {
    if (!IsMagicPacket(packet.payload)) {
        return;
    }

    auto* sender = SenderFor(packet.header.source_ip.AddressFamily());
    if (!sender) {
        logger_.Debug("Ignoring wol packet from {}:{}: no sender for {}",
            packet.header.source_ip, packet.header.source_port, packet.header.source_ip.AddressFamily());
        return;
    }

    if (!sender->Send(packet.payload, port)) {
        logger_.Error("Cannot reflect wol packet from {}:{} to {}:{}",
            packet.header.source_ip, packet.header.source_port, sender->DestinationAddress(), port);
        return;
    }

    // TODO: include source MAC in this log line so operators can identify the originating
    // device, not just its (often DHCP'd) IP.
    logger_.Info("Reflected wol packet from {}:{} to {}:{}",
        packet.header.source_ip, packet.header.source_port, sender->DestinationAddress(), port);
}

void WolReflector::Reset() noexcept {
    registrations_.clear();
    port_handlers_.clear();
}

} // namespace reflector
