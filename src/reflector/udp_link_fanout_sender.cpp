#include "udp_link_fanout_sender.h"

#include "logger.h"

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"UdpLinkFanoutSender"};
    return logger;
}

IpAddress DefaultDestinationAddress(IpAddress::Family family) noexcept {
    return family == IpAddress::Family::V6 ? IpAddress::AllNodesLinkLocalV6() : IpAddress::BroadcastV4();
}

} // namespace

UdpLinkFanoutSender::UdpLinkFanoutSender(std::string_view interface, IpAddress::Family family)
        : UdpLinkFanoutSender{interface, DefaultDestinationAddress(family)} {}

UdpLinkFanoutSender::UdpLinkFanoutSender(std::string_view interface, IpAddress destination_address)
        : socket_{destination_address.AddressFamily()}
        , interface_{interface}
        , destination_address_{destination_address} {
    valid_ = SetUp();
    if (!valid_) {
        GetLogger().Error("Cannot create {} UDP link fanout sender on interface \"{}\"",
            destination_address_.AddressFamily(), interface_);
    }
}

bool UdpLinkFanoutSender::SetUp() noexcept {
    if (!socket_.IsValid()) {
        return false;
    }
    if (!interface_.empty() && !socket_.SetInterface(interface_)) {
        return false;
    }

    if (destination_address_.IsV6()) {
        // IPv6 multicast needs a socket egress interface in addition to the per-send scope id.
        return interface_.empty() || socket_.SetMulticastInterface(interface_);
    }

    return socket_.SetBroadcast(true);
}

bool UdpLinkFanoutSender::Send(std::span<const std::byte> payload, uint16_t port) noexcept {
    if (!valid_) {
        GetLogger().Error("Cannot send UDP link fanout packet on interface \"{}\": sender is invalid", interface_);
        return false;
    }

    if (!socket_.SendTo(payload, destination_address_, port)) {
        GetLogger().Error("Cannot send UDP link fanout packet to {}:{}", destination_address_, port);
        return false;
    }

    GetLogger().Debug("Sent UDP link fanout packet to {}:{} on interface \"{}\"",
        destination_address_, port, interface_);
    return true;
}

} // namespace reflector
