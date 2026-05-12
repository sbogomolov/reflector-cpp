#include "udp_sender.h"

#include "logger.h"

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"UdpSender"};
    return logger;
}

} // namespace

UdpSender::UdpSender(std::string_view interface)
        : UdpSender{interface, IpAddress::Broadcast()} {}

UdpSender::UdpSender(std::string_view interface, IpAddress broadcast_address)
        : interface_{interface}
        , broadcast_address_{broadcast_address} {
    valid_ = (interface_.empty() || socket_.SetInterface(interface_))
        && socket_.SetBroadcast(true);
    if (!valid_) {
        GetLogger().Error("Cannot create UDP sender on interface \"{}\"", interface_);
    }
}

bool UdpSender::SendBroadcast(std::span<const std::byte> payload, uint16_t port) noexcept {
    if (!valid_) {
        GetLogger().Error("Cannot send UDP broadcast on interface \"{}\": sender is invalid", interface_);
        return false;
    }

    if (!socket_.SendTo(payload, broadcast_address_, port)) {
        GetLogger().Error("Cannot send UDP broadcast to {}:{}", broadcast_address_, port);
        return false;
    }

    GetLogger().Debug("Sent UDP broadcast to {}:{} on interface \"{}\"", broadcast_address_, port, interface_);
    return true;
}

} // namespace reflector
