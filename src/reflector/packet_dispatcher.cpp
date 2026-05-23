#include "packet_dispatcher.h"

#include <utility>

namespace reflector {

PacketRegistration::PacketRegistration(PacketDispatcher* packet_dispatcher, PacketRegistrationId id) noexcept
        : packet_dispatcher_{packet_dispatcher}, id_{id} {}

PacketRegistration::~PacketRegistration() noexcept {
    Reset();
}

PacketRegistration::PacketRegistration(PacketRegistration&& other) noexcept
        : packet_dispatcher_{std::exchange(other.packet_dispatcher_, nullptr)}
        , id_{std::exchange(other.id_, 0)} {}

PacketRegistration& PacketRegistration::operator=(PacketRegistration&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    Reset();
    packet_dispatcher_ = std::exchange(other.packet_dispatcher_, nullptr);
    id_ = std::exchange(other.id_, 0);
    return *this;
}

bool PacketRegistration::IsValid() const noexcept {
    return packet_dispatcher_ != nullptr && id_ != 0;
}

bool PacketRegistration::Reset() noexcept {
    if (packet_dispatcher_ == nullptr || id_ == 0) {
        packet_dispatcher_ = nullptr;
        id_ = 0;
        return false;
    }
    auto* packet_dispatcher = std::exchange(packet_dispatcher_, nullptr);
    const auto id = std::exchange(id_, 0);
    return packet_dispatcher->Unregister(id);
}

PacketRegistration PacketDispatcher::MakeRegistration(PacketRegistrationId id) noexcept {
    return PacketRegistration{this, id};
}

} // namespace reflector
