#pragma once

#include "packet.h"
#include "receive_socket.h"
#include "util/no_copy.h"

#include <cstdint>

namespace reflector {

class PacketDispatcher;

using PacketRegistrationId = uint64_t;

// RAII handle for one packet-callback registration. Resetting it (or destroying it) unregisters
// the callback from the dispatcher that issued it. Movable, non-copyable. Must not outlive that
// dispatcher.
class PacketRegistration : NoCopy {
public:
    PacketRegistration() noexcept = default;
    ~PacketRegistration() noexcept;

    PacketRegistration(PacketRegistration&& other) noexcept;
    PacketRegistration& operator=(PacketRegistration&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept;
    bool Reset() noexcept;

private:
    friend class PacketDispatcher;

    PacketRegistration(PacketDispatcher* packet_dispatcher, PacketRegistrationId id) noexcept;

    PacketDispatcher* packet_dispatcher_ = nullptr;
    PacketRegistrationId id_ = 0;
};

// Registers filtered packet callbacks and dispatches matching captured packets to them — the
// "initiation dispatcher" of the reactor pattern. DefaultPacketDispatcher is the production
// implementation (layered on the Dispatcher reactor); tests substitute a fake.
class PacketDispatcher {
public:
    virtual ~PacketDispatcher() noexcept = default;

    // The socket must outlive every registration returned for it and this dispatcher: the
    // dispatcher keeps a raw pointer to it. The returned registration must not outlive the
    // dispatcher.
    [[nodiscard]] virtual PacketRegistration Register(
        ReceiveSocket& socket, const PacketFilter& filter, const PacketCallback& callback) = 0;

protected:
    // Implementations mint the RAII handle for a freshly assigned registration id through this;
    // PacketRegistration's constructor is otherwise private.
    [[nodiscard]] PacketRegistration MakeRegistration(PacketRegistrationId id) noexcept;

private:
    friend class PacketRegistration;

    virtual bool Unregister(PacketRegistrationId id) noexcept = 0;
};

} // namespace reflector
