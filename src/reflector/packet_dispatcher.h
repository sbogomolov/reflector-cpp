#pragma once

#include "packet.h"
#include "receive_socket.h"
#include "util/registration.h"

#include <cstdint>

namespace reflector {

// Registers filtered packet callbacks and dispatches matching captured packets to them — the
// "initiation dispatcher" of the reactor pattern. DefaultPacketDispatcher is the production
// implementation (layered on the Dispatcher reactor); tests substitute a fake.
class PacketDispatcher {
public:
    using RegistrationId = uint64_t;
    // RAII handle for one packet-callback registration; resetting it unregisters the callback.
    using Registration = reflector::Registration<PacketDispatcher, RegistrationId>;

    virtual ~PacketDispatcher() noexcept = default;

    // The socket must outlive every registration returned for it and this dispatcher: the
    // dispatcher keeps a raw pointer to it. The returned registration must not outlive the
    // dispatcher.
    [[nodiscard]] virtual Registration Register(
        ReceiveSocket& socket, const PacketFilter& filter, const PacketCallback& callback) = 0;

protected:
    [[nodiscard]] Registration MakeRegistration(RegistrationId id) noexcept { return Registration{this, id}; }

private:
    friend Registration;

    virtual bool Unregister(RegistrationId id) noexcept = 0;
};

} // namespace reflector
