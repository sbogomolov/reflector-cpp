#pragma once

#include "packet_dispatcher.h"
#include "raw_socket.h"
#include "util/no_copy.h"
#include "util/no_move.h"
#include "util/shared_ptr_unsynchronized.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace reflector {

class WolListener : NoMove {
private:
    struct RegistrationEntry;

public:
    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration() noexcept;

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept;
        bool Reset() noexcept;

    private:
        friend class WolListener;

        explicit Registration(WeakPtrUnsynchronized<RegistrationEntry> registration_entry) noexcept;

        WeakPtrUnsynchronized<RegistrationEntry> registration_entry_;
    };

    WolListener(PacketDispatcher& packet_dispatcher, RawSocket& capture);
    ~WolListener() noexcept;

    [[nodiscard]] Registration Register(uint16_t port, const PacketCallback& callback);

private:
    friend class WolListenerTest;
    friend class WolReflectorTestBase;

    bool Unregister(SharedPtrUnsynchronized<RegistrationEntry> registration) noexcept;
    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    PacketDispatcher* packet_dispatcher_;
    RawSocket* capture_;
    std::vector<SharedPtrUnsynchronized<RegistrationEntry>> registrations_;
};

} // namespace reflector
