#pragma once

#include "dispatcher.h"
#include "udp_listener.h"
#include "util/no_copy.h"
#include "util/no_move.h"
#include "util/shared_ptr_unsynchronized.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
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

    WolListener(Dispatcher& dispatcher, std::string_view interface);
    ~WolListener() noexcept;

    [[nodiscard]] Registration Register(uint16_t port, const PacketCallback& callback);

private:
    friend class WolListenerTest;
    friend class WolReflectorTest;

    struct PortListener {
        UdpListener listener;
        size_t refcount;
        uint16_t port;
    };

    [[nodiscard]] int AcquirePort(uint16_t port);
    void ReleasePort(uint16_t port) noexcept;
    bool Unregister(const SharedPtrUnsynchronized<RegistrationEntry>& registration) noexcept;
    [[nodiscard]] size_t ListenerCount() const noexcept { return listeners_.size(); }

    Dispatcher* dispatcher_;
    std::string interface_;
    std::vector<PortListener> listeners_;
    std::vector<SharedPtrUnsynchronized<RegistrationEntry>> registrations_;
};

} // namespace reflector
