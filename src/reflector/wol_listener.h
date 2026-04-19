#pragma once

#include "dispatcher.h"
#include "logger.h"
#include "udp_listener.h"
#include "util/no_copy.h"
#include "util/no_move.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace reflector {

class WolListener : NoMove {
public:
    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration();

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept { return listener_ != nullptr && dispatcher_reg_.IsValid(); }
        bool Reset() noexcept;

    private:
        friend class WolListener;

        Registration(WolListener& listener, Dispatcher::Registration dispatcher_reg, uint16_t port) noexcept;

        WolListener* listener_ = nullptr;
        Dispatcher::Registration dispatcher_reg_;
        uint16_t port_ = 0;
    };

    WolListener(Dispatcher& dispatcher, std::string_view interface);
    ~WolListener();

    [[nodiscard]] Registration Register(uint16_t port, const PacketCallback& callback);

private:
    friend class WolListenerTest;
    friend class WolReflectorTest;

    struct PortListener {
        UdpListener listener;
        size_t refcount;
        uint16_t port;
    };

    [[nodiscard]] PortListener* AcquirePort(uint16_t port);
    void ReleasePort(uint16_t port) noexcept;
    [[nodiscard]] size_t ListenerCount() const noexcept { return listeners_.size(); }

    Logger logger_{"WolListener"};
    Dispatcher* dispatcher_;
    std::string interface_;
    std::vector<PortListener> listeners_;
};

} // namespace reflector
