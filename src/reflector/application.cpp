#include "application.h"

#include <memory>
#include <string_view>
#include <utility>

namespace reflector {

Application::Application()
        : Application{[](std::string_view interface) {
              return std::make_unique<RawSocket>(interface);
          }} {}

Application::Application(SocketFactory socket_factory)
        : socket_factory_{std::move(socket_factory)}
        , logger_{"Application"} {}

bool Application::Configure(const Config& config) {
    for (const auto& wol_config : config.WolConfigs()) {
        // One socket per source interface, shared by every reflector registered on
        // it; created lazily on first use via the (overridable) factory.
        auto [entry, inserted] = sockets_.try_emplace(wol_config.source_if);
        if (inserted) {
            entry->second = socket_factory_(wol_config.source_if);
        }
        auto& socket = entry->second;
        if (!socket || !socket->IsValid()) {
            logger_.Error("Cannot configure wol reflector \"{}\": socket on interface \"{}\" is invalid",
                wol_config.name, wol_config.source_if);
            return false;
        }

        auto reflector = std::make_unique<WolReflector>(packet_dispatcher_, *socket, wol_config);
        if (!reflector->IsValid()) {
            logger_.Error("Cannot configure wol reflector \"{}\": setup failed", wol_config.name);
            return false;
        }
        reflectors_.push_back(std::move(reflector));
    }
    return true;
}

void Application::OnInterfaceChanged(unsigned interface_index) noexcept {
    // index 0 is the monitor's "refresh everything" signal (notification overflow); otherwise
    // refresh only the socket bound to the changed interface.
    for (const auto& entry : sockets_) {
        const auto& socket = entry.second;
        if (socket && (interface_index == 0 || socket->InterfaceIndex() == interface_index)) {
            socket->RefreshAddresses();
        }
    }
}

void Application::Run(const volatile std::sig_atomic_t& stop_requested) {
    dispatcher_.Run(stop_requested);
}

} // namespace reflector
