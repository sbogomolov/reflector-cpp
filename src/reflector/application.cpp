#include "application.h"

#include "util/delegate.h"

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
        , logger_{"Application"} {
    // Address-change refresh is best-effort: if the monitor can't start (it logs the cause),
    // carry on without it rather than failing the daemon.
    if (!address_monitor_.Start(CreateDelegate<&Application::OnInterfaceChanged>(this))) {
        logger_.Warning("Address monitor unavailable; source addresses will not refresh on interface changes");
    }
}

RawSocket* Application::GetOrCreateSocket(const std::string& interface) {
    // One socket per interface, shared by every reflector that captures on or sends through
    // it; created lazily on first use via the (overridable) factory.
    auto [entry, inserted] = sockets_.try_emplace(interface);
    if (inserted) {
        entry->second = socket_factory_(interface);
    }
    const auto& socket = entry->second;
    return (socket && socket->IsValid()) ? socket.get() : nullptr;
}

bool Application::Configure(const Config& config) {
    for (const auto& wol_config : config.WolConfigs()) {
        auto* source_socket = GetOrCreateSocket(wol_config.source_if);
        if (source_socket == nullptr) {
            logger_.Error("Cannot configure wol reflector \"{}\": socket on interface \"{}\" is invalid",
                wol_config.name, wol_config.source_if);
            return false;
        }
        auto* target_socket = GetOrCreateSocket(wol_config.target_if);
        if (target_socket == nullptr) {
            logger_.Error("Cannot configure wol reflector \"{}\": socket on interface \"{}\" is invalid",
                wol_config.name, wol_config.target_if);
            return false;
        }

        auto reflector = std::make_unique<WolReflector>(packet_dispatcher_, *source_socket, *target_socket, wol_config);
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
