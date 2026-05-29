#include "application.h"

#include "default_address_monitor.h"
#include "event_loop_dispatcher.h"
#include "mdns_reflector.h"
#include "raw_socket.h"
#include "ssdp_reflector.h"
#include "util/delegate.h"
#include "wol_reflector.h"

#include <cassert>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace reflector {

Application::Application()
        : socket_factory_{[](std::string_view interface) -> std::unique_ptr<LinkSocket> {
              return std::make_unique<RawSocket>(interface);
          }}
        , logger_{"Application"}
        , dispatcher_{std::make_unique<EventLoopDispatcher>()}
        , address_monitor_{std::make_unique<DefaultAddressMonitor>(*dispatcher_)} {
    StartMonitor();
}

Application::Application(std::unique_ptr<Dispatcher> dispatcher, std::unique_ptr<AddressMonitor> monitor,
    SocketFactory socket_factory)
        : socket_factory_{std::move(socket_factory)}
        , logger_{"Application"}
        , dispatcher_{std::move(dispatcher)}
        , address_monitor_{std::move(monitor)} {
    StartMonitor();
}

Application Application::ForTesting(std::unique_ptr<Dispatcher> dispatcher,
    std::unique_ptr<AddressMonitor> monitor, SocketFactory socket_factory) {
    return Application{std::move(dispatcher), std::move(monitor), std::move(socket_factory)};
}

void Application::StartMonitor() {
    // Address-change refresh is best-effort: if the monitor can't start (it logs the cause),
    // carry on without it rather than failing the daemon.
    if (!address_monitor_->Start(CreateDelegate<&Application::OnInterfaceChanged>(this))) {
        logger_.Warning("Address monitor unavailable; source addresses will not refresh on interface changes");
    }
}

LinkSocket* Application::GetOrCreateSocket(const std::string& interface) {
    // One socket per interface, shared by every reflector that captures on or sends through
    // it; created lazily on first use via the (overridable) factory.
    auto [entry, inserted] = sockets_.try_emplace(interface);
    if (inserted) {
        entry->second = socket_factory_(interface);
    }
    const auto& socket = entry->second;
    return (socket && socket->IsValid()) ? socket.get() : nullptr;
}

template <class ReflectorType, class ConfigType>
bool Application::ConfigureReflectors(const std::vector<ConfigType>& configs, std::string_view protocol) {
    for (const auto& config : configs) {
        auto* source_socket = GetOrCreateSocket(config.source_if);
        if (source_socket == nullptr) {
            logger_.Error("Cannot configure {} reflector \"{}\": socket on interface \"{}\" is invalid",
                protocol, config.name, config.source_if);
            return false;
        }
        auto* target_socket = GetOrCreateSocket(config.target_if);
        if (target_socket == nullptr) {
            logger_.Error("Cannot configure {} reflector \"{}\": socket on interface \"{}\" is invalid",
                protocol, config.name, config.target_if);
            return false;
        }

        auto reflector = std::make_unique<ReflectorType>(packet_dispatcher_, *source_socket, *target_socket, config);
        if (!reflector->IsValid()) {
            logger_.Error("Cannot configure {} reflector \"{}\": setup failed", protocol, config.name);
            return false;
        }
        reflectors_.push_back(std::move(reflector));
    }
    return true;
}

bool Application::Configure(const Config& config) {
    if (ConfigureReflectors<WolReflector>(config.WolConfigs(), "wol")
        && ConfigureReflectors<MdnsReflector>(config.MdnsConfigs(), "mdns")
        && ConfigureReflectors<SsdpReflector>(config.SsdpConfigs(), "ssdp")) {
        return true;
    }
    // Fail closed: drop any reflectors wired before the failure so a config error never leaves a
    // partially-wired Application. Pairs with Run's assert(!reflectors_.empty()).
    reflectors_.clear();
    return false;
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
    // Reaching Run with nothing wired means the caller ignored a failed Configure (a valid config
    // has at least one reflector). The control flow already guarantees this; assert documents it.
    assert(!reflectors_.empty());
    dispatcher_->Run(stop_requested);
}

} // namespace reflector
