#include "application.h"

#include "default_address_monitor.h"
#include "error.h"
#include "event_loop_dispatcher.h"
#include "logger.h"
#include "mdns_reflector.h"
#include "raw_socket.h"
#include "ssdp_reflector.h"
#include "util/delegate.h"
#include "util/fd_util.h"
#include "wol_reflector.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {
using namespace reflector;
Logger& GetLogger() noexcept {
    static Logger logger{"Application"};
    return logger;
}
} // namespace

namespace reflector {

Application::Application()
        : interface_factory_{[](std::string_view name) { return std::make_unique<Interface>(name); }}
        , socket_factory_{[](const Interface& interface) -> std::unique_ptr<LinkSocket> {
              return std::make_unique<RawSocket>(interface);
          }}
        , dispatcher_{std::make_unique<EventLoopDispatcher>()}
        , address_monitor_{std::make_unique<DefaultAddressMonitor>(*dispatcher_)} {
    StartMonitor();
}

Application::Application(std::unique_ptr<Dispatcher> dispatcher, std::unique_ptr<AddressMonitor> monitor,
    InterfaceFactory interface_factory, SocketFactory socket_factory)
        : interface_factory_{std::move(interface_factory)}
        , socket_factory_{std::move(socket_factory)}
        , dispatcher_{std::move(dispatcher)}
        , address_monitor_{std::move(monitor)} {
    StartMonitor();
}

Application Application::ForTesting(std::unique_ptr<Dispatcher> dispatcher,
    std::unique_ptr<AddressMonitor> monitor, InterfaceFactory interface_factory,
    SocketFactory socket_factory) {
    return Application{std::move(dispatcher), std::move(monitor), std::move(interface_factory),
        std::move(socket_factory)};
}

void Application::StartMonitor() {
    // Address-change refresh is best-effort: if the monitor can't start (it logs the cause),
    // carry on without it rather than failing the daemon.
    if (!address_monitor_->Start(CreateDelegate<&Application::OnInterfaceChanged>(this))) {
        GetLogger().Warning("Address monitor unavailable; source addresses will not refresh on interface changes");
    }
}

Interface* Application::GetOrCreateInterface(const std::string& name) {
    // One Interface per name, shared by the socket and every borrower; created lazily on first
    // use via the (overridable) factory.
    auto [entry, inserted] = interfaces_.try_emplace(name);
    if (inserted) {
        entry->second = interface_factory_(name);
    }
    const auto& iface = entry->second;
    return (iface && iface->IsValid()) ? iface.get() : nullptr;
}

LinkSocket* Application::GetOrCreateSocket(const std::string& interface) {
    auto* iface = GetOrCreateInterface(interface);
    if (iface == nullptr) {
        return nullptr;
    }
    // One socket per interface, shared by every reflector that captures on or sends through
    // it; created lazily on first use via the (overridable) factory.
    auto [entry, inserted] = sockets_.try_emplace(interface);
    if (inserted) {
        entry->second = socket_factory_(*iface);
    }
    const auto& socket = entry->second;
    return (socket && socket->IsValid()) ? socket.get() : nullptr;
}

template <class ReflectorType, class ConfigType>
bool Application::ConfigureReflectors(const std::vector<ConfigType>& configs, std::string_view protocol) {
    for (const auto& config : configs) {
        auto* source_socket = GetOrCreateSocket(config.source_if);
        if (source_socket == nullptr) {
            GetLogger().Error("Cannot configure {} reflector \"{}\": socket on interface \"{}\" is invalid",
                protocol, config.name, config.source_if);
            return false;
        }
        auto* target_socket = GetOrCreateSocket(config.target_if);
        if (target_socket == nullptr) {
            GetLogger().Error("Cannot configure {} reflector \"{}\": socket on interface \"{}\" is invalid",
                protocol, config.name, config.target_if);
            return false;
        }

        auto reflector = std::make_unique<ReflectorType>(packet_dispatcher_, *source_socket, *target_socket, config);
        if (!reflector->IsValid()) {
            GetLogger().Error("Cannot configure {} reflector \"{}\": setup failed", protocol, config.name);
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
    // refresh only the changed interface.
    for (const auto& entry : interfaces_) {
        const auto& iface = entry.second;
        if (iface && (interface_index == 0 || iface->Index() == interface_index)) {
            iface->Refresh();
        }
    }

    // The fresh addresses are now visible. Let every reflector react (re-gate families, join/leave
    // groups, log transitions) — each reads live interface state and no-ops if nothing relevant to
    // it changed, so a single broadcast after the refresh is enough.
    for (const auto& reflector : reflectors_) {
        reflector->OnInterfaceChanged();
    }
}

int Application::PrepareSignalWakeup() {
    int fds[2];
    if (::pipe(fds) != 0) {
        GetLogger().Warning("Cannot create signal wakeup pipe: {}; shutdown bounded by the poll interval",
            Error::FromErrno());
        return -1;
    }
    wakeup_read_.Reset(fds[0]);
    wakeup_write_.Reset(fds[1]);

    // Non-blocking both ends: the handler's write must never block in async-signal context (a full pipe just
    // drops the byte -- one already pending suffices to wake), and OnWakeup drains to EAGAIN. No close-on-exec:
    // the daemon never execs (like every other fd here), so there is nothing to leak across an exec.
    for (const int fd : {wakeup_read_.Get(), wakeup_write_.Get()}) {
        if (!SetNonBlocking(fd)) {
            GetLogger().Warning("Cannot configure signal wakeup pipe: {}; shutdown bounded by the poll interval",
                Error::FromErrno());
            wakeup_read_.Reset();
            wakeup_write_.Reset();
            return -1;
        }
    }

    wakeup_reg_ = dispatcher_->Register(wakeup_read_.Get(), CreateDelegate<&Application::OnWakeup>(this));
    if (!wakeup_reg_.IsValid()) {
        GetLogger().Warning("Cannot register the signal wakeup pipe; shutdown bounded by the poll interval");
        wakeup_read_.Reset();
        wakeup_write_.Reset();
        return -1;
    }
    return wakeup_write_.Get();
}

void Application::OnWakeup(int fd) noexcept {
    // The wakeup byte(s) exist only to break the poll; consume them so the level-triggered read does not
    // re-fire, then let the loop's stop_requested check end the run.
    std::array<std::byte, 64> scratch{};
    while (::read(fd, scratch.data(), scratch.size()) > 0) {
    }
}

void Application::Run(const volatile std::sig_atomic_t& stop_requested) {
    // Reaching Run with nothing wired means the caller ignored a failed Configure (a valid config
    // has at least one reflector). The control flow already guarantees this; assert documents it.
    assert(!reflectors_.empty());
    dispatcher_->Run(stop_requested);
}

} // namespace reflector
