#include "application.h"

#include "default_address_monitor.h"
#include "error.h"
#include "event_loop_dispatcher.h"
#include "logger.h"
#include "mdns_reflector.h"
#include "memory_report.h"
#include "raw_socket.h"
#include "ssdp_reflector.h"
#include "util/delegate.h"
#include "util/fd_util.h"
#include "wol_reflector.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
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
// How often the memory diagnostic logs once debug_memory is enabled.
constexpr std::chrono::seconds MEMORY_REPORT_INTERVAL{60};
// The reconcile backstop. Every other trigger depends on the kernel telling us something, and a
// notification can be dropped without the kernel saying so, so this is the one channel that always
// arrives. It rides the wakeup the poll already makes, costing only one attachment probe per
// capture when nothing is wrong.
constexpr std::chrono::seconds RECONCILE_BACKSTOP_INTERVAL{30};
// The retry cadence while a repair is outstanding. A rebind that failed on a transient error has
// no announcement coming, so nothing but this would ever finish it.
constexpr std::chrono::seconds REPAIR_RETRY_INTERVAL{1};
} // namespace

namespace reflector {

Application::Application()
        : interface_factory_{[](std::string_view name) { return std::make_unique<Interface>(name); }}
        , socket_factory_{[](const Interface& interface) -> std::unique_ptr<LinkSocket> {
              return std::make_unique<RawSocket>(interface);
          }}
        , dispatcher_{std::make_unique<EventLoopDispatcher>()}
        , address_monitor_{std::make_unique<DefaultAddressMonitor>(*dispatcher_)} {
    packet_dispatcher_.OnCaptureFailure(CreateDelegate<&Application::OnCaptureFailure>(this));
    StartMonitor();
}

Application::Application(std::unique_ptr<Dispatcher> dispatcher, std::unique_ptr<AddressMonitor> monitor,
    InterfaceFactory interface_factory, SocketFactory socket_factory)
        : interface_factory_{std::move(interface_factory)}
        , socket_factory_{std::move(socket_factory)}
        , dispatcher_{std::move(dispatcher)}
        , address_monitor_{std::move(monitor)} {
    packet_dispatcher_.OnCaptureFailure(CreateDelegate<&Application::OnCaptureFailure>(this));
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
    if (!address_monitor_->Start(CreateDelegate<&Application::OnInterfacesChanged>(this))) {
        GetLogger().Warn("Address monitor unavailable; source addresses will not refresh on interface changes");
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
        reconcile_timer_.Start(
            RECONCILE_BACKSTOP_INTERVAL, CreateDelegate<&Application::OnReconcileTick>(this));
        if (config.DebugMemory()) {
            GetLogger().Info("Memory diagnostics enabled; reporting RSS/heap every {}s",
                MEMORY_REPORT_INTERVAL.count());
            LogMemoryReport();  // a baseline at startup, then every interval via the timer
            memory_timer_.emplace(*dispatcher_);
            memory_timer_->Start(MEMORY_REPORT_INTERVAL, CreateDelegate<&Application::ReportMemory>(this));
        }
        return true;
    }
    // Fail closed: drop any reflectors wired before the failure so a config error never leaves a
    // partially-wired Application. Pairs with Run's assert(!reflectors_.empty()).
    reflectors_.clear();
    return false;
}

void Application::OnInterfacesChanged(std::span<const unsigned> indexes, bool refresh_all) noexcept {
    ArmRepairRetry(ReconcileInterfaces(indexes, refresh_all));
    NotifyReflectors();
}

void Application::OnReconcileTick(std::chrono::steady_clock::time_point) noexcept {
    ArmRepairRetry(ReconcileInterfaces({}, false));
    NotifyReflectors();
}

bool Application::ReconcileInterfaces(std::span<const unsigned> indexes, bool refresh_all) noexcept {
    bool outstanding = false;
    for (const auto& [name, iface] : interfaces_) {
        // Configure fails unless every configured interface resolved and opened a valid socket, so
        // a daemon that reached the event loop holds one for each interface.
        const auto entry = sockets_.find(name);
        assert(entry != sockets_.end());
        LinkSocket& socket = *entry->second;

        // Both read before Reidentify, which is what moves the index out from under them.
        const bool refresh_requested =
            refresh_all || std::ranges::find(indexes, iface->Index()) != indexes.end();
        // Probe before resolving: getsockname is one syscall where a name lookup is three (glibc
        // opens a socket inside if_nametoindex), and a capture the kernel still has attached
        // proves its interface has not gone anywhere. A rename is the exception — it keeps both
        // the index and the capture, so only the name lookup sees it — but it also announces
        // itself, which is why a requested interface resolves regardless.
        const bool attached = socket.Attached();
        const bool capturing = attached && socket.GroupsJoined();
        if (capturing && !refresh_requested) {
            continue;
        }

        const auto change = iface->Reidentify();
        if (change == Interface::IdentityChange::Unresolved) {
            outstanding = true;  // says nothing about the interface, so act on nothing
            continue;
        }
        if (change == Interface::IdentityChange::Unchanged && refresh_requested) {
            iface->Refresh();  // Reidentify already refreshed the other cases
        }

        // Only a detached capture or a moved index means the kernel object itself was replaced;
        // memberships gone from an attached capture is a failed re-join on a live one, and
        // evicting state over that would be wrong. A counter rather than a call, so the write
        // carries none of the ordering the post-loop broadcast has to respect.
        if (!attached || change == Interface::IdentityChange::Repointed) {
            iface->MarkReplaced();
        }

        // A capture is bound to a kernel object, not to a name, so it does not follow the
        // interface across a recreation. Two ways it shows: the index moved, or it did not and the
        // capture is detached anyway, which is what happens where the kernel hands a recreated
        // interface the number it had.
        if (!iface->IsValid()) {
            continue;  // parked, so there is nothing to bind to until it comes back
        }
        if ((!capturing || change == Interface::IdentityChange::Repointed) && !socket.Rebind()) {
            outstanding = true;  // Rebind logs its own failure
        }
    }
    return outstanding;
}

void Application::OnCaptureFailure() noexcept {
    // Repair on the retry cadence rather than inline: this runs inside a drain, and the reconcile
    // rebinds sockets and broadcasts to reflectors, which is not work to do underneath one.
    ArmRepairRetry(true);
}

void Application::ArmRepairRetry(bool outstanding) noexcept {
    if (!outstanding) {
        repair_timer_.Stop();
        return;
    }
    // Re-registering re-anchors the deadline to now, so restarting an already-running retry on
    // every failed pass would let a stream of address events push it back indefinitely.
    if (!repair_timer_.IsRunning()) {
        repair_timer_.Start(REPAIR_RETRY_INTERVAL, CreateDelegate<&Application::OnReconcileTick>(this));
    }
}

void Application::NotifyReflectors() noexcept {
    // Each reads live interface state and no-ops if nothing relevant to it changed, so one
    // broadcast after the reconcile is enough.
    for (const auto& reflector : reflectors_) {
        reflector->OnInterfaceChanged();
    }
}

int Application::PrepareSignalWakeup() {
    int fds[2];
    if (::pipe(fds) != 0) {
        GetLogger().Warn("Cannot create signal wakeup pipe: {}; shutdown bounded by the poll interval",
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
            GetLogger().Warn("Cannot configure signal wakeup pipe: {}; shutdown bounded by the poll interval",
                Error::FromErrno());
            wakeup_read_.Reset();
            wakeup_write_.Reset();
            return -1;
        }
    }

    wakeup_reg_ = dispatcher_->Register(wakeup_read_.Get(), CreateDelegate<&Application::OnWakeup>(this));
    if (!wakeup_reg_.IsValid()) {
        GetLogger().Warn("Cannot register the signal wakeup pipe; shutdown bounded by the poll interval");
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

void Application::ReportMemory(std::chrono::steady_clock::time_point) noexcept {
    LogMemoryReport();
}

void Application::Run(const volatile std::sig_atomic_t& stop_requested) {
    // Reaching Run with nothing wired means the caller ignored a failed Configure (a valid config
    // has at least one reflector). The control flow already guarantees this; assert documents it.
    assert(!reflectors_.empty());
    dispatcher_->Run(stop_requested);
}

} // namespace reflector
