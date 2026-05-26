#pragma once

#include "config.h"
#include "default_address_monitor.h"
#include "event_loop_dispatcher.h"
#include "logger.h"
#include "default_packet_dispatcher.h"
#include "raw_socket.h"
#include "util/delegate.h"
#include "util/no_move.h"
#include "wol_reflector.h"

#include <csignal>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace reflector {

// Owns and wires together the sockets, the dispatcher and packet dispatcher, and the
// reflectors for a set of WolConfigs, then runs the dispatcher event loop. Extracting this out
// of main() keeps the entry point thin (arg parsing, config load, signal setup) and makes the
// wiring testable: the socket factory can be overridden to inject sockets wrapping fake
// fds, so the dedup and failure paths are exercisable without CAP_NET_RAW.
class Application : NoMove {
public:
    // Creates the socket for an interface. Production opens a real
    // RawSocket; tests inject one wrapping a fake fd.
    using SocketFactory =
        std::function<std::unique_ptr<RawSocket>(std::string_view interface)>;

    Application();
    explicit Application(SocketFactory socket_factory);

    // Builds one reflector per WolConfig, sharing a single socket across configs on
    // the same source interface (the packet dispatcher watches that socket's fd once, however
    // many reflectors register on it). Returns false (after logging) on the first failure; the
    // partially-wired state is then torn down by the destructor.
    [[nodiscard]] bool Configure(const Config& config);

    void Run(const volatile std::sig_atomic_t& stop_requested);

private:
    friend class ApplicationTest;

    [[nodiscard]] size_t SocketCount() const noexcept { return sockets_.size(); }
    [[nodiscard]] size_t ReflectorCount() const noexcept { return reflectors_.size(); }

    // Returns the socket for `interface`, creating it via the factory on first use and sharing
    // it across reflectors. Null (after no logging) when the socket is missing or its fd is
    // invalid; the caller logs with the interface's role (source vs target).
    [[nodiscard]] RawSocket* GetOrCreateSocket(const std::string& interface);

    // Address-monitor callback: re-resolve the source addresses of the socket bound to the
    // changed interface, or every socket when index == 0 (the monitor's overflow signal).
    void OnInterfaceChanged(unsigned interface_index) noexcept;

    SocketFactory socket_factory_;
    Logger logger_;

    // Declaration order is teardown order in reverse. Within the packet pipeline: reflectors drop
    // their packet-dispatcher registrations first, the packet dispatcher then drops its per-socket
    // dispatcher registrations, the dispatcher tears down its event queue, and only then the
    // sockets close their fds. The packet dispatcher caches a raw pointer to each socket, so the
    // sockets live behind unique_ptr to keep their addresses stable across map rehashing.
    std::unordered_map<std::string, std::unique_ptr<RawSocket>> sockets_;
    EventLoopDispatcher dispatcher_;
    DefaultPacketDispatcher packet_dispatcher_{dispatcher_};
    std::vector<std::unique_ptr<WolReflector>> reflectors_;
    AddressMonitor address_monitor_{dispatcher_, CreateDelegate<&Application::OnInterfaceChanged>(this)};
};

} // namespace reflector
