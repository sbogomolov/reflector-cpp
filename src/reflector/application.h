#pragma once

#include "address_monitor.h"
#include "config.h"
#include "default_packet_dispatcher.h"
#include "dispatcher.h"
#include "interface.h"
#include "link_socket.h"
#include "reflector.h"
#include "util/no_move.h"
#include "util/unique_fd.h"

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
// reflectors for a set of WoL, mDNS, and SSDP configs, then runs the dispatcher event loop. Extracting
// this out of main() keeps the entry point thin (arg parsing, config load, signal setup) and makes
// the wiring testable: ForTesting injects a fake dispatcher, address monitor, and socket factory,
// so the dedup, failure, and address-refresh paths are exercisable without CAP_NET_RAW.
class Application : NoMove {
public:
    // Creates the Interface record for a name. Production resolves a real one; tests inject a fake.
    using InterfaceFactory = std::function<std::unique_ptr<Interface>(std::string_view name)>;
    // Creates the socket capturing on `interface`. Production opens a real RawSocket; tests inject
    // a fake.
    using SocketFactory =
        std::function<std::unique_ptr<LinkSocket>(const Interface& interface)>;

    Application();

    // Test seam: inject the dispatcher, address monitor, and both factories instead of building the
    // production EventLoopDispatcher / DefaultAddressMonitor / Interface / RawSocket, so the wiring
    // runs with fakes and no real sockets.
    [[nodiscard]] static Application ForTesting(std::unique_ptr<Dispatcher> dispatcher,
        std::unique_ptr<AddressMonitor> monitor, InterfaceFactory interface_factory,
        SocketFactory socket_factory);

    // Builds one reflector per WoL, mDNS, and SSDP config, sharing a single socket across configs on the
    // same interface (the packet dispatcher watches that socket's fd once, however many reflectors
    // register on it). Transactional: returns true with everything wired, or false (after logging)
    // on the first failure, having cleared any reflectors wired before it.
    [[nodiscard]] bool Configure(const Config& config);

    void Run(const volatile std::sig_atomic_t& stop_requested);

    // Sets up a self-pipe and registers its read end with the dispatcher, returning the write fd a signal
    // handler writes one byte to in order to break the blocking poll immediately -- the loop then re-checks
    // stop_requested and exits, instead of waiting up to one poll interval. Also robust to a SA_RESTART
    // handler (signal()'s default on Linux) that would otherwise restart the poll rather than surface EINTR.
    // Best-effort: returns -1 (after logging a warning) if the pipe or its registration cannot be set up,
    // leaving shutdown bounded by the poll interval. Call once, after Configure, before Run. Production
    // wiring only -- the other tests never call it, so their dispatcher-registration counts are unperturbed.
    [[nodiscard]] int PrepareSignalWakeup();

private:
    friend class ApplicationTest;

    // The injecting constructor ForTesting uses. The production Application() can't delegate to it
    // (the address monitor must be built from the dispatcher), so it sets these members in its own
    // init list; both constructors then call StartMonitor().
    Application(std::unique_ptr<Dispatcher> dispatcher, std::unique_ptr<AddressMonitor> monitor,
        InterfaceFactory interface_factory, SocketFactory socket_factory);

    // Starts the address monitor, routing changes to OnInterfaceChanged. Logs a warning and
    // continues if it can't start — address refresh is best-effort, not required to run.
    void StartMonitor();

    // Wires every entry in `configs` into a reflector of type R, sharing one socket per interface
    // across all reflectors (see GetOrCreateSocket). WolReflector, MdnsReflector, and SsdpReflector
    // share the ctor shape (dispatcher, source, target, config) and the IsValid contract, so one
    // template covers them all; `protocol` only labels the error logs. Returns false on the first failure (already
    // logged); reflectors wired so far stay in reflectors_ for Configure to roll back.
    template <class ReflectorType, class ConfigType>
    bool ConfigureReflectors(const std::vector<ConfigType>& configs, std::string_view protocol);

    [[nodiscard]] size_t SocketCount() const noexcept { return sockets_.size(); }
    [[nodiscard]] size_t ReflectorCount() const noexcept { return reflectors_.size(); }

    // Returns the Interface for `name`, creating it via the factory on first use and sharing it
    // across sockets and reflectors. Null when the interface is invalid (over-long or unknown
    // name); failures are cached like GetOrCreateSocket's.
    [[nodiscard]] Interface* GetOrCreateInterface(const std::string& name);

    // Returns the socket for `interface`, creating it via the factory on first use and sharing
    // it across reflectors. Null (after no logging) when the interface or the socket is invalid;
    // the caller logs with the interface's role (source vs target).
    [[nodiscard]] LinkSocket* GetOrCreateSocket(const std::string& interface);

    // Address-monitor callback: re-resolve the source addresses of the changed interface, or of
    // every interface when index == 0 (the monitor's overflow signal).
    void OnInterfaceChanged(unsigned interface_index) noexcept;

    // Drains the signal-wakeup self-pipe set up by PrepareSignalWakeup. The byte exists only to wake the
    // poll; the loop's stop_requested check ends the run. Level-triggered, so drain fully.
    void OnWakeup(int fd) noexcept;

    InterfaceFactory interface_factory_;
    SocketFactory socket_factory_;

    // Declaration order is teardown order in reverse. Interfaces precede the packet pipeline:
    // sockets, reflectors, and the DIAL proxy borrow references into them, so they are destroyed
    // after everything else. Within the packet pipeline: reflectors drop their packet-dispatcher
    // registrations first, the packet dispatcher then drops its per-socket dispatcher
    // registrations, the dispatcher tears down its event queue, and only then the sockets close
    // their fds. The packet dispatcher caches a raw pointer to each socket (and each socket a
    // reference to its interface), so both maps hold unique_ptr to keep addresses stable across
    // rehashing.
    std::unordered_map<std::string, std::unique_ptr<Interface>> interfaces_;
    std::unordered_map<std::string, std::unique_ptr<LinkSocket>> sockets_;
    std::unique_ptr<Dispatcher> dispatcher_;
    DefaultPacketDispatcher packet_dispatcher_{*dispatcher_};
    std::vector<std::unique_ptr<Reflector>> reflectors_;
    std::unique_ptr<AddressMonitor> address_monitor_;

    // Signal-wakeup self-pipe (best-effort; populated by PrepareSignalWakeup, otherwise empty). Declared
    // last so it tears down first: wakeup_reg_ unregisters from dispatcher_ while it is still alive, then
    // the pipe fds close. wakeup_reg_ holds a callback bound to `this`, so it must outlive nothing here.
    UniqueFd wakeup_write_;
    UniqueFd wakeup_read_;
    Dispatcher::Registration wakeup_reg_;
};

} // namespace reflector
