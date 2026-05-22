#pragma once

#include "config.h"
#include "dispatcher.h"
#include "logger.h"
#include "packet_dispatcher.h"
#include "raw_socket.h"
#include "util/no_move.h"
#include "wol_listener.h"
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

// Owns and wires together the capture sockets, dispatcher, listeners and reflectors for a
// set of WolConfigs, then runs the dispatcher event loop. Extracting this out of main()
// keeps the entry point thin (arg parsing, config load, signal setup) and makes the wiring
// testable: the capture-socket factory can be overridden to inject sockets wrapping fake
// fds, so the dedup and failure paths are exercisable without CAP_NET_RAW.
class Application : NoMove {
public:
    // Creates the capture socket for an interface. Production opens a real
    // RawSocket; tests inject one wrapping a fake fd.
    using CaptureSocketFactory =
        std::function<std::unique_ptr<RawSocket>(std::string_view interface)>;

    // TODO: when mDNS/SSDP reflectors land, give Application a sender factory too, mirroring
    // the capture-socket factory — Application would build the sender (as it builds the
    // capture socket) and forward it into the reflector, replacing WolReflector's test-only
    // sender-injecting constructor. That makes the whole composition root unit-testable
    // without root (loopback senders need no SO_BINDTODEVICE) and unifies the injection seam.
    // Likely pairs with consolidating the broadcast (UdpLinkFanoutSender) and multicast
    // senders behind one sender abstraction.

    Application();
    explicit Application(CaptureSocketFactory capture_socket_factory);

    // Builds one reflector per WolConfig, sharing a single capture socket and listener
    // across configs on the same source interface. Returns false (after logging) on the
    // first failure; the partially-wired state is then torn down by the destructor.
    [[nodiscard]] bool Configure(const Config& config);

    void Run(const volatile std::sig_atomic_t& stop_requested);

private:
    friend class ApplicationTest;

    [[nodiscard]] size_t CaptureSocketCount() const noexcept { return capture_sockets_.size(); }
    [[nodiscard]] size_t ListenerCount() const noexcept { return wol_listeners_.size(); }
    [[nodiscard]] size_t ReflectorCount() const noexcept { return reflectors_.size(); }

    CaptureSocketFactory capture_socket_factory_;
    Logger logger_;

    // Declaration order is the teardown order in reverse: reflectors drop their listener
    // registrations first, listeners then drop their packet-dispatcher registrations, the
    // packet dispatcher drops its per-socket dispatcher registrations, the dispatcher tears
    // down its event queue, and only then the capture sockets close their fds. The packet
    // dispatcher caches each RawSocket*, so the sockets live behind unique_ptr to keep their
    // addresses stable across map rehashing.
    std::unordered_map<std::string, std::unique_ptr<RawSocket>> capture_sockets_;
    Dispatcher dispatcher_;
    PacketDispatcher packet_dispatcher_{dispatcher_};
    std::unordered_map<std::string, WolListener> wol_listeners_;
    std::vector<std::unique_ptr<WolReflector>> reflectors_;
};

} // namespace reflector
