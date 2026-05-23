#pragma once

#include "dispatcher.h"
#include "logger.h"
#include "util/delegate.h"
#include "util/no_move.h"

#include <cstddef>
#include <span>
#include <vector>

namespace reflector {

// Watches the kernel for interface address changes and reports the affected interface index, so
// a long-running daemon can refresh its cached source addresses (e.g. once an IPv6 address
// finishes DAD, or on DHCP renewal). Linux uses a NETLINK_ROUTE socket subscribed to the
// IPv4/IPv6 address groups; macOS uses a PF_ROUTE socket. The monitor registers its own fd with
// the Dispatcher at construction and owns that registration, so it must be destroyed before the
// Dispatcher it was given.
class AddressMonitor : NoMove {
public:
    // Invoked with the index of an interface whose addresses changed, or 0 ("all interfaces")
    // when notifications may have been dropped (kernel buffer overflow) and everything should be
    // re-resolved. Kernel interface indices are >= 1, so 0 is an unambiguous sentinel.
    using OnInterfaceChanged = Delegate<void(unsigned interface_index)>;

    AddressMonitor(Dispatcher& dispatcher, const OnInterfaceChanged& on_change);
    ~AddressMonitor() noexcept;

    // Test seam: build a monitor around an already-open `fd` (e.g. a socketpair end) instead of the
    // kernel notification socket, registering it with `dispatcher`. The monitor owns and closes
    // `fd`. Lets tests drive OnReadable with synthesized messages and observe on_change, with no
    // real netlink/route socket.
    [[nodiscard]] static AddressMonitor ForTesting(
        Dispatcher& dispatcher, int fd, const OnInterfaceChanged& on_change);

    [[nodiscard]] bool IsValid() const noexcept { return fd_ >= 0; }

private:
    // Used by ForTesting: adopts an already-open `fd` and registers it with `dispatcher` instead of
    // opening the kernel socket. Distinguished from the production constructor by the fd parameter.
    AddressMonitor(Dispatcher& dispatcher, int fd, const OnInterfaceChanged& on_change) noexcept;

    // Opens the notification socket and registers it with `dispatcher`, leaving fd_ >= 0 and
    // registration_ valid on success. Logs the specific cause and returns false on any failure;
    // the constructor then closes the fd and logs the consequence.
    [[nodiscard]] bool Open(Dispatcher& dispatcher) noexcept;

    // Registers the already-open fd_ with `dispatcher` so its readability drives OnReadable.
    // Returns false (after logging) if registration fails.
    [[nodiscard]] bool Watch(Dispatcher& dispatcher) noexcept;

    void Close() noexcept;

    // Drains the notification socket and invokes on_change_ for each changed interface. Bound as
    // the Dispatcher fd callback at construction; the int argument (the ready fd) is unused.
    void OnReadable(int fd) noexcept;

    // Parses a buffer of kernel notification messages and appends each changed interface index to
    // `changed`, skipping any already present. Split out from OnReadable so tests can drive it with
    // synthesized messages.
    void CollectChangedInterfaces(std::span<const std::byte> messages,
        std::vector<unsigned>& changed) const noexcept;

    Logger logger_;
    OnInterfaceChanged on_change_;
    Dispatcher::Registration registration_;
    int fd_ = -1;
};

} // namespace reflector
