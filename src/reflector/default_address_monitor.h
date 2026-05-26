#pragma once

#include "address_monitor.h"
#include "dispatcher.h"
#include "logger.h"
#include "util/no_move.h"

#include <cstddef>
#include <span>
#include <vector>

namespace reflector {

// Production AddressMonitor. Linux uses a NETLINK_ROUTE socket subscribed to the IPv4/IPv6 address
// groups; macOS uses a PF_ROUTE socket. The notification socket is opened at construction; the fd
// is registered with the Dispatcher in Start(). The monitor owns that registration, so it must be
// destroyed before the Dispatcher it was given.
class DefaultAddressMonitor : public AddressMonitor, NoMove {
public:
    explicit DefaultAddressMonitor(Dispatcher& dispatcher);
    ~DefaultAddressMonitor() noexcept override;

    // Test seam: build a monitor around an already-open `fd` (e.g. a socketpair end) instead of the
    // kernel notification socket. The monitor owns and closes `fd`. Like the production path, it
    // does not watch until Start() is called, so tests can drive OnReadable with synthesized
    // messages and observe on_change with no real netlink/route socket.
    [[nodiscard]] static DefaultAddressMonitor ForTesting(Dispatcher& dispatcher, int fd);

    [[nodiscard]] bool Start(const OnInterfaceChanged& on_change) noexcept override;

    [[nodiscard]] bool IsValid() const noexcept { return fd_ >= 0; }

private:
    // Used by ForTesting: adopts an already-open `fd` instead of opening the kernel socket.
    // Distinguished from the production constructor by the fd parameter. Watching begins at Start().
    DefaultAddressMonitor(Dispatcher& dispatcher, int fd) noexcept;

    // Opens the notification socket into fd_, leaving fd_ >= 0 on success. Logs the specific cause
    // and returns false on any failure; the caller then closes the fd.
    [[nodiscard]] bool Open() noexcept;

    // Registers the already-open fd_ with the dispatcher so its readability drives OnReadable.
    // Returns false (after logging) if registration fails.
    [[nodiscard]] bool Watch() noexcept;

    void Close() noexcept;

    // Drains the notification socket and invokes on_change_ for each changed interface. Bound as
    // the Dispatcher fd callback by Watch(); the int argument (the ready fd) is unused.
    void OnReadable(int fd) noexcept;

    // Parses a buffer of kernel notification messages and appends each changed interface index to
    // `changed`, skipping any already present. Split out from OnReadable so tests can drive it with
    // synthesized messages.
    void CollectChangedInterfaces(std::span<const std::byte> messages,
        std::vector<unsigned>& changed) const noexcept;

    Logger logger_;
    Dispatcher* dispatcher_;
    // Invalid (default-constructed) until Start() or the testing constructor binds it. Always
    // valid by the time the fd is watched, so OnReadable can call it.
    OnInterfaceChanged on_change_;
    Dispatcher::Registration registration_;
    int fd_ = -1;
};

} // namespace reflector
