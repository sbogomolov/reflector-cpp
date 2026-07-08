#pragma once

#include "address_monitor.h"
#include "dispatcher.h"
#include "util/no_move.h"
#include "util/unique_fd.h"

#include <cstddef>
#include <span>
#include <vector>
#include <sys/socket.h>

namespace reflector {

namespace detail {

// Whether a notification's source address (as recvfrom reports it) is the kernel's. On Linux the
// kernel's netlink source has nl_pid == 0; a user process's carries its own port id, so a non-zero
// pid — or a source too short to be a sockaddr_nl — is a locally-spoofed datagram (netlink
// user-to-user unicast needs no privilege) and is rejected. On the BSDs the route socket carries no
// per-message sender identity, so every datagram is the kernel's and this is always true. Exposed
// for testing. Prefer verifying in the monitor over trusting the socket's group binding.
[[nodiscard]] bool NetlinkSenderIsKernel(sockaddr_storage src, socklen_t len) noexcept;

} // namespace detail

// Production AddressMonitor. Linux uses a NETLINK_ROUTE socket subscribed to the IPv4/IPv6 address
// groups and the link group (a MAC change is a link event, not an address one); macOS uses a
// PF_ROUTE socket. The notification socket is opened at construction; the fd is registered with
// the Dispatcher in Start(). The monitor owns that registration, so it must be destroyed before
// the Dispatcher it was given.
class DefaultAddressMonitor : public AddressMonitor, NoMove {
public:
    explicit DefaultAddressMonitor(Dispatcher& dispatcher);
    ~DefaultAddressMonitor() noexcept override;

    // Test seam: build a monitor around an already-open `fd` (e.g. a socketpair end) instead of the
    // kernel notification socket. The monitor owns and closes `fd`. Like the production path, it
    // does not watch until Start() is called, so tests can drive OnReadable with synthesized
    // messages and observe on_change with no real netlink/route socket. Sender verification is off
    // by default: a socketpair source is not a netlink kernel address, so an on-check monitor would
    // drop every synthesized datagram; pass `verify_sender=true` to exercise that drop path.
    [[nodiscard]] static DefaultAddressMonitor ForTesting(Dispatcher& dispatcher, int fd,
        bool verify_sender = false);

    [[nodiscard]] bool Start(const OnInterfaceChanged& on_change) noexcept override;

    [[nodiscard]] bool IsValid() const noexcept { return fd_.IsValid(); }

private:
    // Used by ForTesting: adopts an already-open `fd` instead of opening the kernel socket.
    // Watching begins at Start().
    DefaultAddressMonitor(Dispatcher& dispatcher, int fd, bool verify_sender) noexcept;

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

    Dispatcher* dispatcher_;
    // Invalid (default-constructed) until Start() binds it (the testing constructor leaves it
    // unbound, so tests must call Start() too). Always valid by the time the fd is watched —
    // Watch() runs only inside Start(), after the bind — so OnReadable can call it.
    OnInterfaceChanged on_change_;
    Dispatcher::Registration registration_;
    UniqueFd fd_;
    // Whether OnReadable rejects datagrams whose source isn't the kernel (production always does;
    // the testing seam defaults it off since a socketpair can't carry a netlink kernel source).
    bool verify_sender_ = true;
};

} // namespace reflector
