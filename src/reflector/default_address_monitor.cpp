#include "default_address_monitor.h"

#include "error.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(__APPLE__) && !defined(__linux__)
#error "AddressMonitor only supports macOS and Linux"
#endif

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#endif

namespace reflector {

namespace {

// A single address notification is small and bounded — an ifaddrmsg / ifa_msghdr plus a few short
// attributes — with none of the large per-interface blocks that force the RTM_GETLINK dump to grow
// its buffer. The kernel delivers each notification as its own datagram, so 4 KB comfortably holds
// one and the receive buffer never has to grow.
constexpr size_t NOTIFICATION_BUFFER_SIZE = 4 * 1024;

void AddUnique(std::vector<unsigned>& indices, unsigned index) {
    if (std::ranges::find(indices, index) == indices.end()) {
        indices.push_back(index);
    }
}

} // namespace

DefaultAddressMonitor::DefaultAddressMonitor(Dispatcher& dispatcher)
        : logger_{"AddressMonitor"}, dispatcher_{&dispatcher} {
    if (!Open()) {
        Close();
    }
}

DefaultAddressMonitor::DefaultAddressMonitor(Dispatcher& dispatcher, int fd) noexcept
        : logger_{"AddressMonitor"}, dispatcher_{&dispatcher}, fd_{fd} {}

DefaultAddressMonitor DefaultAddressMonitor::ForTesting(Dispatcher& dispatcher, int fd) {
    return DefaultAddressMonitor{dispatcher, fd};
}

bool DefaultAddressMonitor::Start(const OnInterfaceChanged& on_change) noexcept {
    if (!on_change.IsValid()) {
        logger_.Error("Cannot start address monitor: the change callback is not bound");
        Close();
        return false;
    }
    on_change_ = on_change;
    if (fd_ < 0 || !Watch()) {
        // Open() (at construction) or Watch() has already logged the specific cause; whether to
        // proceed without address refresh is the caller's policy, not ours.
        Close();
        return false;
    }
    return true;
}

bool DefaultAddressMonitor::Open() noexcept {
#if defined(__linux__)
    fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd_ < 0) {
        logger_.Error("Cannot open netlink socket: {}", Error::FromErrno());
        return false;
    }

    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        logger_.Error("Cannot subscribe to netlink address groups: {}", Error::FromErrno());
        return false;
    }
#elif defined(__APPLE__)
    fd_ = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd_ < 0) {
        logger_.Error("Cannot open route socket: {}", Error::FromErrno());
        return false;
    }
    if (fcntl(fd_, F_SETFL, O_NONBLOCK) != 0) {
        logger_.Error("Cannot set route socket non-blocking: {}", Error::FromErrno());
        return false;
    }
#endif

    return true;
}

bool DefaultAddressMonitor::Watch() noexcept {
    registration_ = dispatcher_->Register(fd_, CreateDelegate<&DefaultAddressMonitor::OnReadable>(this));
    if (!registration_.IsValid()) {
        logger_.Error("Cannot register the address-notification socket with the dispatcher");
        return false;
    }
    logger_.Debug("Watching for interface address changes on fd {}", fd_);
    return true;
}

DefaultAddressMonitor::~DefaultAddressMonitor() noexcept {
    registration_.Reset();  // unregister while fd_ is still open, before Close() invalidates it
    Close();
}

void DefaultAddressMonitor::Close() noexcept {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

void DefaultAddressMonitor::OnReadable(int /*fd*/) noexcept {
    // Left uninitialized on purpose: recv fills it and we only ever read the bytes it reports.
    // The Linux parser casts buffer.data() to nlmsghdr*, so align for that; the macOS parser
    // reads via memcpy and needs no particular alignment.
#if defined(__linux__)
    alignas(nlmsghdr)
#endif
    std::array<std::byte, NOTIFICATION_BUFFER_SIZE> buffer;

    // Coalesce a whole drain into one callback per interface: a burst commonly repeats the same
    // index, and on overflow we drop the partial list and emit a single refresh-all instead.
    std::vector<unsigned> changed;
    bool overflowed = false;
    for (;;) {
        const auto received = recv(fd_, buffer.data(), buffer.size(), 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (IsWouldBlockErrno(errno)) {
                break;  // drained
            }
#if defined(__linux__)
            if (errno == ENOBUFS) {
                overflowed = true;  // kernel dropped notifications; emit one refresh-all below
                continue;
            }
#endif
            logger_.Error("Cannot read address notifications: {}", Error::FromErrno());
            break;
        }
        if (received == 0) {
            break;
        }
        // Once overflowed we'll emit a single refresh-all, so keep draining the socket but stop
        // parsing — the collected list would only be discarded.
        if (!overflowed) {
            CollectChangedInterfaces(
                std::span<const std::byte>{buffer.data(), static_cast<size_t>(received)}, changed);
        }
    }

    if (overflowed) {
        logger_.Warning("Address notifications overflowed; refreshing all interfaces");
        on_change_(0u);
    } else {
        for (const unsigned index : changed) {
            on_change_(index);
        }
    }
}

#if defined(__linux__)

// The kernel netlink macros (NLMSG_OK, NLMSG_NEXT, NLMSG_DATA) use C-style casts and byte-wise
// pointer arithmetic that the project's strict warning set rejects; the access is sound (OnReadable
// aligns the buffer for nlmsghdr and messages are NLMSG_ALIGN padded). Scope the suppression to the
// parser.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"

void DefaultAddressMonitor::CollectChangedInterfaces(std::span<const std::byte> messages,
        std::vector<unsigned>& changed) const noexcept {
    const auto* header = reinterpret_cast<const nlmsghdr*>(messages.data());
    for (int length = static_cast<int>(messages.size()); NLMSG_OK(header, length);
            header = NLMSG_NEXT(header, length)) {
        if (header->nlmsg_type == RTM_NEWADDR || header->nlmsg_type == RTM_DELADDR) {
            const auto* address = static_cast<const ifaddrmsg*>(NLMSG_DATA(header));
            AddUnique(changed, address->ifa_index);
        }
    }
}

#pragma GCC diagnostic pop

#elif defined(__APPLE__)

void DefaultAddressMonitor::CollectChangedInterfaces(std::span<const std::byte> messages,
        std::vector<unsigned>& changed) const noexcept {
    // PF_ROUTE messages pack back-to-back; each begins with rt_msghdr's prefix (u_short msglen;
    // u_char version; u_char type). Read the fields with memcpy — the buffer carries no
    // alignment guarantee and the messages aren't a single struct type.
    size_t offset = 0;
    while (offset + offsetof(rt_msghdr, rtm_type) + sizeof(u_char) <= messages.size()) {
        u_short message_length = 0;
        std::memcpy(&message_length, messages.data() + offset + offsetof(rt_msghdr, rtm_msglen),
            sizeof(message_length));
        if (message_length == 0 || offset + message_length > messages.size()) {
            break;  // truncated or malformed
        }

        const auto type = std::to_integer<u_char>(messages[offset + offsetof(rt_msghdr, rtm_type)]);
        constexpr size_t index_end = offsetof(ifa_msghdr, ifam_index) + sizeof(u_short);
        if ((type == RTM_NEWADDR || type == RTM_DELADDR) && message_length >= index_end) {
            u_short index = 0;
            std::memcpy(&index, messages.data() + offset + offsetof(ifa_msghdr, ifam_index), sizeof(index));
            AddUnique(changed, index);
        }
        offset += message_length;
    }
}

#endif

} // namespace reflector
