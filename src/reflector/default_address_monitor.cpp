#include "default_address_monitor.h"

#include "error.h"
#include "logger.h"
#include "platform.h"
#include "util/fd_util.h"
#include "util/narrow_cast.h"
#include "util/start_lifetime_as.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else
#include <net/if.h>
#include <net/route.h>
#endif

namespace {

using namespace reflector;

Logger& GetLogger() noexcept {
    static Logger logger{"AddressMonitor"};
    return logger;
}

// The kernel delivers each notification as its own datagram, never a coalesced dump. Sized for
// the largest: an RTM_NEWLINK carries the interface's whole attribute set (stats, IFLA_AF_SPEC,
// VF info) at ~1 KB; address notifications are far smaller. 8 KB is roomy either way.
constexpr size_t NOTIFICATION_BUFFER_SIZE = 8 * 1024;

#if !defined(__linux__)
// The BSD route socket's receive queue defaults to only ~8 KiB, so a burst of routing messages can
// overflow it and drop changes. Request a far larger SO_RCVBUF (kernel-clamped, best-effort). Linux
// netlink already defaults to the system max, so it isn't grown.
constexpr int ROUTE_RECEIVE_BUFFER_BYTES = 256 * 1024;
#endif

void AddUnique(std::vector<unsigned>& indices, unsigned index) {
    if (index == 0) {
        return;  // names no interface (kernel indices are >= 1) — and 0 is the refresh-all sentinel
    }
    if (std::ranges::find(indices, index) == indices.end()) {
        indices.push_back(index);
    }
}

} // namespace

namespace reflector {

namespace detail {

#if defined(__linux__)
bool NetlinkSenderIsKernel(sockaddr_storage src, socklen_t len) noexcept {
    if (len < narrow_cast<socklen_t>(sizeof(sockaddr_nl))) {
        return false;  // too short to carry a netlink source address
    }
    // The kernel filled `src`'s bytes; bless them as the sockaddr_nl they represent (by value, since
    // start_lifetime_as reuses the storage) rather than read a never-created object via a cast.
    return start_lifetime_as<sockaddr_nl>(&src)->nl_pid == 0;
}
#else
bool NetlinkSenderIsKernel(sockaddr_storage /*src*/, socklen_t /*len*/) noexcept {
    return true;  // PF_ROUTE messages carry no per-message sender identity; all are the kernel's
}
#endif

} // namespace detail

DefaultAddressMonitor::DefaultAddressMonitor(Dispatcher& dispatcher)
        : dispatcher_{&dispatcher} {
    if (!Open()) {
        Close();
    }
}

DefaultAddressMonitor::DefaultAddressMonitor(Dispatcher& dispatcher, int fd, bool verify_sender) noexcept
        : dispatcher_{&dispatcher}, fd_{fd}, verify_sender_{verify_sender} {}

DefaultAddressMonitor DefaultAddressMonitor::ForTesting(Dispatcher& dispatcher, int fd, bool verify_sender) {
    return DefaultAddressMonitor{dispatcher, fd, verify_sender};
}

bool DefaultAddressMonitor::Start(const OnInterfaceChanged& on_change) noexcept {
    if (!on_change.IsValid()) {
        GetLogger().Error("Cannot start address monitor: the change callback is not bound");
        Close();
        return false;
    }
    on_change_ = on_change;
    if (!fd_ || !Watch()) {
        // Open() (at construction) or Watch() has already logged the specific cause; whether to
        // proceed without address refresh is the caller's policy, not ours.
        Close();
        return false;
    }
    return true;
}

bool DefaultAddressMonitor::Open() noexcept {
#if defined(__linux__)
    fd_.Reset(socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE));
    if (!fd_) {
        GetLogger().Error("Cannot open netlink socket: {}", Error::FromErrno());
        return false;
    }

    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;
    if (bind(fd_.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        GetLogger().Error("Cannot subscribe to netlink notification groups: {}", Error::FromErrno());
        return false;
    }
#else
    fd_.Reset(socket(PF_ROUTE, SOCK_RAW, 0));
    if (!fd_) {
        GetLogger().Error("Cannot open route socket: {}", Error::FromErrno());
        return false;
    }
    if (!SetNonBlocking(fd_.Get())) {
        GetLogger().Error("Cannot set route socket non-blocking: {}", Error::FromErrno());
        return false;
    }
    // Best-effort: a bigger receive queue so a routing-message burst is less likely to overflow it.
    // Kernel-clamped, and the default still works, so a failure only warns — it doesn't fail Open.
    if (setsockopt(fd_.Get(), SOL_SOCKET, SO_RCVBUF,
            &ROUTE_RECEIVE_BUFFER_BYTES, sizeof(ROUTE_RECEIVE_BUFFER_BYTES)) != 0) {
        GetLogger().Warning("Cannot enlarge the route socket receive buffer: {}", Error::FromErrno());
    }
#if defined(__FreeBSD__)
    // Without SO_RERROR (FreeBSD 13+) a receive-buffer overflow is dropped silently, so the ENOBUFS
    // refresh-all recovery in OnReadable never fires and address changes are lost under pressure.
    // Enabling it surfaces the overflow as ENOBUFS on the next recv. macOS has no equivalent.
    const int rerror = 1;
    if (setsockopt(fd_.Get(), SOL_SOCKET, SO_RERROR, &rerror, sizeof(rerror)) != 0) {
        GetLogger().Error("Cannot enable SO_RERROR on the route socket: {}", Error::FromErrno());
        return false;
    }
#endif
#endif

    return true;
}

bool DefaultAddressMonitor::Watch() noexcept {
    registration_ = dispatcher_->Register(fd_.Get(), CreateDelegate<&DefaultAddressMonitor::OnReadable>(this));
    if (!registration_.IsValid()) {
        GetLogger().Error("Cannot register the address-notification socket with the dispatcher");
        return false;
    }
    GetLogger().Debug("Watching for interface address changes on fd {}", fd_.Get());
    return true;
}

DefaultAddressMonitor::~DefaultAddressMonitor() noexcept {
    registration_.Reset();  // unregister while fd_ is still open, before Close() invalidates it
    Close();
}

void DefaultAddressMonitor::Close() noexcept {
    fd_.Reset();
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
    while (true) {
        sockaddr_storage src{};
        socklen_t addrlen = sizeof(src);
        const auto received = recvfrom(fd_.Get(), buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&src), &addrlen);
        if (received < 0) {
            if (IsWouldBlockErrno(errno)) {
                break;  // drained
            }
            if (errno == ENOBUFS) {
                // The kernel dropped notifications on a receive-queue overflow: emit one refresh-all
                // below. Linux netlink reports this natively; the FreeBSD route socket does once
                // SO_RERROR is enabled (see Open). Refreshing all is always safe, just occasionally
                // redundant, so treat ENOBUFS uniformly rather than per platform.
                overflowed = true;
                continue;
            }
            GetLogger().Error("Cannot read address notifications: {}", Error::FromErrno());
            break;
        }
        if (received == 0) {
            break;
        }
        // A local process can unicast a netlink datagram to this socket (user-to-user needs no
        // privilege), spoofing an address change; drop anything whose source isn't the kernel.
        if (verify_sender_ && !detail::NetlinkSenderIsKernel(src, addrlen)) {
            GetLogger().Debug("Dropping an address notification from a non-kernel sender");
            continue;
        }
        // Once overflowed we'll emit a single refresh-all, so keep draining the socket but stop
        // parsing — the collected list would only be discarded.
        if (!overflowed) {
            CollectChangedInterfaces(
                std::span<std::byte>{buffer.data(), static_cast<size_t>(received)}, changed);
        }
    }

    if (overflowed) {
        GetLogger().Warning("Address notifications overflowed; refreshing all interfaces");
        on_change_(0u);
    } else {
        for (const unsigned index : changed) {
            on_change_(index);
        }
    }
}

#if defined(__linux__)

// The kernel netlink macros (NLMSG_OK, NLMSG_NEXT, NLMSG_DATA) use C-style casts and byte-wise
// pointer arithmetic that the project's strict warning set rejects; the alignment is sound
// (OnReadable aligns the buffer for nlmsghdr and messages are NLMSG_ALIGN padded). Scope the
// suppression to the parser. Every struct the walk reads is start_lifetime_as'd first: the macros
// only compute addresses and read fields of the already-blessed current header, so blessing each
// derived pointer before its first dereference keeps all accesses on live objects.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"

void DefaultAddressMonitor::CollectChangedInterfaces(std::span<std::byte> messages,
        std::vector<unsigned>& changed) const noexcept {
    auto* header = start_lifetime_as<nlmsghdr>(messages.data());
    for (int length = static_cast<int>(messages.size()); NLMSG_OK(header, length);
            header = start_lifetime_as<nlmsghdr>(NLMSG_NEXT(header, length))) {
        if (header->nlmsg_type == RTM_NEWADDR || header->nlmsg_type == RTM_DELADDR) {
            const auto* address = start_lifetime_as<ifaddrmsg>(NLMSG_DATA(header));
            AddUnique(changed, address->ifa_index);
        } else if (header->nlmsg_type == RTM_NEWLINK || header->nlmsg_type == RTM_DELLINK) {
            const auto* link = start_lifetime_as<ifinfomsg>(NLMSG_DATA(header));
            AddUnique(changed, static_cast<unsigned>(link->ifi_index));
        }
    }
}

#pragma GCC diagnostic pop

#else

void DefaultAddressMonitor::CollectChangedInterfaces(std::span<std::byte> messages,
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
        // A link/MAC change arrives as RTM_IFINFO (if_msghdr), whose index sits at the same
        // offset as ifa_msghdr's — asserted here so one read handles both shapes.
        static_assert(offsetof(if_msghdr, ifm_index) == offsetof(ifa_msghdr, ifam_index));
        if ((type == RTM_NEWADDR || type == RTM_DELADDR || type == RTM_IFINFO)
                && message_length >= index_end) {
            u_short index = 0;
            std::memcpy(&index, messages.data() + offset + offsetof(ifa_msghdr, ifam_index), sizeof(index));
            AddUnique(changed, index);
        }
        offset += message_length;
    }
}

#endif

} // namespace reflector
