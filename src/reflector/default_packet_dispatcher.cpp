#include "default_packet_dispatcher.h"

#include "logger.h"
#include "util/delegate.h"

#include <algorithm>
#include <utility>

namespace {

using namespace reflector;

Logger& GetLogger() noexcept {
    static Logger logger{"PacketDispatcher"};
    return logger;
}

} // namespace

namespace reflector {

DefaultPacketDispatcher::DefaultPacketDispatcher(Dispatcher& dispatcher)
        : dispatcher_{&dispatcher} {}

DefaultPacketDispatcher::~DefaultPacketDispatcher() noexcept {
    if (!registrations_.empty()) {
        GetLogger().Error("Destroying packet dispatcher with {} registration(s) still active", registrations_.size());
    }
}

PacketRegistration DefaultPacketDispatcher::Register(
    ReceiveSocket& socket, const PacketFilter& filter, const PacketCallback& callback) {
    if (!socket.IsValid()) {
        GetLogger().Error("Cannot register packet callback: capture socket is invalid");
        return {};
    }

    const auto fd = socket.Fd();
    if (!capture_sources_.contains(fd)) {
        // First subscriber for this socket: start watching its fd through the Dispatcher.
        auto dispatcher_reg = dispatcher_->Register(fd, CreateDelegate<&DefaultPacketDispatcher::OnReadable>(this));
        if (!dispatcher_reg.IsValid()) {
            GetLogger().Error("Cannot register packet callback: dispatcher registration failed for fd {}", fd);
            return {};
        }
        capture_sources_.emplace(fd, CaptureSource{.socket = &socket, .dispatcher_reg = std::move(dispatcher_reg)});
    }

    // Must append (never insert in the middle) so registrations_ stays sorted by id —
    // DispatchPacket's merge walk depends on it.
    const auto id = next_registration_id_++;
    registrations_.push_back(RegistrationEntry{
        .id = id,
        .socket = &socket,
        .filter = filter,
        .callback = callback,
    });
    GetLogger().Debug("Registered packet callback {} for fd {}", id, fd);
    return MakeRegistration(id);
}

bool DefaultPacketDispatcher::Unregister(PacketRegistrationId id) noexcept {
    const auto it = std::ranges::find_if(registrations_, [id](const auto& registration) {
        return registration.id == id;
    });
    if (it == registrations_.end()) {
        GetLogger().Warning("Cannot unregister packet callback {}: not found", id);
        return false;
    }

    const auto* socket = it->socket;
    registrations_.erase(it);

    const auto socket_still_used = std::ranges::any_of(registrations_, [socket](const auto& r) {
        return r.socket == socket;
    });
    if (!socket_still_used) {
        // Dropping the CaptureSource resets its DispatcherRegistration, which removes the
        // read event for this fd.
        capture_sources_.erase(socket->Fd());
        // Tell DrainReadableFd to stop before its next Receive() — the socket no longer has
        // any registered consumers.
        if (active_socket_ == socket) {
            active_socket_ = nullptr;
        }
    }

    GetLogger().Debug("Unregistered packet callback {}", id);
    return true;
}

void DefaultPacketDispatcher::OnReadable(int fd) noexcept {
    const auto it = capture_sources_.find(fd);
    if (it == capture_sources_.end()) {
        GetLogger().Warning("Readable callback for unknown capture fd {}", fd);
        return;
    }
    DrainReadableFd(*it->second.socket);
}

void DefaultPacketDispatcher::DrainReadableFd(ReceiveSocket& socket) noexcept {
    active_socket_ = &socket;

#if defined(__APPLE__)
    for (size_t packet_count = 0; packet_count < MAX_PACKETS_PER_READ_EVENT || socket.HasBufferedData(); ++packet_count) {
#elif defined(__linux__)
    for (size_t packet_count = 0; packet_count < MAX_PACKETS_PER_READ_EVENT; ++packet_count) {
#endif
        const auto packet = socket.Receive();
        if (!packet) {
#if defined(__APPLE__)
            if (socket.HasBufferedData()) {
                // Drain all userland-buffered frames. kqueue/epoll only fire on kernel-side
                // activity, so if we leave frames buffered they'll stall. Only macOS BPF
                // buffers in userland; HasBufferedData is not defined on Linux.
                continue;
            }
#endif
            break;
        }

        DispatchPacket(socket, *packet);

        if (active_socket_ != &socket) {
            // A callback dropped the last registration for this socket; nothing wants
            // its frames anymore. Discard any userland-buffered frames so they don't
            // stall (kqueue won't refire on data that's already in our buffer).
#if defined(__APPLE__)
            socket.ClearBuffer();
#endif
            break;
        }
    }

    active_socket_ = nullptr;
}

void DefaultPacketDispatcher::DispatchPacket(const ReceiveSocket& socket, const Packet& packet) const {
    // Walk registrations_ live; no snapshot. A callback may call Unregister and shift
    // elements, so after each dispatch we check that our slot still holds the entry we
    // just fired; if it doesn't, we restart from the front and let last_dispatched_id
    // skip anything we already handled. registrations_ is sorted by id (Register
    // appends with a monotonically increasing id, Unregister preserves order), so the
    // id filter is both necessary and sufficient to avoid duplicate dispatch.
    //
    // Side effect to be aware of: a callback that calls Register creates a new entry
    // with a higher id, which this loop will reach and dispatch for the current packet.
    PacketRegistrationId last_dispatched_id = 0;
    for (size_t idx = 0; idx < registrations_.size();) {
        auto& entry = registrations_[idx];
        if (entry.id > last_dispatched_id
            && entry.socket == &socket
            && entry.filter.Matches(packet)) {
            last_dispatched_id = entry.id;
            entry.callback(packet);

            // If a callback shifted entries before us, our slot now holds a different id
            // (or is past the end). Restart from the front; the last_dispatched_id filter
            // above skips anything we already dispatched.
            if (idx >= registrations_.size() || registrations_[idx].id != last_dispatched_id) {
                idx = 0;
                continue;
            }
        }
        ++idx;
    }
}

} // namespace reflector
