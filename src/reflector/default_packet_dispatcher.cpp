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

PacketDispatcher::Registration DefaultPacketDispatcher::Register(
    LinkSocket& socket, const PacketFilter& filter, const PacketCallback& callback) {
    if (!socket.IsValid()) {
        GetLogger().Error("Cannot register packet callback: capture socket is invalid");
        return {};
    }

    const auto fd = socket.Fd();
    auto source = capture_sources_.find(fd);
    if (source == capture_sources_.end()) {
        // First subscriber for this socket: start watching its fd through the Dispatcher.
        auto dispatcher_reg = dispatcher_->Register(fd, CreateDelegate<&DefaultPacketDispatcher::OnReadable>(this));
        if (!dispatcher_reg.IsValid()) {
            GetLogger().Error("Cannot register packet callback: dispatcher registration failed for fd {}", fd);
            return {};
        }
        source = capture_sources_.emplace(
            fd, CaptureSource{.socket = &socket, .dispatcher_reg = std::move(dispatcher_reg)}).first;
    }

    // Append (never insert mid-vector) so ids stay ascending; the entry's ctor takes a hold on the
    // capture source's count.
    const auto id = static_cast<RegistrationId>(next_registration_id_++);
    registrations_.emplace_back(id, &source->second, callback, filter);
    GetLogger().Debug("Registered packet callback {} for fd {}", std::to_underlying(id), fd);
    return MakeRegistration(id);
}

bool DefaultPacketDispatcher::Unregister(RegistrationId id) noexcept {
    const auto it = std::ranges::find_if(registrations_, [id](const auto& r) {
        return r.id == id && r.enabled;
    });
    if (it == registrations_.end()) {
        GetLogger().Warning("Cannot unregister packet callback {}: not found", std::to_underlying(id));
        return false;
    }
    GetLogger().Debug("Unregistered packet callback {}", std::to_underlying(id));
    if (dispatching_) {
        it->enabled = false;  // DrainReadableFd is walking; defer the erase + teardown to its sweep
        return true;
    }
    // No drain in progress: erase in place. The entry's dtor releases its hold on the capture source; if
    // that was the last, drop the now-unreferenced source.
    auto* source = it->capture_source;
    registrations_.erase(it);
    if (source->active_registrations == 0) {
        capture_sources_.erase(source->socket->Fd());
    }
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

void DefaultPacketDispatcher::DrainReadableFd(LinkSocket& socket) noexcept {
    // Bracket the whole drain: a callback's Unregister only marks its entry disabled (DispatchPacket
    // skips it from here on), and the single sweep below erases the marked entries plus any now-orphaned
    // capture source. A socket whose last registration is dropped mid-drain just dispatches to nothing
    // for the rest of the drain, then loses its capture source in the sweep.
    dispatching_ = true;

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
    }

    dispatching_ = false;
    Sweep();
}

void DefaultPacketDispatcher::DispatchPacket(const LinkSocket& socket, const Packet& packet) const {
    // Forward walk in registration order, skipping disabled entries. A callback may Unregister (marks
    // disabled -- skipped here, swept after the drain) or Register (appends, possibly reallocating) --
    // so index by position and re-fetch each iteration, never holding an iterator across the callback.
    // Removal is deferred to the sweep, so the walk never shifts and needs no restart. A callback that
    // Registers appends a higher entry this loop still reaches, dispatching it for the current packet.
    for (size_t idx = 0; idx < registrations_.size(); ++idx) {
        const auto& entry = registrations_[idx];
        if (entry.enabled && entry.capture_source->socket == &socket && entry.filter.Matches(packet)) {
            entry.callback(packet);
        }
    }
}

void DefaultPacketDispatcher::Sweep() noexcept {
    // The erased entries' dtors release their capture-source holds; then drop every source left at 0 --
    // one flat pass over capture_sources_ (a handful of fds), not a per-registration scan.
    std::erase_if(registrations_, [](const RegistrationEntry& r) { return !r.enabled; });
    std::erase_if(capture_sources_, [](const auto& entry) { return entry.second.active_registrations == 0; });
}

} // namespace reflector
