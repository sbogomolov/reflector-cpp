#include "dispatcher.h"

#include "error.h"
#include "logger.h"

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if !defined(__APPLE__) && !defined(__linux__)
#error "Dispatcher only supports macOS and Linux"
#endif

#if defined(__APPLE__)
#include <sys/event.h>
#elif defined(__linux__)
#include <sys/epoll.h>
#endif

namespace {

using namespace reflector;

#if defined(__APPLE__)
timespec ToTimespec(std::chrono::milliseconds timeout) noexcept {
    return timespec{
        .tv_sec = static_cast<time_t>(timeout.count() / 1000),
        .tv_nsec = static_cast<long>((timeout.count() % 1000) * 1000000),
    };
}
#endif

bool Matches(const PacketFilter& filter, const Packet& packet) {
    if (filter.source_ip && *filter.source_ip != packet.header.source_ip) {
        return false;
    }
    if (filter.dest_ip && *filter.dest_ip != packet.header.dest_ip) {
        return false;
    }
    if (filter.source_port && *filter.source_port != packet.header.source_port) {
        return false;
    }
    if (filter.dest_port && *filter.dest_port != packet.header.dest_port) {
        return false;
    }
    if (filter.source_mac && *filter.source_mac != packet.header.source_mac) {
        return false;
    }
    if (filter.dest_mac && *filter.dest_mac != packet.header.dest_mac) {
        return false;
    }
    return true;
}

Logger& GetLogger() noexcept {
    static Logger logger{"Dispatcher"};
    return logger;
}

} // namespace

namespace reflector {

struct Dispatcher::DispatcherState {
    Dispatcher* dispatcher;
};

Dispatcher::Registration::Registration(WeakPtrUnsynchronized<DispatcherState> dispatcher_state, RegistrationId id) noexcept
        : dispatcher_state_{std::move(dispatcher_state)}, id_{id} {}

Dispatcher::Registration::~Registration() noexcept {
    Reset();
}

Dispatcher::Registration::Registration(Registration&& other) noexcept
        : dispatcher_state_{std::move(other.dispatcher_state_)}
        , id_{std::exchange(other.id_, 0)} {}

Dispatcher::Registration& Dispatcher::Registration::operator=(Registration&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Reset();
    dispatcher_state_ = std::move(other.dispatcher_state_);
    id_ = std::exchange(other.id_, 0);
    return *this;
}

bool Dispatcher::Registration::IsValid() const noexcept {
    const auto dispatcher_state = dispatcher_state_.lock();
    return id_ != 0 && dispatcher_state;
}

bool Dispatcher::Registration::Reset() noexcept {
    const auto dispatcher_state = dispatcher_state_.lock();
    if (id_ == 0 || !dispatcher_state) {
        dispatcher_state_.reset();
        id_ = 0;
        return false;
    }

    const auto id = std::exchange(id_, 0);
    dispatcher_state_.reset();
    return dispatcher_state->dispatcher->Unregister(id);
}

Dispatcher::Dispatcher()
        : dispatcher_state_{new DispatcherState{this}} {
#if defined(__APPLE__)
    event_fd_ = kqueue();
#elif defined(__linux__)
    event_fd_ = epoll_create1(0);
#endif

    if (event_fd_ < 0) {
        GetLogger().Error("Cannot create dispatcher event queue: {}", Error::FromErrno());
    } else {
        GetLogger().Debug("Created dispatcher event queue fd {}", event_fd_);
    }
}

Dispatcher::~Dispatcher() noexcept {
    if (!registrations_.empty()) {
        GetLogger().Error("Destroying dispatcher with {} packet callback registration(s) still active", registrations_.size());
    }
    dispatcher_state_.reset();
    registrations_.clear();

    if (event_fd_ >= 0) {
        GetLogger().Debug("Closing dispatcher event queue fd {}", event_fd_);
        close(event_fd_);
        event_fd_ = -1;
    }
}

Dispatcher::Registration Dispatcher::Register(
    PacketCaptureSocket& socket, const PacketFilter& filter, const PacketCallback& callback) {
    if (!socket.IsValid()) {
        GetLogger().Error("Cannot register packet callback: capture socket is invalid");
        return Registration{};
    }
    const auto fd = socket.Fd();
    if (!AddReadEvent(socket)) {
        GetLogger().Error("Cannot register packet callback: read event registration failed for fd {}", fd);
        return Registration{};
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
    return Registration{dispatcher_state_, id};
}

bool Dispatcher::Unregister(RegistrationId id) noexcept {
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
        if (!RemoveReadEvent(*socket)) {
            GetLogger().Error("Cannot remove read event for fd {} after unregistering callback {}", socket->Fd(), id);
        }
        // Tell DrainReadableFd to stop before its next Receive() — the socket no longer
        // has any registered consumers.
        if (active_socket_ == socket) {
            active_socket_ = nullptr;
        }
    }

    GetLogger().Debug("Unregistered packet callback {}", id);
    return true;
}

void Dispatcher::Run(const volatile std::sig_atomic_t& stop_requested) {
    GetLogger().Info("Starting dispatcher event loop");
    while (stop_requested == 0) {
        PollOnce(std::chrono::milliseconds{1000});
    }
    GetLogger().Info("Stopped dispatcher event loop");
}

bool Dispatcher::PollOnce(std::chrono::milliseconds timeout) {
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot poll dispatcher: event queue is invalid");
        return false;
    }

#if defined(__APPLE__)
    auto timeout_spec = ToTimespec(timeout);
    struct kevent event{};
    const auto event_count = kevent(event_fd_, nullptr, 0, &event, 1, &timeout_spec);
    if (event_count < 0) {
        if (errno == EINTR) {
            // Expected when a signal interrupts polling; callers decide whether to retry or shut down.
            return false;
        }
        GetLogger().Error("Cannot poll dispatcher read events: {}", Error::FromErrno());
        return false;
    }
    if (event_count == 0) {
        return false;
    }
    if ((event.flags & EV_ERROR) != 0) {
        GetLogger().Error("Dispatcher read event failed for fd {}: {}", static_cast<int>(event.ident), event.data);
        return false;
    }

    auto* socket = static_cast<PacketCaptureSocket*>(event.udata);
#elif defined(__linux__)
    epoll_event event{};
    const auto event_count = epoll_wait(event_fd_, &event, 1, static_cast<int>(timeout.count()));
    if (event_count < 0) {
        if (errno == EINTR) {
            // Expected when a signal interrupts polling; callers decide whether to retry or shut down.
            return false;
        }
        GetLogger().Error("Cannot poll dispatcher read events: {}", Error::FromErrno());
        return false;
    }
    if (event_count == 0) {
        return false;
    }
    auto* socket = static_cast<PacketCaptureSocket*>(event.data.ptr);
    const auto events = event.events;
    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
        GetLogger().Error("Dispatcher read event failed for fd {} (events: {:#x})", socket->Fd(), events);
        return false;
    }
#endif

    return DrainReadableFd(*socket);
}

bool Dispatcher::AddReadEvent(PacketCaptureSocket& socket) noexcept {
    const auto fd = socket.Fd();
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot add read event for fd {}: event queue is invalid", fd);
        return false;
    }

#if defined(__APPLE__)
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, &socket);
    if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot add read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#elif defined(__linux__)
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.ptr = &socket;
    if (epoll_ctl(event_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
        if (errno == EEXIST) {
            GetLogger().Debug("Read event already registered for fd {}", fd);
            return true;
        }
        GetLogger().Error("Cannot add read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#endif

    GetLogger().Debug("Registered read event for fd {}", fd);
    return true;
}

bool Dispatcher::RemoveReadEvent(const PacketCaptureSocket& socket) noexcept {
    const auto fd = socket.Fd();
    if (event_fd_ < 0) {
        GetLogger().Error("Cannot remove read event for fd {}: event queue is invalid", fd);
        return false;
    }

#if defined(__APPLE__)
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot remove read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#elif defined(__linux__)
    if (epoll_ctl(event_fd_, EPOLL_CTL_DEL, fd, nullptr) != 0) {
        GetLogger().Error("Cannot remove read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#endif

    GetLogger().Debug("Removed read event for fd {}", fd);
    return true;
}

bool Dispatcher::DrainReadableFd(PacketCaptureSocket& socket) noexcept {
    active_socket_ = &socket;
    bool dispatched_any = false;

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
        dispatched_any = true;

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
    return dispatched_any;
}

void Dispatcher::DispatchPacket(const PacketCaptureSocket& socket, const Packet& packet) const {
    // Walk registrations_ live; no snapshot. A callback may call Unregister and shift
    // elements, so after each dispatch we check that our slot still holds the entry we
    // just fired; if it doesn't, we restart from the front and let last_dispatched_id
    // skip anything we already handled. registrations_ is sorted by id (Register
    // appends with a monotonically increasing id, Unregister preserves order), so the
    // id filter is both necessary and sufficient to avoid duplicate dispatch.
    //
    // Side effect to be aware of: a callback that calls Register creates a new entry
    // with a higher id, which this loop will reach and dispatch for the current packet.
    RegistrationId last_dispatched_id = 0;
    for (size_t idx = 0; idx < registrations_.size();) {
        auto& entry = registrations_[idx];
        if (entry.id > last_dispatched_id
            && entry.socket == &socket
            && Matches(entry.filter, packet)) {
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
