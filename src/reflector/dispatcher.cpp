#include "dispatcher.h"

#include "error.h"
#include "logger.h"

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <netinet/in.h>
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
    if (!filter.source_ip.IsAny() && filter.source_ip != packet.header.source_ip) {
        return false;
    }
    if (filter.source_port != 0 && filter.source_port != packet.header.source_port) {
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
    explicit DispatcherState(Dispatcher& dispatcher) noexcept
            : dispatcher{&dispatcher} {}

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
        : dispatcher_state_{new DispatcherState{*this}} {
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
    const UdpSocket& socket, const PacketFilter& filter, const PacketCallback& callback) {
    if (!socket.IsValid()) {
        GetLogger().Error("Cannot register packet callback: socket is invalid");
        return Registration{};
    }

    const auto fd = socket.Fd();
    if (!AddReadEvent(fd)) {
        GetLogger().Error("Cannot register packet callback: read event registration failed for fd {}", fd);
        return Registration{};
    }

    const auto id = next_registration_id_++;
    registrations_.push_back(RegistrationEntry{
        .id = id,
        .fd = fd,
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

    const auto fd = it->fd;
    registrations_.erase(it);

    const auto fd_still_used = std::ranges::any_of(registrations_, [fd](const auto& r) {
        return r.fd == fd;
    });
    if (fd >= 0 && !fd_still_used) {
        if (!RemoveReadEvent(fd)) {
            GetLogger().Error("Cannot remove read event for fd {} after unregistering callback {}", fd, id);
        }
        // The caller may now close the fd; invalidate active_fd_ so DrainReadableFd stops
        // before recvfrom on a possibly-reused descriptor.
        if (active_fd_ == fd) {
            active_fd_ = -1;
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

    const auto fd = static_cast<int>(event.ident);
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
    const auto fd = event.data.fd;
    const auto events = event.events;
    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
        GetLogger().Error("Dispatcher read event failed for fd {} (events: {:#x})", fd, events);
        return false;
    }
#endif

    return DrainReadableFd(fd);
}

bool Dispatcher::AddReadEvent(int fd) noexcept {
    if (event_fd_ < 0 || fd < 0) {
        GetLogger().Error("Cannot add read event: event queue or fd is invalid");
        return false;
    }

#if defined(__APPLE__)
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    if (kevent(event_fd_, &change, 1, nullptr, 0, nullptr) != 0) {
        GetLogger().Error("Cannot add read event for fd {}: {}", fd, Error::FromErrno());
        return false;
    }
#elif defined(__linux__)
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = fd;
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

bool Dispatcher::RemoveReadEvent(int fd) noexcept {
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

bool Dispatcher::DrainReadableFd(int fd) noexcept {
    active_fd_ = fd;
    bool dispatched_any = false;
    for (size_t packet_count = 0; packet_count < MAX_PACKETS_PER_READ_EVENT; ++packet_count) {
        const auto packet = Receive(fd);
        if (!packet) {
            break;
        }

        DispatchPacket(fd, *packet);
        dispatched_any = true;

        if (active_fd_ != fd) {
            // A callback unregistered the last user of this fd; the descriptor may already
            // belong to a new socket. Stop draining before recvfrom hits it.
            break;
        }
    }

    active_fd_ = -1;
    return dispatched_any;
}

std::optional<Packet> Dispatcher::Receive(int fd) noexcept {
    sockaddr_in source_address{};
    socklen_t source_address_size = sizeof(source_address);
    // EINTR before recvfrom consumes the datagram leaves it queued — retry, don't drop.
    ssize_t bytes_received;
    do {
        bytes_received = recvfrom(fd,
            receive_buffer_.data(),
            receive_buffer_.size(),
            0,
            reinterpret_cast<sockaddr*>(&source_address),
            &source_address_size);
    } while (bytes_received < 0 && errno == EINTR);
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }

        GetLogger().Error("Cannot receive packet from fd {}: {}", fd, Error::FromErrno());
        return std::nullopt;
    }

    Packet packet{
        .header = PacketHeader{
            .source_ip = IpAddress::FromInAddr(source_address.sin_addr.s_addr),
            .source_port = ntohs(source_address.sin_port),
        },
        .payload = std::span<const std::byte>{receive_buffer_.data(), static_cast<size_t>(bytes_received)},
    };
    GetLogger().Debug("Received {} bytes from {}:{}", bytes_received, packet.header.source_ip, packet.header.source_port);
    return packet;
}

void Dispatcher::DispatchPacket(int fd, const Packet& packet) const {
    // Snapshot IDs first: a callback may call Unregister, which modifies registrations_.
    std::vector<RegistrationId> registration_ids;
    for (const auto& registration : registrations_) {
        if (registration.fd == fd && Matches(registration.filter, packet)) {
            registration_ids.push_back(registration.id);
        }
    }

    for (const auto registration_id : registration_ids) {
        const auto it = std::ranges::find_if(registrations_, [registration_id](const auto& registration) {
            return registration.id == registration_id;
        });
        if (it != registrations_.end()) {
            it->callback(packet);
        }
    }
}

} // namespace reflector
