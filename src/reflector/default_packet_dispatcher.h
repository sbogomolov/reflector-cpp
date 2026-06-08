#pragma once

#include "dispatcher.h"
#include "link_socket.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "util/no_move.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace reflector {

// Demultiplexes captured packets to filtered subscribers, layered on a Dispatcher. It
// registers one readable-fd callback per capture socket with the Dispatcher; when a socket
// becomes readable it drains every queued frame and dispatches each to the registrations
// whose filter matches. Packet subscribers register their interest here, not with the
// Dispatcher — keeping the Dispatcher a plain fd reactor.
class DefaultPacketDispatcher : public PacketDispatcher, NoMove {
public:
    explicit DefaultPacketDispatcher(Dispatcher& dispatcher);
    ~DefaultPacketDispatcher() noexcept override;

    [[nodiscard]] PacketDispatcher::Registration Register(
        LinkSocket& socket, const PacketFilter& filter, const PacketCallback& callback) override;

    [[nodiscard]] Dispatcher& UnderlyingDispatcher() noexcept override { return *dispatcher_; }

private:
    friend class DefaultPacketDispatcherTest;

    static constexpr size_t MAX_PACKETS_PER_READ_EVENT = 64;

    struct RegistrationEntry {
        RegistrationId id;
        LinkSocket* socket;
        PacketFilter filter;
        PacketCallback callback;
    };

    // One per capture socket fd: the socket plus the Dispatcher registration that keeps its
    // fd watched. Created with the socket's first packet registration and dropped with its
    // last, so the fd is watched exactly while something wants its frames.
    struct CaptureSource {
        LinkSocket* socket;
        Dispatcher::Registration dispatcher_reg;
    };

    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    bool Unregister(RegistrationId id) noexcept override;
    void OnReadable(int fd) noexcept;
    void DrainReadableFd(LinkSocket& socket) noexcept;
    void DispatchPacket(const LinkSocket& socket, const Packet& packet) const;

    Dispatcher* dispatcher_;
    // Kept sorted by id: Register appends with a monotonically increasing id and Unregister
    // erases in place. DispatchPacket relies on this for its merge walk; any insertion that
    // breaks the order would silently corrupt dispatch.
    std::vector<RegistrationEntry> registrations_;
    std::unordered_map<int, CaptureSource> capture_sources_;
    uint64_t next_registration_id_ = 1;
    // Socket currently being drained; cleared when its last registration is dropped, so
    // DrainReadableFd can bail before the next Receive() on a socket nothing wants.
    const LinkSocket* active_socket_ = nullptr;
};

} // namespace reflector
