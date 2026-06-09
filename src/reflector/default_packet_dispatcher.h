#pragma once

#include "dispatcher.h"
#include "link_socket.h"
#include "packet.h"
#include "packet_dispatcher.h"
#include "util/no_move.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <utility>
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

    // One per capture socket fd: the socket, the Dispatcher registration that keeps its fd watched, and a
    // count of the live packet registrations on it (kept by RegistrationEntry's ctor/dtor). Created with
    // the socket's first registration and dropped when the count reaches 0, so the fd is watched exactly
    // while something wants its frames. Defined before RegistrationEntry, whose ctor/dtor touch the count.
    struct CaptureSource {
        LinkSocket* socket;
        Dispatcher::Registration dispatcher_reg;
        size_t active_registrations = 0;  // registrations pinned to this socket; 0 -> drop it, no scan
    };

    // A packet subscription. Move-only: it holds one unit of its CaptureSource's active_registrations --
    // the ctor takes one, the dtor releases one, and the move ops hand it off (a moved-from entry owns
    // nothing), so the count stays exact as the vector reallocs and erase shuffles entries. The entry
    // never erases the source itself; Unregister and the drain sweep do that, where the map is at hand.
    struct RegistrationEntry {
        RegistrationEntry(RegistrationId registration_id, CaptureSource* source,
            const PacketCallback& packet_callback, const PacketFilter& packet_filter)
                : id{registration_id}, capture_source{source}, callback{packet_callback},
                  filter{packet_filter} {
            ++capture_source->active_registrations;
        }
        ~RegistrationEntry() noexcept {
            if (capture_source != nullptr) {
                --capture_source->active_registrations;
            }
        }
        RegistrationEntry(RegistrationEntry&& other) noexcept
                : id{other.id}
                , capture_source{std::exchange(other.capture_source, nullptr)}
                , callback{std::move(other.callback)}
                , filter{std::move(other.filter)}
                , enabled{other.enabled} {}
        RegistrationEntry& operator=(RegistrationEntry&& other) noexcept {
            if (this != &other) {
                if (capture_source != nullptr) {
                    --capture_source->active_registrations;
                }
                id = other.id;
                capture_source = std::exchange(other.capture_source, nullptr);
                callback = std::move(other.callback);
                filter = std::move(other.filter);
                enabled = other.enabled;
            }
            return *this;
        }
        RegistrationEntry(const RegistrationEntry&) = delete;
        RegistrationEntry& operator=(const RegistrationEntry&) = delete;

        RegistrationId id;
        CaptureSource* capture_source;
        PacketCallback callback;
        PacketFilter filter;  // before `enabled` so the bool tucks into the filter's trailing padding
        bool enabled = true;  // Unregister marks this false; the post-drain sweep erases it
    };

    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    bool Unregister(RegistrationId id) noexcept override;
    void OnReadable(int fd) noexcept;
    void DrainReadableFd(LinkSocket& socket) noexcept;
    void DispatchPacket(const LinkSocket& socket, const Packet& packet) const;
    // Erases the registrations Unregister marked disabled (their dtors release the capture-source count),
    // then drops every capture source left at 0. Runs after DrainReadableFd's drain -- never mid-walk,
    // where a live erase would shift the vector.
    void Sweep() noexcept;

    Dispatcher* dispatcher_;
    // capture_sources_ is declared before registrations_ so registrations_ is destroyed FIRST: each
    // entry's dtor releases its CaptureSource's count, so the sources must still be alive.
    std::unordered_map<int, CaptureSource> capture_sources_;
    // Register appends; Unregister marks disabled and the post-drain sweep erases (preserving order).
    // DispatchPacket walks this in append order, skipping disabled -- so dispatch stays in registration
    // order and the walk never needs to restart.
    std::vector<RegistrationEntry> registrations_;
    uint64_t next_registration_id_ = 1;
    bool dispatching_ = false;  // true while DrainReadableFd drains; Unregister then defers the erase to the sweep
};

} // namespace reflector
