#pragma once

#include "dispatcher.h"
#include "packet.h"
#include "raw_socket.h"
#include "util/no_copy.h"
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
class PacketDispatcher : NoMove {
public:
    using RegistrationId = uint64_t;

    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration() noexcept;

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept;
        bool Reset() noexcept;

    private:
        friend class PacketDispatcher;

        Registration(PacketDispatcher* packet_dispatcher, RegistrationId id) noexcept;

        PacketDispatcher* packet_dispatcher_ = nullptr;
        RegistrationId id_ = 0;
    };

    explicit PacketDispatcher(Dispatcher& dispatcher);
    ~PacketDispatcher() noexcept;

    // The socket must outlive every registration returned for it and this PacketDispatcher:
    // we keep a raw pointer to it and dereference it on Unregister and on every drain.
    // The returned Registration must not outlive this PacketDispatcher.
    [[nodiscard]] Registration Register(RawSocket& socket, const PacketFilter& filter, const PacketCallback& callback);

private:
    friend class PacketDispatcherTest;
    friend class WolListenerTest;
    friend class WolReflectorTest;
    friend class WolReflectorPerFamilyTest;

    static constexpr size_t MAX_PACKETS_PER_READ_EVENT = 64;

    struct RegistrationEntry {
        RegistrationId id;
        RawSocket* socket;
        PacketFilter filter;
        PacketCallback callback;
    };

    // One per capture socket fd: the socket plus the Dispatcher registration that keeps its
    // fd watched. Created with the socket's first packet registration and dropped with its
    // last, so the fd is watched exactly while something wants its frames.
    struct CaptureSource {
        RawSocket* socket;
        Dispatcher::Registration dispatcher_reg;
    };

    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    bool Unregister(RegistrationId id) noexcept;
    void OnReadable(int fd) noexcept;
    void DrainReadableFd(RawSocket& socket) noexcept;
    void DispatchPacket(const RawSocket& socket, const Packet& packet) const;

    Dispatcher* dispatcher_;
    // Kept sorted by id: Register appends with a monotonically increasing id and Unregister
    // erases in place. DispatchPacket relies on this for its merge walk; any insertion that
    // breaks the order would silently corrupt dispatch.
    std::vector<RegistrationEntry> registrations_;
    std::unordered_map<int, CaptureSource> capture_sources_;
    RegistrationId next_registration_id_ = 1;
    // Socket currently being drained; cleared when its last registration is dropped, so
    // DrainReadableFd can bail before the next Receive() on a socket nothing wants.
    const RawSocket* active_socket_ = nullptr;
};

} // namespace reflector
