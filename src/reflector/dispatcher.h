#pragma once

#include "packet.h"
#include "packet_capture_socket.h"
#include "util/no_copy.h"
#include "util/no_move.h"
#include "util/shared_ptr_unsynchronized.h"

#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstdint>
#include <vector>

namespace reflector {

class Dispatcher : NoMove {
private:
    struct DispatcherState;

public:
    using RegistrationId = uint64_t;

public:
    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration() noexcept;

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept;
        bool Reset() noexcept;

    private:
        friend class Dispatcher;

        Registration(WeakPtrUnsynchronized<DispatcherState> dispatcher_state, RegistrationId id) noexcept;

        WeakPtrUnsynchronized<DispatcherState> dispatcher_state_;
        RegistrationId id_ = 0;
    };

    Dispatcher();
    ~Dispatcher() noexcept;

    [[nodiscard]] Registration Register(PacketCaptureSocket& socket, const PacketFilter& filter, const PacketCallback& callback);

    void Run(const volatile std::sig_atomic_t& stop_requested);
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class DispatcherTest;
    friend class WolListenerTest;
    friend class WolListenerPerFamilyTest;
    friend class WolReflectorTest;
    friend class WolReflectorPerFamilyTest;

    static constexpr size_t MAX_PACKETS_PER_READ_EVENT = 64;

    struct RegistrationEntry {
        RegistrationId id;
        PacketCaptureSocket* socket;
        PacketFilter filter;
        PacketCallback callback;
    };

    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    [[nodiscard]] bool AddReadEvent(PacketCaptureSocket& socket) noexcept;
    [[nodiscard]] bool RemoveReadEvent(const PacketCaptureSocket& socket) noexcept;
    [[nodiscard]] bool DrainReadableFd(PacketCaptureSocket& socket) noexcept;
    bool Unregister(RegistrationId id) noexcept;
    void DispatchPacket(const PacketCaptureSocket& socket, const Packet& packet) const;

    // Kept sorted by id: Register appends with a monotonically increasing id and
    // Unregister erases in place. DispatchPacket relies on this for its merge walk;
    // any insertion that breaks the order would silently corrupt dispatch.
    std::vector<RegistrationEntry> registrations_;
    SharedPtrUnsynchronized<DispatcherState> dispatcher_state_;
    RegistrationId next_registration_id_ = 1;
    int event_fd_ = -1;
    // Socket currently being drained; cleared when its last registration is dropped, so
    // DrainReadableFd can bail before the next Receive() on a socket nothing wants.
    const PacketCaptureSocket* active_socket_ = nullptr;
};

} // namespace reflector
