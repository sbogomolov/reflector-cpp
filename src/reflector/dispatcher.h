#pragma once

#include "packet.h"
#include "udp_socket.h"
#include "util/no_copy.h"
#include "util/no_move.h"
#include "util/shared_ptr_unsynchronized.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstdint>
#include <optional>
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

    [[nodiscard]] Registration Register(const UdpSocket& socket, const PacketFilter& filter, const PacketCallback& callback);

    void Run(const volatile std::sig_atomic_t& stop_requested);
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class DispatcherTest;
    friend class WolListenerTest;
    friend class WolReflectorTest;

    // Large enough for the maximum normal IPv4/IPv6 UDP payload. UDP datagrams can
    // exceed link MTU via IP fragmentation, and recvfrom returns the reassembled payload.
    // IPv6 jumbograms are not supported and would be truncated.
    static constexpr size_t RECEIVE_BUFFER_SIZE = 64 * 1024;
    static constexpr size_t MAX_PACKETS_PER_READ_EVENT = 64;

    struct RegistrationEntry {
        RegistrationId id;
        int fd;
        PacketFilter filter;
        PacketCallback callback;
    };

    [[nodiscard]] size_t RegistrationCount() const noexcept { return registrations_.size(); }

    [[nodiscard]] bool AddReadEvent(int fd) noexcept;
    [[nodiscard]] bool RemoveReadEventIfUnused(int fd) noexcept;
    [[nodiscard]] bool DrainReadableFd(int fd) noexcept;
    bool Unregister(RegistrationId id) noexcept;
    [[nodiscard]] std::optional<Packet> Receive(int fd) noexcept;
    void DispatchPacket(int fd, const Packet& packet) const;

    std::vector<RegistrationEntry> registrations_;
    // Reused across calls; Packet::payload spans into this and is only valid during dispatch.
    std::array<std::byte, RECEIVE_BUFFER_SIZE> receive_buffer_{};
    SharedPtrUnsynchronized<DispatcherState> dispatcher_state_;
    RegistrationId next_registration_id_ = 1;
    int event_fd_ = -1;
};

} // namespace reflector
