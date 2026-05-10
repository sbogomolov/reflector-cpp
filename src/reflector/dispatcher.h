#pragma once

#include "logger.h"
#include "packet.h"
#include "udp_socket.h"
#include "util/no_copy.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstdint>
#include <optional>
#include <vector>

namespace reflector {

class Dispatcher : NoCopy {
public:
    using RegistrationId = uint64_t;

    class Registration : NoCopy {
    public:
        Registration() noexcept = default;
        ~Registration();

        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;

        [[nodiscard]] bool IsValid() const noexcept { return dispatcher_ != nullptr && id_ != 0; }
        bool Reset() noexcept;

    private:
        friend class Dispatcher;

        Registration(Dispatcher& dispatcher, RegistrationId id) noexcept;

        Dispatcher* dispatcher_ = nullptr;
        RegistrationId id_ = 0;
    };

    Dispatcher();
    ~Dispatcher();

    [[nodiscard]] Registration Register(const UdpSocket& socket, const PacketFilter& filter, const PacketCallback& callback);

    void Run(const volatile std::sig_atomic_t& stop_requested);
    bool PollOnce(std::chrono::milliseconds timeout);

private:
    friend class DispatcherTest;
    friend class WolListenerTest;
    friend class WolReflectorTest;

    static constexpr size_t RECEIVE_BUFFER_SIZE = 4096;
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

    Logger logger_{"Dispatcher"};
    std::vector<RegistrationEntry> registrations_;
    // Reused across calls; Packet::payload spans into this and is only valid during dispatch.
    std::array<std::byte, RECEIVE_BUFFER_SIZE> receive_buffer_{};
    RegistrationId next_registration_id_ = 1;
    int event_fd_ = -1;
};

} // namespace reflector
