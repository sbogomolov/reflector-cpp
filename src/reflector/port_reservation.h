#pragma once

#include "ip_address.h"

#include <cstdint>
#include <optional>

namespace reflector {

// A reservation over a single ephemeral UDP port. SSDP step 2 re-emits a relayed M-SEARCH from this
// port so devices unicast their 200 OK back to it; the port must stay "claimed" for the session's
// lifetime so the kernel's UDP socket lookup succeeds and it does NOT answer the response with an
// ICMP port-unreachable. The bound socket is never read — the real datagram is captured by the raw
// socket. On Linux a drop-all BPF filter makes the socket enqueue nothing; elsewhere it is simply
// never drained. Move-only fd owner.
class PortReservation {
public:
    // Opens and binds a socket to an OS-assigned ephemeral port of `family` on the wildcard address.
    // Returns nullopt (after logging) if the socket/bind/getsockname fails.
    [[nodiscard]] static std::optional<PortReservation> Create(IpAddress::Family family) noexcept;

    PortReservation(PortReservation&& other) noexcept;
    PortReservation& operator=(PortReservation&& other) noexcept;
    ~PortReservation() noexcept;

    [[nodiscard]] uint16_t Port() const noexcept { return port_; }

private:
    PortReservation(int fd, uint16_t port) noexcept : fd_{fd}, port_{port} {}

    int fd_ = -1;
    uint16_t port_ = 0;
};

} // namespace reflector
