#pragma once

#include "packet.h"

#include <optional>

namespace reflector {

// The receive side of a socket the packet dispatcher watches and drains: a readable fd plus a
// pull for the next parsed datagram. RawSocket implements it over real L2 capture; tests
// substitute a fake so the dispatcher and its subscribers exercise no real socket.
class ReceiveSocket {
public:
    virtual ~ReceiveSocket() noexcept = default;

    [[nodiscard]] virtual bool IsValid() const noexcept = 0;
    [[nodiscard]] virtual int Fd() const noexcept = 0;

    // The next parsed datagram, or nullopt when none is currently available (EAGAIN) or the
    // next frame is unparseable. The payload may span the socket's buffer and stays valid only
    // until the next Receive() on the same socket.
    [[nodiscard]] virtual std::optional<Packet> Receive() noexcept = 0;

#if defined(__APPLE__)
    // macOS BPF batches several frames into one read(); these let the dispatcher drain the
    // userland buffer past the per-event cap and discard it when it abandons a drain. Not on
    // Linux, where AF_PACKET delivers one frame per recv with no userland buffering.
    [[nodiscard]] virtual bool HasBufferedData() const noexcept = 0;
    virtual void ClearBuffer() noexcept = 0;
#endif
};

} // namespace reflector
