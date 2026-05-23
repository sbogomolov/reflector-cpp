#pragma once

#include "reflector/packet.h"
#include "reflector/receive_socket.h"

#include <optional>

namespace reflector {

// Minimal ReceiveSocket stand-in for a reflector's source socket when packets are pushed
// through a FakePacketDispatcher rather than drained off a real fd. Receive() never yields.
struct FakeReceiveSocket : ReceiveSocket {
    [[nodiscard]] bool IsValid() const noexcept override { return true; }
    [[nodiscard]] int Fd() const noexcept override { return -1; }
    [[nodiscard]] std::optional<Packet> Receive() noexcept override { return std::nullopt; }
#if defined(__APPLE__)
    [[nodiscard]] bool HasBufferedData() const noexcept override { return false; }
    void ClearBuffer() noexcept override {}
#endif
};

} // namespace reflector
