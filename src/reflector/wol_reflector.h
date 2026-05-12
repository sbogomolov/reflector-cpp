#pragma once

#include "config.h"
#include "logger.h"
#include "mac_address.h"
#include "udp_sender.h"
#include "util/no_move.h"
#include "wol_listener.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

class WolReflector : NoMove {
public:
    WolReflector(WolListener& listener, const WolConfig& config);
    WolReflector(WolListener& listener, UdpSender& sender, const WolConfig& config);
    ~WolReflector() noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return !registrations_.empty(); }

private:
    friend class WolReflectorTest;

    static constexpr size_t PREFIX_SIZE = 6;
    static constexpr size_t MAC_REPETITIONS = 16;
    static constexpr size_t MAGIC_PACKET_SIZE = PREFIX_SIZE + MAC_REPETITIONS * 6;

    struct PortHandler {
        WolReflector* parent;
        uint16_t port;
        void OnPacket(const Packet& packet) noexcept;
    };

    [[nodiscard]] bool ValidateConfig(const WolConfig& config);
    void Initialize(WolListener& listener, const WolConfig& config);
    void BuildExpectedMagicPacket(MacAddress mac) noexcept;
    [[nodiscard]] bool IsMagicPacket(std::span<const std::byte> payload) noexcept;
    void HandlePacket(const Packet& packet, uint16_t port) noexcept;
    void Reset() noexcept;

    Logger logger_;
    std::optional<UdpSender> owned_sender_;
    UdpSender* sender_ = nullptr;
    std::array<std::byte, MAGIC_PACKET_SIZE> expected_magic_packet_{};
    // std::deque keeps element addresses stable across growth — Delegate stores raw PortHandler*
    // pointers into this container, so reallocating storage would dangle them.
    std::deque<PortHandler> port_handlers_;
    std::vector<WolListener::Registration> registrations_;
};

} // namespace reflector
