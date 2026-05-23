#pragma once

#include "config.h"
#include "logger.h"
#include "mac_address.h"
#include "packet_dispatcher.h"
#include "receive_socket.h"
#include "udp_sender.h"
#include "util/no_move.h"

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

class WolReflector : NoMove {
public:
    // Captures WoL magic packets on `source_socket` and re-emits matching ones through
    // `target_socket`. Both must outlive this reflector.
    WolReflector(PacketDispatcher& packet_dispatcher, ReceiveSocket& source_socket,
        UdpSender& target_socket, const WolConfig& config);
    ~WolReflector() noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return !registrations_.empty(); }

private:
    static constexpr size_t PREFIX_SIZE = 6;
    static constexpr size_t MAC_SIZE = 6;
    static constexpr size_t MAC_REPETITIONS = 16;
    static constexpr size_t MAGIC_PACKET_SIZE = PREFIX_SIZE + MAC_REPETITIONS * MAC_SIZE;

    [[nodiscard]] bool ValidateConfig(const WolConfig& config);
    void Initialize(PacketDispatcher& packet_dispatcher, ReceiveSocket& source_socket, const WolConfig& config);
    void BuildExpectedMagicPacket(MacAddress mac) noexcept;
    [[nodiscard]] bool IsMagicPacket(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasMagicPacketPrefix(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasRepeatedMac(std::span<const std::byte> payload) noexcept;
    void OnPacket(const Packet& packet) noexcept;
    [[nodiscard]] bool ReflectsFamily(IpAddress::Family family) const noexcept;
    void Reset() noexcept;

    Logger logger_;
    UdpSender& target_socket_;
    // Families this reflector actually re-emits: the config uses the family and target_socket_
    // can originate it. A family the config merely *uses* (Default uses both, requires only v4)
    // but the target can't send is left false, so OnPacket drops it instead of failing every send.
    bool reflects_v4_ = false;
    bool reflects_v6_ = false;
    std::optional<MacAddress> target_mac_;
    // Always contains the magic-packet prefix. In fixed-MAC mode it also contains the
    // repeated target MAC; in any-MAC mode only the prefix bytes are used.
    std::array<std::byte, MAGIC_PACKET_SIZE> expected_magic_packet_{};
    std::vector<PacketRegistration> registrations_;
};

} // namespace reflector
