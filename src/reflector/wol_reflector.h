#pragma once

#include "config.h"
#include "family_capability.h"
#include "link_socket.h"
#include "mac_address.h"
#include "packet_dispatcher.h"
#include "reflector.h"

#include <array>
#include <cstddef>
#include <optional>
#include <span>

namespace reflector {

class WolReflector : public Reflector {
public:
    // Captures WoL magic packets on `source_socket` and re-emits matching ones through
    // `target_socket`. Both must outlive this reflector.
    WolReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
        LinkSocket& target_socket, const WolConfig& config);

private:
    static constexpr size_t PREFIX_SIZE = 6;
    static constexpr size_t MAC_SIZE = 6;
    static constexpr size_t MAC_REPETITIONS = 16;
    static constexpr size_t MAGIC_PACKET_SIZE = PREFIX_SIZE + MAC_REPETITIONS * MAC_SIZE;

    [[nodiscard]] bool ValidateConfig(const WolConfig& config);
    void Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket, const WolConfig& config);
    void BuildExpectedMagicPacket(MacAddress mac) noexcept;
    [[nodiscard]] bool IsMagicPacket(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasMagicPacketPrefix(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasRepeatedMac(std::span<const std::byte> payload) noexcept;
    void OnPacket(const Packet& packet) noexcept;

    LinkSocket& target_socket_;
    // The target interface's per-family send capability, gated by the config's family policy.
    // Read live per packet, so an address change takes effect without re-creating the reflector
    // (a merely-used family is dropped quietly while the target can't send it); transition
    // notices fire one-shot via Observe().
    FamilyCapability target_capability_;
    std::optional<MacAddress> target_mac_;
    // Always contains the magic-packet prefix. In fixed-MAC mode it also contains the
    // repeated target MAC; in any-MAC mode only the prefix bytes are used.
    std::array<std::byte, MAGIC_PACKET_SIZE> expected_magic_packet_{};
};

} // namespace reflector
