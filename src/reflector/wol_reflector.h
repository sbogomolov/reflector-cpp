#pragma once

#include "config.h"
#include "logger.h"
#include "mac_address.h"
#include "packet_dispatcher.h"
#include "raw_socket.h"
#include "udp_link_fanout_sender.h"
#include "util/no_move.h"

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace reflector {

class WolReflector : NoMove {
public:
    WolReflector(PacketDispatcher& packet_dispatcher, RawSocket& socket, const WolConfig& config);
    ~WolReflector() noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return !registrations_.empty(); }

private:
    friend class WolReflectorTestBase;

    static constexpr size_t PREFIX_SIZE = 6;
    static constexpr size_t MAC_SIZE = 6;
    static constexpr size_t MAC_REPETITIONS = 16;
    static constexpr size_t MAGIC_PACKET_SIZE = PREFIX_SIZE + MAC_REPETITIONS * MAC_SIZE;

    WolReflector(PacketDispatcher& packet_dispatcher, RawSocket& socket, const WolConfig& config,
        std::optional<UdpLinkFanoutSender> v4_sender, std::optional<UdpLinkFanoutSender> v6_sender);

    [[nodiscard]] bool ValidateConfig(const WolConfig& config);
    void Initialize(PacketDispatcher& packet_dispatcher, RawSocket& socket, const WolConfig& config);
    void BuildExpectedMagicPacket(MacAddress mac) noexcept;
    [[nodiscard]] bool IsMagicPacket(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasMagicPacketPrefix(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool HasRepeatedMac(std::span<const std::byte> payload) noexcept;
    void OnPacket(const Packet& packet) noexcept;
    [[nodiscard]] UdpLinkFanoutSender* SenderFor(IpAddress::Family family) noexcept;
    void Reset() noexcept;

    Logger logger_;
    std::optional<UdpLinkFanoutSender> v4_sender_;
    std::optional<UdpLinkFanoutSender> v6_sender_;
    std::optional<MacAddress> target_mac_;
    // Always contains the magic-packet prefix. In fixed-MAC mode it also contains the
    // repeated target MAC; in any-MAC mode only the prefix bytes are used.
    std::array<std::byte, MAGIC_PACKET_SIZE> expected_magic_packet_{};
    std::vector<PacketDispatcher::Registration> registrations_;
};

} // namespace reflector
