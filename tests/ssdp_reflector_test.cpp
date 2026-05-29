#include "reflector/ssdp_reflector.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "mocks/fake_link_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reflector {

namespace {
constexpr uint16_t SSDP_PORT = 1900;

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}
} // namespace

class SsdpReflectorTestBase {
protected:
    static SsdpConfig MakeConfig(AddressFamily address_family = AddressFamily::Default) {
        return SsdpConfig{
            .name = "cast",
            .mac = std::nullopt,
            .source_if = "lan",
            .target_if = "iot",
            .address_family = address_family,
        };
    }

    static std::vector<std::byte> MakeSearch() {
        return Bytes(
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n");
    }

    static std::vector<std::byte> MakeAdvertisement() {
        return Bytes(
            "NOTIFY * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "NT: upnp:rootdevice\r\n"
            "NTS: ssdp:alive\r\n\r\n");
    }

    // A packet captured for `group` (its multicast destination), from that family's loopback. ttl 1
    // so re-emit can be shown to override it with the SSDP hop limit.
    static Packet MakePacket(std::span<const std::byte> payload, const IpAddress& group,
        MacAddress source_mac = {}) {
        const auto family = group.IsV4() ? IpAddress::Family::V4 : IpAddress::Family::V6;
        return Packet{
            .header = PacketHeader{
                .source_ip = LoopbackFor(family),
                .dest_ip = group,
                .source_port = SSDP_PORT,
                .dest_port = SSDP_PORT,
                .ttl = 1,
                .source_mac = source_mac,
            },
            .payload = payload,
        };
    }
};

// Behaviors that depend on the address family run for both V4 and V6. SSDP differs from mDNS here:
// the V6 family has two groups (link-local + site-local), so registration/join counts scale with
// the group count.
class SsdpReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                   public SsdpReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;
    FakeLinkSocket target;

    size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }
    std::vector<IpAddress> Groups() const { return IpAddress::SsdpGroupsFor(GetParam()); }

    SsdpReflector BuildReflector() {
        const bool v4 = GetParam() == IpAddress::Family::V4;
        source.can_send_v4 = target.can_send_v4 = v4;
        source.can_send_v6 = target.can_send_v6 = !v4;
        return SsdpReflector{packet_dispatcher, source, target,
            MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    SsdpReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& param_info) { return std::format("{}", param_info.param); });

TEST_P(SsdpReflectorPerFamilyTest, RegistersBothDirectionsPerGroup) {
    const auto reflector = BuildReflector();

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2 * Groups().size());  // source->target and target->source, per group
}

TEST_P(SsdpReflectorPerFamilyTest, JoinsEveryGroupOnBothSockets) {
    const auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    EXPECT_EQ(source.joined_groups, Groups());
    EXPECT_EQ(target.joined_groups, Groups());
}

TEST_P(SsdpReflectorPerFamilyTest, RelaysSearchFromSourceToTargetOnEveryGroup) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto search = MakeSearch();
    size_t relayed = 0;
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(source, MakePacket(search, group));
        ++relayed;
        ASSERT_EQ(target.sent.size(), relayed);
        const auto& sent = target.sent.back();
        EXPECT_EQ(sent.dst_ip, group);
        EXPECT_EQ(sent.dst_port, SSDP_PORT);
        EXPECT_EQ(sent.src_port, SSDP_PORT);
        EXPECT_EQ(sent.ttl, 2);  // re-emitted with the SSDP hop limit, not the captured TTL
        EXPECT_EQ(sent.payload, search);
    }
    EXPECT_TRUE(source.sent.empty());  // not echoed back to the source
}

TEST_P(SsdpReflectorPerFamilyTest, DropsAdvertisementFromSourceToTarget) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    // A NOTIFY arriving on source is not relayed to target — only M-SEARCH flows that way.
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(source, MakePacket(MakeAdvertisement(), group));
    }
    EXPECT_TRUE(target.sent.empty());
}

TEST_P(SsdpReflectorPerFamilyTest, RelaysAdvertisementFromTargetToSource) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto advertisement = MakeAdvertisement();
    size_t relayed = 0;
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(target, MakePacket(advertisement, group));
        ++relayed;
        ASSERT_EQ(source.sent.size(), relayed);
        const auto& sent = source.sent.back();
        EXPECT_EQ(sent.dst_ip, group);
        EXPECT_EQ(sent.dst_port, SSDP_PORT);
        EXPECT_EQ(sent.src_port, SSDP_PORT);
        EXPECT_EQ(sent.ttl, 2);
        EXPECT_EQ(sent.payload, advertisement);
    }
    EXPECT_TRUE(target.sent.empty());
}

TEST_P(SsdpReflectorPerFamilyTest, DropsSearchFromTargetToSource) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    // An M-SEARCH arriving on target is not relayed to source — that would let target devices
    // discover the source network.
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(target, MakePacket(MakeSearch(), group));
    }
    EXPECT_TRUE(source.sent.empty());
}

TEST_P(SsdpReflectorPerFamilyTest, RequiredFamilyUnavailableOnSourceMakesInvalid) {
    const auto family = GetParam();
    const bool v4 = family == IpAddress::Family::V4;
    source.can_send_v4 = !v4 ? true : false;
    source.can_send_v6 = !v4 ? false : true;  // the required family is missing on source
    target.can_send_v4 = target.can_send_v6 = true;

    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target,
            MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find(std::format("{}", family)), std::string::npos) << output;
}

TEST_P(SsdpReflectorPerFamilyTest, RequiredFamilyUnavailableOnTargetMakesInvalid) {
    const auto family = GetParam();
    const bool v4 = family == IpAddress::Family::V4;
    source.can_send_v4 = source.can_send_v6 = true;
    target.can_send_v4 = !v4 ? true : false;
    target.can_send_v6 = !v4 ? false : true;  // the required family is missing on target

    const SsdpReflector reflector{packet_dispatcher, source, target,
        MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
    EXPECT_FALSE(reflector.IsValid());
}

// Family-independent behavior, exercised once.
class SsdpReflectorTest : public ::testing::Test, public SsdpReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;  // both families sendable by default
    FakeLinkSocket target;

    size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }
};

TEST_F(SsdpReflectorTest, RejectsInvalidConfig) {
    auto config = MakeConfig();
    config.target_if = config.source_if;  // source_if == target_if fails Verify

    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target, config};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, CreatedLogUsesConfigName) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig()};
        EXPECT_TRUE(reflector.IsValid());
    });
    EXPECT_NE(output.find("cast"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, DualReflectsBothFamilies) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};

    EXPECT_TRUE(reflector.IsValid());
    // v4 (1 group) + v6 (2 groups) = 3 groups, both directions each.
    EXPECT_EQ(RegistrationCount(), 6);
    EXPECT_EQ(source.joined_groups.size(), 3u);
    EXPECT_EQ(target.joined_groups.size(), 3u);
}

TEST_F(SsdpReflectorTest, DualInvalidWhenSourceCannotSendAFamily) {
    source.can_send_v6 = false;  // Dual requires v6 on both
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

TEST_F(SsdpReflectorTest, DualInvalidWhenTargetCannotSendAFamily) {
    target.can_send_v6 = false;
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

// Default uses both families but requires only IPv4; with IPv6 unavailable on one side it stays
// valid over IPv4 alone (the v6 groups are neither joined nor registered).
TEST_F(SsdpReflectorTest, DefaultReflectsAvailableFamilyOnly) {
    target.can_send_v6 = false;
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only, one group
    EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
    EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
}

TEST_F(SsdpReflectorTest, MacFilterRelaysOnlyTheConfiguredDevice) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    const auto advertisement = MakeAdvertisement();
    const auto group = IpAddress::SsdpGroupV4();
    // A NOTIFY from a different device is filtered out (the dispatcher's source_mac filter).
    packet_dispatcher.Deliver(target,
        MakePacket(advertisement, group, *MacAddress::FromString("00:00:00:00:00:01")));
    EXPECT_TRUE(source.sent.empty());

    // The configured device's advertisement is relayed.
    packet_dispatcher.Deliver(target,
        MakePacket(advertisement, group, *MacAddress::FromString("aa:bb:cc:dd:ee:ff")));
    EXPECT_EQ(source.sent.size(), 1u);
}

TEST_F(SsdpReflectorTest, NoMacFilterRelaysAnyDevice) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target,
        MakePacket(MakeAdvertisement(), IpAddress::SsdpGroupV4(), *MacAddress::FromString("12:34:56:78:9a:bc")));
    EXPECT_EQ(source.sent.size(), 1u);
}

TEST_F(SsdpReflectorTest, LogsAndDropsNonSsdpPacket) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A unicast-style HTTP response that strayed onto the group: not an M-SEARCH or NOTIFY.
    const auto response = Bytes("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n");
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(response, IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_NE(output.find("non-SSDP"), std::string::npos) << output;  // anomaly surfaced at INFO
}

TEST_F(SsdpReflectorTest, DropsWrongDirectionSilently) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A NOTIFY arriving on source is normal bidirectional SSDP, not an anomaly: dropped without the
    // non-SSDP log.
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeAdvertisement(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(output.find("non-SSDP"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, LogsErrorWhenSendFails) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    target.fail_send = true;

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, JoinFailureMakesInvalid) {
    source.fail_join = true;

    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, RegistrationFailureRollsBackAndInvalidates) {
    packet_dispatcher.fail_register_on_call = 2;  // the second registration fails

    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
        EXPECT_FALSE(reflector.IsValid());
    });

    EXPECT_EQ(RegistrationCount(), 0);  // the first registration was rolled back
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, DestructorUnregisters) {
    {
        const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(RegistrationCount(), 6);
    }

    EXPECT_EQ(RegistrationCount(), 0);
}

} // namespace reflector
