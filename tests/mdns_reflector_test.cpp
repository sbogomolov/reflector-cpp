#include "reflector/mdns_reflector.h"
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
#include <vector>

namespace reflector {

namespace {
constexpr uint16_t MDNS_PORT = 5353;
}

class MdnsReflectorTestBase {
protected:
    static MdnsConfig MakeConfig(AddressFamily address_family = AddressFamily::Default) {
        return MdnsConfig{
            .name = "bridge",
            .mac = std::nullopt,
            .source_if = "lan",
            .target_if = "iot",
            .address_family = address_family,
        };
    }

    // A 12-byte DNS header (QR clear) plus trailing record bytes, so the >12-byte path and payload
    // preservation are exercised.
    static std::vector<std::byte> MakeQuery() {
        std::vector<std::byte> payload(20, std::byte{0xab});
        for (size_t i = 0; i < 12; ++i) {
            payload[i] = std::byte{0};
        }
        return payload;  // byte 2 == 0 -> QR clear -> query
    }

    static std::vector<std::byte> MakeResponse() {
        auto payload = MakeQuery();
        payload[2] = std::byte{0x84};  // QR set (+AA) -> response
        return payload;
    }

    static Packet MakePacket(std::span<const std::byte> payload, IpAddress::Family family,
        MacAddress source_mac = {}) {
        return Packet{
            .header = PacketHeader{
                .source = {LoopbackFor(family), MDNS_PORT},
                .dest = {IpAddress::MdnsGroupFor(family), MDNS_PORT},
                .ttl = 1,  // re-emit must override this with the mDNS TTL (255)
                .source_mac = source_mac,
            },
            .payload = payload,
        };
    }
};

// Behaviors that depend on the address family run for both V4 and V6.
class MdnsReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                   public MdnsReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;
    FakeLinkSocket target;

    size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

    // A single-family config for GetParam(), with only that family sendable on both sockets.
    MdnsReflector BuildReflector() {
        const bool v4 = GetParam() == IpAddress::Family::V4;
        source.can_send_v4 = target.can_send_v4 = v4;
        source.can_send_v6 = target.can_send_v6 = !v4;
        return MdnsReflector{packet_dispatcher, source, target,
            MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
    }
};

INSTANTIATE_TEST_SUITE_P(
    Families,
    MdnsReflectorPerFamilyTest,
    ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
    [](const ::testing::TestParamInfo<IpAddress::Family>& param_info) { return std::format("{}", param_info.param); });

TEST_P(MdnsReflectorPerFamilyTest, RegistersBothDirections) {
    const auto reflector = BuildReflector();

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // source->target and target->source
}

TEST_P(MdnsReflectorPerFamilyTest, JoinsGroupOnBothSockets) {
    const auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto group = IpAddress::MdnsGroupFor(GetParam());
    EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{group});
    EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{group});
}

TEST_P(MdnsReflectorPerFamilyTest, RelaysQueryFromSourceToTarget) {
    const auto family = GetParam();
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto query = MakeQuery();
    packet_dispatcher.Deliver(source, MakePacket(query, family));

    ASSERT_EQ(target.sent.size(), 1u);
    const auto& sent = target.sent.front();
    EXPECT_EQ(sent.dst_ip, IpAddress::MdnsGroupFor(family));
    EXPECT_EQ(sent.dst_port, MDNS_PORT);
    EXPECT_EQ(sent.src_port, MDNS_PORT);
    EXPECT_EQ(sent.ttl, 255);  // re-emitted with the mDNS hop limit, not the captured TTL
    EXPECT_EQ(sent.payload, query);
    EXPECT_TRUE(source.sent.empty());  // not echoed back to the source
}

TEST_P(MdnsReflectorPerFamilyTest, DropsResponseFromSourceToTarget) {
    const auto family = GetParam();
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    // A response arriving on source is not relayed to target — only queries flow that way.
    packet_dispatcher.Deliver(source, MakePacket(MakeResponse(), family));

    EXPECT_TRUE(target.sent.empty());
}

TEST_P(MdnsReflectorPerFamilyTest, RelaysResponseFromTargetToSource) {
    const auto family = GetParam();
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto response = MakeResponse();
    packet_dispatcher.Deliver(target, MakePacket(response, family));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto& sent = source.sent.front();
    EXPECT_EQ(sent.dst_ip, IpAddress::MdnsGroupFor(family));
    EXPECT_EQ(sent.dst_port, MDNS_PORT);
    EXPECT_EQ(sent.src_port, MDNS_PORT);
    EXPECT_EQ(sent.ttl, 255);
    EXPECT_EQ(sent.payload, response);
    EXPECT_TRUE(target.sent.empty());
}

TEST_P(MdnsReflectorPerFamilyTest, DropsQueryFromTargetToSource) {
    const auto family = GetParam();
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    // A query arriving on target is not relayed to source — that would let target devices discover
    // the source network.
    packet_dispatcher.Deliver(target, MakePacket(MakeQuery(), family));

    EXPECT_TRUE(source.sent.empty());
}

TEST_P(MdnsReflectorPerFamilyTest, RequiredFamilyUnavailableOnSourceMakesInvalid) {
    const auto family = GetParam();
    const bool v4 = family == IpAddress::Family::V4;
    source.can_send_v4 = !v4 ? true : false;
    source.can_send_v6 = !v4 ? false : true;  // the required family is missing on source
    target.can_send_v4 = target.can_send_v6 = true;

    const std::string output = CaptureStdout([&] {
        const MdnsReflector reflector{packet_dispatcher, source, target,
            MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find(std::format("{}", family)), std::string::npos) << output;
}

TEST_P(MdnsReflectorPerFamilyTest, RequiredFamilyUnavailableOnTargetMakesInvalid) {
    const auto family = GetParam();
    const bool v4 = family == IpAddress::Family::V4;
    source.can_send_v4 = source.can_send_v6 = true;
    target.can_send_v4 = !v4 ? true : false;
    target.can_send_v6 = !v4 ? false : true;  // the required family is missing on target

    const MdnsReflector reflector{packet_dispatcher, source, target,
        MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
    EXPECT_FALSE(reflector.IsValid());
}

// Family-independent behavior, exercised once.
class MdnsReflectorTest : public ::testing::Test, public MdnsReflectorTestBase {
protected:
    FakePacketDispatcher packet_dispatcher;
    FakeLinkSocket source;  // both families sendable by default
    FakeLinkSocket target;

    size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }
};

TEST_F(MdnsReflectorTest, RejectsInvalidConfig) {
    auto config = MakeConfig();
    config.target_if = config.source_if;  // source_if == target_if fails Verify

    const std::string output = CaptureStdout([&] {
        const MdnsReflector reflector{packet_dispatcher, source, target, config};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, CreatedLogUsesConfigName) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const std::string output = CaptureStdout([&] {
        const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig()};
        EXPECT_TRUE(reflector.IsValid());
    });
    EXPECT_NE(output.find("bridge"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, DualReflectsBothFamilies) {
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 4);  // both directions for each family
    EXPECT_EQ(source.joined_groups.size(), 2u);
    EXPECT_EQ(target.joined_groups.size(), 2u);
}

TEST_F(MdnsReflectorTest, DualInvalidWhenSourceCannotSendAFamily) {
    source.can_send_v6 = false;  // Dual requires v6 on both
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

TEST_F(MdnsReflectorTest, DualInvalidWhenTargetCannotSendAFamily) {
    target.can_send_v6 = false;
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

// Default uses both families but requires only IPv4; with IPv6 unavailable on one side it stays
// valid over IPv4 alone (the v6 group is neither joined nor registered).
TEST_F(MdnsReflectorTest, DefaultReflectsAvailableFamilyOnly) {
    target.can_send_v6 = false;
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only
    EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{IpAddress::MdnsGroupV4()});
    EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{IpAddress::MdnsGroupV4()});
}

TEST_F(MdnsReflectorTest, MacFilterRelaysOnlyTheConfiguredDevice) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
    const MdnsReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    const auto response = MakeResponse();
    // A response from a different device is filtered out (the dispatcher's source_mac filter).
    packet_dispatcher.Deliver(target,
        MakePacket(response, IpAddress::Family::V4, *MacAddress::FromString("00:00:00:00:00:01")));
    EXPECT_TRUE(source.sent.empty());

    packet_dispatcher.Deliver(target,
        MakePacket(response, IpAddress::Family::V4, *MacAddress::FromString("aa:bb:cc:dd:ee:ff")));
    EXPECT_EQ(source.sent.size(), 1u);
}

TEST_F(MdnsReflectorTest, NoMacFilterRelaysAnyDevice) {
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target,
        MakePacket(MakeResponse(), IpAddress::Family::V4, *MacAddress::FromString("12:34:56:78:9a:bc")));
    EXPECT_EQ(source.sent.size(), 1u);
}

TEST_F(MdnsReflectorTest, LogsAndDropsNonMdnsPacket) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    const std::vector<std::byte> too_short(11, std::byte{0});  // < 12-byte DNS header
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(too_short, IpAddress::Family::V4));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_NE(output.find("non-mDNS"), std::string::npos) << output;  // anomaly surfaced at INFO
}

TEST_F(MdnsReflectorTest, DropsWrongDirectionSilently) {
    const ScopedMinLogLevel level{LogLevel::Info};
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A response arriving on source is normal bidirectional mDNS, not an anomaly: dropped without
    // the non-mDNS log.
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeResponse(), IpAddress::Family::V4));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(output.find("non-mDNS"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, LogsErrorWhenSendFails) {
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    target.fail_send = true;

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeQuery(), IpAddress::Family::V4));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, JoinFailureMakesInvalid) {
    source.fail_join = true;

    const std::string output = CaptureStdout([&] {
        const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);
    });
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, RegistrationFailureRollsBackAndInvalidates) {
    packet_dispatcher.fail_register_on_call = 2;  // the second registration fails

    const std::string output = CaptureStdout([&] {
        const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
        EXPECT_FALSE(reflector.IsValid());
    });

    EXPECT_EQ(RegistrationCount(), 0);  // the first registration was rolled back
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(MdnsReflectorTest, DestructorUnregisters) {
    {
        const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
        ASSERT_TRUE(reflector.IsValid());
        ASSERT_EQ(RegistrationCount(), 4);
    }

    EXPECT_EQ(RegistrationCount(), 0);
}

} // namespace reflector
