#include "reflector/mdns_reflector.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "mocks/fake_link_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace reflector;
constexpr uint16_t MDNS_PORT = 5353;

// A sorted copy, so group-set assertions don't depend on join/leave ordering.
std::vector<IpAddress> Sorted(std::vector<IpAddress> groups) {
    std::ranges::sort(groups);
    return groups;
}
}

namespace reflector {

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
        source.iface.SetHasSource(IpAddress::Family::V4, v4);
        target.iface.SetHasSource(IpAddress::Family::V4, v4);
        source.iface.SetHasSource(IpAddress::Family::V6, !v4);
        target.iface.SetHasSource(IpAddress::Family::V6, !v4);
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

// The reflector holds its group memberships for its lifetime (the groups stay joined) and leaves
// exactly the groups it joined when destroyed — a regression guard against dropping the membership
// tokens at setup.
TEST_P(MdnsReflectorPerFamilyTest, HoldsGroupsWhileAliveAndLeavesOnDestruction) {
    {
        const auto reflector = BuildReflector();
        ASSERT_TRUE(reflector.IsValid());
        EXPECT_TRUE(source.left_groups.empty()) << "groups must stay joined while the reflector lives";
        EXPECT_TRUE(target.left_groups.empty());
    }
    EXPECT_EQ(Sorted(source.left_groups), Sorted(source.joined_groups));
    EXPECT_EQ(Sorted(target.left_groups), Sorted(target.joined_groups));
}

// A join failure on one interface invalidates the reflector AND auto-leaves the membership already
// taken on the other interface — the RAII-token guarantee that no group is left dangling-joined.
TEST_P(MdnsReflectorPerFamilyTest, PartialJoinFailureLeavesTheOtherInterfacesGroup) {
    source.fail_join = true;  // source join fails; SetUpFamily joins target first, then rolls back

    const std::string output = CaptureStdout([&] {
        const auto reflector = BuildReflector();
        EXPECT_FALSE(reflector.IsValid());
    });

    EXPECT_TRUE(source.joined_groups.empty());          // source never took a membership
    EXPECT_FALSE(target.joined_groups.empty());         // target did join before the rollback
    EXPECT_EQ(target.left_groups, target.joined_groups);  // and that membership was auto-left
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
    source.iface.SetHasSource(IpAddress::Family::V4, !v4);
    source.iface.SetHasSource(IpAddress::Family::V6, v4);  // the required family is missing on source
    target.iface.SetHasSource(IpAddress::Family::V4, true);
    target.iface.SetHasSource(IpAddress::Family::V6, true);

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
    source.iface.SetHasSource(IpAddress::Family::V4, true);
    source.iface.SetHasSource(IpAddress::Family::V6, true);
    target.iface.SetHasSource(IpAddress::Family::V4, !v4);
    target.iface.SetHasSource(IpAddress::Family::V6, v4);  // the required family is missing on target

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
    source.iface.SetHasSource(IpAddress::Family::V6, false);  // Dual requires v6 on both
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

TEST_F(MdnsReflectorTest, DualInvalidWhenTargetCannotSendAFamily) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

// Default uses both families but requires only IPv4; with IPv6 unavailable on one side it stays
// valid over IPv4 alone (the v6 group is neither joined nor registered).
TEST_F(MdnsReflectorTest, DefaultReflectsAvailableFamilyOnly) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);
    const MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only
    EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{IpAddress::MdnsGroupV4()});
    EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{IpAddress::MdnsGroupV4()});
}

// A family that isn't reflectable at construction comes up once both interfaces can send it: on the
// next interface change the group is joined and captures registered on both sockets, and its
// traffic relays.
TEST_F(MdnsReflectorTest, OptionalFamilyComesUpWhenItBecomesReflectable) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 not reflectable at startup
    MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only

    target.iface.SetHasSource(IpAddress::Family::V6, true);  // a v6 address appears
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), 4);  // v6 now registered on both sockets too
    EXPECT_NE(std::ranges::find(source.joined_groups, IpAddress::MdnsGroupV6()), source.joined_groups.end());
    EXPECT_NE(std::ranges::find(target.joined_groups, IpAddress::MdnsGroupV6()), target.joined_groups.end());

    packet_dispatcher.Deliver(source, MakePacket(MakeQuery(), IpAddress::Family::V6));
    ASSERT_EQ(target.sent.size(), 1u);  // a v6 query now relays source -> target
    EXPECT_EQ(target.sent.front().dst_ip, IpAddress::MdnsGroupV6());
}

// A reflected family is torn down when it stops being reflectable: the group is left, both captures
// unregistered, and its traffic no longer relays.
TEST_F(MdnsReflectorTest, FamilyIsTornDownWhenItStopsBeingReflectable) {
    MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 4);  // both families up

    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 lost on the target
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), 2);  // v6 captures dropped
    EXPECT_NE(std::ranges::find(source.left_groups, IpAddress::MdnsGroupV6()), source.left_groups.end());
    EXPECT_NE(std::ranges::find(target.left_groups, IpAddress::MdnsGroupV6()), target.left_groups.end());

    packet_dispatcher.Deliver(source, MakePacket(MakeQuery(), IpAddress::Family::V6));
    EXPECT_TRUE(target.sent.empty());  // no registration -> no relay
}

// A required family lost at runtime is torn down (with an Error notice) and brought back when its
// address returns. The reflector stays valid throughout (validity is decided at construction).
TEST_F(MdnsReflectorTest, RequiredFamilyTornDownAndRecovered) {
    MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);

    target.iface.SetHasSource(IpAddress::Family::V4, false);  // the required v4 vanishes
    const std::string lost = CaptureStdout([&] { reflector.OnInterfaceChanged(); });
    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_TRUE(reflector.IsValid());  // still valid: validity is fixed at construction, not by teardown
    EXPECT_NE(std::ranges::find(target.left_groups, IpAddress::MdnsGroupV4()), target.left_groups.end());
    EXPECT_NE(lost.find(std::format("Cannot reflect {} packets", IpAddress::Family::V4)),
        std::string::npos) << lost;

    target.iface.SetHasSource(IpAddress::Family::V4, true);  // and returns
    reflector.OnInterfaceChanged();
    EXPECT_EQ(RegistrationCount(), 2);  // brought back up

    packet_dispatcher.Deliver(source, MakePacket(MakeQuery(), IpAddress::Family::V4));
    ASSERT_EQ(target.sent.size(), 1u);
}

// An interface change that doesn't flip any family's reflectability is a no-op: SyncFamily's
// already-in-desired-state guard means no group is re-joined and no capture re-registered.
TEST_F(MdnsReflectorTest, RepeatInterfaceChangeWithoutCapabilityChangeIsANoOp) {
    MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    const auto joins_before = source.joined_groups.size();
    const auto count_before = RegistrationCount();

    reflector.OnInterfaceChanged();
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), count_before);          // no duplicate registrations
    EXPECT_EQ(source.joined_groups.size(), joins_before);  // no duplicate joins
    EXPECT_TRUE(source.left_groups.empty());               // and nothing torn down
}

// A transient bring-up failure when a family becomes reflectable (e.g. a join momentarily fails)
// leaves the family down without partial setup, keeps the reflector valid, and is retried — and
// succeeds — on the next interface change once the condition clears.
TEST_F(MdnsReflectorTest, TransientBringUpFailureLeavesFamilyDownThenRetries) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 down at construction
    MdnsReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only

    source.fail_join = true;                                  // v6's bring-up will fail to join
    target.iface.SetHasSource(IpAddress::Family::V6, true);   // v6 becomes reflectable
    const std::string output = CaptureStdout([&] { reflector.OnInterfaceChanged(); });

    EXPECT_EQ(RegistrationCount(), 2);   // bring-up failed -> v6 stays down, nothing half-set-up
    EXPECT_TRUE(reflector.IsValid());    // still valid
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;  // the join failure was logged

    source.fail_join = false;            // the transient condition clears
    reflector.OnInterfaceChanged();      // retried on the next change
    EXPECT_EQ(RegistrationCount(), 4);   // v6 now up
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
