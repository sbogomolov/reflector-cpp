#include "reflector/ssdp_reflector.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "reflector/tcp_socket.h"
#include "mocks/fake_interface.h"
#include "mocks/fake_link_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace reflector;
constexpr uint16_t SSDP_PORT = 1900;

// A sorted copy, so group-set assertions don't depend on join/leave ordering.
std::vector<IpAddress> Sorted(std::vector<IpAddress> groups) {
    std::ranges::sort(groups);
    return groups;
}

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

std::string_view AsText(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}
} // namespace

namespace reflector {

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

    // The device authority both DIAL fixtures advertise; a non-loopback literal so a rewrite to the
    // minted (loopback) reflector listener is observable in the forwarded payload.
    static constexpr std::string_view DIAL_DEVICE_AUTHORITY = "192.168.1.50:8008";

    static std::vector<std::byte> MakeDialAdvertisement() {
        return Bytes(
            "NOTIFY * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "LOCATION: http://192.168.1.50:8008/dd.xml\r\n"
            "NT: urn:dial-multiscreen-org:service:dial:1\r\n"
            "NTS: ssdp:alive\r\n\r\n");
    }

    static std::vector<std::byte> MakeDialResponse() {
        return Bytes(
            "HTTP/1.1 200 OK\r\n"
            "ST: urn:dial-multiscreen-org:service:dial:1\r\n"
            "LOCATION: http://192.168.1.50:8008/dd.xml\r\n\r\n");
    }

    // A packet captured for `group` (its multicast destination), from that family's loopback. ttl 1
    // so re-emit can be shown to override it with the SSDP hop limit.
    static Packet MakePacket(std::span<const std::byte> payload, const IpAddress& group,
        MacAddress source_mac = {}) {
        const auto family = group.IsV4() ? IpAddress::Family::V4 : IpAddress::Family::V6;
        return Packet{
            .header = PacketHeader{
                .source = {LoopbackFor(family), SSDP_PORT},
                .dest = {group, SSDP_PORT},
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
        source.iface.SetHasSource(IpAddress::Family::V4, v4);
        target.iface.SetHasSource(IpAddress::Family::V4, v4);
        source.iface.SetHasSource(IpAddress::Family::V6, !v4);
        target.iface.SetHasSource(IpAddress::Family::V6, !v4);
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

// The reflector holds every group membership for its lifetime (the groups stay joined) and leaves
// exactly the groups it joined when destroyed — a regression guard against dropping the membership
// tokens at setup.
TEST_P(SsdpReflectorPerFamilyTest, HoldsGroupsWhileAliveAndLeavesOnDestruction) {
    {
        const auto reflector = BuildReflector();
        ASSERT_TRUE(reflector.IsValid());
        EXPECT_TRUE(source.left_groups.empty()) << "groups must stay joined while the reflector lives";
        EXPECT_TRUE(target.left_groups.empty());
    }
    EXPECT_EQ(Sorted(source.left_groups), Sorted(Groups()));
    EXPECT_EQ(Sorted(target.left_groups), Sorted(Groups()));
}

// A join failure on one interface invalidates the reflector AND auto-leaves the membership already
// taken on the other interface — the RAII-token guarantee that no group is left dangling-joined.
TEST_P(SsdpReflectorPerFamilyTest, PartialJoinFailureLeavesTheOtherInterfacesGroup) {
    source.fail_join = true;  // source join fails; SetUpGroup joins target first, then rolls back

    const std::string output = CaptureStdout([&] {
        const auto reflector = BuildReflector();
        EXPECT_FALSE(reflector.IsValid());
    });

    EXPECT_TRUE(source.joined_groups.empty());          // source never took a membership
    EXPECT_FALSE(target.joined_groups.empty());         // target joined the first group before rollback
    EXPECT_EQ(target.left_groups, target.joined_groups);  // and every membership it took was auto-left
}

TEST_P(SsdpReflectorPerFamilyTest, ReflectsSearchFromSourceToTargetOnEveryGroup) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto search = MakeSearch();
    size_t reflected = 0;
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(source, MakePacket(search, group));
        ++reflected;
        ASSERT_EQ(target.sent.size(), reflected);
        const auto& sent = target.sent.back();
        EXPECT_EQ(sent.dst_ip, group);
        EXPECT_EQ(sent.dst_port, SSDP_PORT);
        EXPECT_NE(sent.src_port, SSDP_PORT);  // reflected from the per-search reserved port, not 1900
        EXPECT_NE(sent.src_port, 0u);
        EXPECT_EQ(sent.ttl, 2);  // re-emitted with the SSDP hop limit, not the captured TTL
        EXPECT_EQ(sent.payload, search);
    }
    EXPECT_TRUE(source.sent.empty());  // not echoed back to the source
}

TEST_P(SsdpReflectorPerFamilyTest, DropsAdvertisementFromSourceToTarget) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    // A NOTIFY arriving on source is not reflected to target — only M-SEARCH flows that way.
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(source, MakePacket(MakeAdvertisement(), group));
    }
    EXPECT_TRUE(target.sent.empty());
}

TEST_P(SsdpReflectorPerFamilyTest, ReflectsAdvertisementFromTargetToSource) {
    auto reflector = BuildReflector();
    ASSERT_TRUE(reflector.IsValid());

    const auto advertisement = MakeAdvertisement();
    size_t reflected = 0;
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(target, MakePacket(advertisement, group));
        ++reflected;
        ASSERT_EQ(source.sent.size(), reflected);
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

    // An M-SEARCH arriving on target is not reflected to source — that would let target devices
    // discover the source network.
    for (const auto& group : Groups()) {
        packet_dispatcher.Deliver(target, MakePacket(MakeSearch(), group));
    }
    EXPECT_TRUE(source.sent.empty());
}

TEST_P(SsdpReflectorPerFamilyTest, RequiredFamilyUnavailableOnSourceMakesInvalid) {
    const auto family = GetParam();
    const bool v4 = family == IpAddress::Family::V4;
    source.iface.SetHasSource(IpAddress::Family::V4, !v4);
    source.iface.SetHasSource(IpAddress::Family::V6, v4);  // the required family is missing on source
    target.iface.SetHasSource(IpAddress::Family::V4, true);
    target.iface.SetHasSource(IpAddress::Family::V6, true);

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
    source.iface.SetHasSource(IpAddress::Family::V4, true);
    source.iface.SetHasSource(IpAddress::Family::V6, true);
    target.iface.SetHasSource(IpAddress::Family::V4, !v4);
    target.iface.SetHasSource(IpAddress::Family::V6, v4);  // the required family is missing on target

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
    source.iface.SetHasSource(IpAddress::Family::V6, false);  // Dual requires v6 on both
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

TEST_F(SsdpReflectorTest, DualInvalidWhenTargetCannotSendAFamily) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    EXPECT_FALSE(reflector.IsValid());
}

// Default uses both families but requires only IPv4; with IPv6 unavailable on one side it stays
// valid over IPv4 alone (the v6 groups are neither joined nor registered).
TEST_F(SsdpReflectorTest, DefaultReflectsAvailableFamilyOnly) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};

    EXPECT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only, one group
    EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
    EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
}

// An optional family not reflectable at construction comes up once both interfaces can send it: on
// the next interface change ALL its groups (IPv6 has two) are joined and captured, and traffic
// flows. Mirrors mDNS but exercises SSDP's multi-group BringUpFamily.
TEST_F(SsdpReflectorTest, OptionalFamilyComesUpWhenItBecomesReflectable) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 not reflectable at startup
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only (one group, both directions)

    target.iface.SetHasSource(IpAddress::Family::V6, true);  // a v6 address appears
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), 6);  // + v6's two groups x both directions
    for (const auto& group : IpAddress::SsdpGroupsFor(IpAddress::Family::V6)) {
        EXPECT_NE(std::ranges::find(source.joined_groups, group), source.joined_groups.end());
        EXPECT_NE(std::ranges::find(target.joined_groups, group), target.joined_groups.end());
    }

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV6LinkLocal()));
    EXPECT_FALSE(target.sent.empty());  // a v6 search now reflects source -> target
}

// All of a family's groups are torn down when it stops being reflectable: every group left, all its
// captures unregistered, and its traffic no longer reflects.
TEST_F(SsdpReflectorTest, FamilyIsTornDownWhenItStopsBeingReflectable) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 6);  // v4 (1 group) + v6 (2 groups), both directions

    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 lost on the target
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), 2);  // v6's four captures dropped
    for (const auto& group : IpAddress::SsdpGroupsFor(IpAddress::Family::V6)) {
        EXPECT_NE(std::ranges::find(target.left_groups, group), target.left_groups.end());
    }

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV6LinkLocal()));
    EXPECT_TRUE(target.sent.empty());  // no registration -> no reflection
}

// A required family lost at runtime is torn down (with an Error notice) and brought back when its
// address returns. The reflector stays valid throughout (validity is decided at construction).
TEST_F(SsdpReflectorTest, RequiredFamilyTornDownAndRecovered) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);

    target.iface.SetHasSource(IpAddress::Family::V4, false);  // the required v4 vanishes
    const std::string lost = CaptureStdout([&] { reflector.OnInterfaceChanged(); });
    EXPECT_EQ(RegistrationCount(), 0);
    EXPECT_TRUE(reflector.IsValid());  // still valid: validity is fixed at construction
    EXPECT_NE(std::ranges::find(target.left_groups, IpAddress::SsdpGroupV4()), target.left_groups.end());
    EXPECT_NE(lost.find(std::format("Cannot reflect {} packets", IpAddress::Family::V4)),
        std::string::npos) << lost;

    target.iface.SetHasSource(IpAddress::Family::V4, true);  // and returns
    reflector.OnInterfaceChanged();
    EXPECT_EQ(RegistrationCount(), 2);  // brought back up
}

// SSDP counterpart of MdnsReflectorTest.RepeatInterfaceChangeWithoutCapabilityChangeIsANoOp: an
// interface change that doesn't flip any family's reflectability is a no-op. SyncFamily's
// already-in-desired-state guard is per-family, so this also covers IPv6's second group (site-local) —
// a per-group guard, or none at all, would churn it on every call even though nothing changed.
TEST_F(SsdpReflectorTest, RepeatInterfaceChangeWithoutCapabilityChangeIsANoOp) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    const auto joins_before = source.joined_groups.size();
    const auto count_before = RegistrationCount();

    reflector.OnInterfaceChanged();
    reflector.OnInterfaceChanged();

    EXPECT_EQ(RegistrationCount(), count_before);          // no duplicate registrations
    EXPECT_EQ(source.joined_groups.size(), joins_before);  // no duplicate joins
    EXPECT_TRUE(source.left_groups.empty());               // and nothing torn down
}

// SSDP counterpart of MdnsReflectorTest.TransientBringUpFailureLeavesFamilyDownThenRetries, timed to
// fail v6's SECOND group (site-local) rather than its first: proves BringUpFamily's per-group rollback
// (not just DynamicFamilyReflector's family-level teardown) releases the FIRST group's (link-local)
// already-taken membership/registrations when a LATER group fails during a dynamic (OnInterfaceChanged)
// bring-up — the construction-time equivalent is FailureOnALaterGroupRollsBackTheWholeFamily below.
TEST_F(SsdpReflectorTest, TransientBringUpFailureOnALaterGroupLeavesFamilyDownThenRetries) {
    target.iface.SetHasSource(IpAddress::Family::V6, false);  // v6 down at construction
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);  // v4 only

    // v6 becomes reflectable; fail its SECOND group's (site-local) first registration, after the first
    // group (link-local) has already taken its memberships/registrations.
    target.iface.SetHasSource(IpAddress::Family::V6, true);
    packet_dispatcher.fail_register_on_call = RegistrationCount() + 3;
    const std::string output = CaptureStdout([&] { reflector.OnInterfaceChanged(); });

    EXPECT_EQ(RegistrationCount(), 2);   // bring-up failed -> v6 stays fully down, nothing half-set-up
    EXPECT_TRUE(reflector.IsValid());    // still valid
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;  // the registration failure was logged
    // the first group's membership, already taken before the second group's failure, was rolled back too
    EXPECT_NE(std::ranges::find(source.left_groups, IpAddress::SsdpGroupV6LinkLocal()),
        source.left_groups.end());

    packet_dispatcher.fail_register_on_call = 0;  // the transient condition clears
    reflector.OnInterfaceChanged();                // retried on the next change
    EXPECT_EQ(RegistrationCount(), 6);  // v4 (2) + v6's two groups x both directions (4)
}

// Multi-group construction rollback: when a LATER group of a family fails to register, the family's
// already-set-up earlier groups are rolled back (BringUpFamily resets the setup) before the
// reflector reports invalid. (IPv6 has two groups; fail the second's first registration.)
TEST_F(SsdpReflectorTest, FailureOnALaterGroupRollsBackTheWholeFamily) {
    packet_dispatcher.fail_register_on_call = 3;  // group 1 (calls 1-2) succeeds; group 2's first reg (3) fails

    const std::string output = CaptureStdout([&] {
        const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv6)};
        EXPECT_FALSE(reflector.IsValid());
        EXPECT_EQ(RegistrationCount(), 0);  // the first group's captures were rolled back too
    });

    EXPECT_NE(std::ranges::find(source.left_groups, IpAddress::SsdpGroupV6LinkLocal()),
        source.left_groups.end());
}

// The DIAL proxy is independent of family setup: tearing the v4 family down and bringing it back up
// (an interface change) leaves the proxy intact, so DIAL LOCATION rewriting still works afterward.
TEST_F(SsdpReflectorTest, DialProxySurvivesAFamilyTeardown) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    target.iface.SetHasSource(IpAddress::Family::V4, false);  // v4 family torn down
    reflector.OnInterfaceChanged();
    target.iface.SetHasSource(IpAddress::Family::V4, true);   // and brought back up
    reflector.OnInterfaceChanged();

    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_EQ(text.find(DIAL_DEVICE_AUTHORITY), std::string_view::npos) << text;  // still rewritten
    EXPECT_NE(text.find("http://127.0.0.1:"), std::string_view::npos) << text;
}

TEST_F(SsdpReflectorTest, MacFilterReflectsOnlyTheConfiguredDevice) {
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

    // The configured device's advertisement is reflected.
    packet_dispatcher.Deliver(target,
        MakePacket(advertisement, group, *MacAddress::FromString("aa:bb:cc:dd:ee:ff")));
    EXPECT_EQ(source.sent.size(), 1u);
}

TEST_F(SsdpReflectorTest, NoMacFilterReflectsAnyDevice) {
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
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();
    target.fail_send = true;

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(RegistrationCount(), base);  // the response capture is rolled back on the failed reflect
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

// --- unicast M-SEARCH response reflection. These deliver an M-SEARCH, which mutates the session
// table via OnSourcePacket, so the reflector must be non-const (writing through a const object is UB).

TEST_F(SsdpReflectorTest, MSearchReflectionOriginatesFromAReservedPortAndCreatesSession) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t before = RegistrationCount();

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(target.sent.size(), 1u);
    const auto& sent = target.sent.back();
    EXPECT_EQ(sent.dst_ip, IpAddress::SsdpGroupV4());
    EXPECT_EQ(sent.dst_port, SSDP_PORT);
    EXPECT_NE(sent.src_port, SSDP_PORT);  // reflected from the reserved ephemeral port, not 1900
    EXPECT_NE(sent.src_port, 0u);
    EXPECT_EQ(sent.ttl, 2);
    EXPECT_EQ(RegistrationCount(), before + 1);  // + the session's response capture
}

TEST_F(SsdpReflectorTest, DoesNotReflectMSearchWhenTargetHasNoSourceAddress) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();
    target.iface.SetV4(std::nullopt);  // e.g. the interface's v4 address vanished after construction

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());
    EXPECT_EQ(RegistrationCount(), base);  // no session / capture created
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, DoesNotReflectMSearchWhenResponseCaptureRegistrationFails) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();             // the two multicast registrations
    packet_dispatcher.fail_register_on_call = base + 1;  // fail the session's response-capture registration

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());      // capture failed before the reflect, so nothing is sent
    EXPECT_EQ(RegistrationCount(), base);  // no session; the reservation was rolled back
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, ReflectsUnicastResponseBackToSearcher) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // 1) An M-SEARCH (carrying the searcher's frame MAC) establishes the session and reveals port P.
    const auto searcher_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:02");
    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4(), searcher_mac));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    // 2) A device unicasts a 200 OK to our interface address on P (captured on target).
    const auto response = Bytes("HTTP/1.1 200 OK\r\nST: ssdp:all\r\nLOCATION: http://x/d.xml\r\n\r\n");
    Packet reply{
        .header = PacketHeader{
            .source = {IpAddress::FromV4Bytes(10, 0, 0, 5), SSDP_PORT},  // the responding device
            .dest = {*target.iface.SourceAddress(IpAddress::Family::V4), reserved_port},  // our target_if address
            .ttl = 4,
            .source_mac = *MacAddress::FromString("aa:bb:cc:dd:ee:01"),
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    // 3) It is injected to the original searcher on source, from our own address (no spoofing),
    //    addressed to the searcher's captured frame MAC, with the SSDP hop limit.
    ASSERT_EQ(source.sent.size(), 1u);
    const auto& out = source.sent.back();
    EXPECT_EQ(out.dst_ip, LoopbackFor(IpAddress::Family::V4));  // the M-SEARCH's source_ip (searcher)
    EXPECT_EQ(out.dst_port, SSDP_PORT);                          // the M-SEARCH's source_port
    EXPECT_EQ(out.dst_mac, searcher_mac);                        // unicast to the searcher's frame MAC
    EXPECT_EQ(out.payload, response);
    EXPECT_EQ(out.ttl, 2);
}

TEST_F(SsdpReflectorTest, LogsErrorWhenReflectingResponseFails) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    source.fail_send = true;  // injecting the response back to the searcher will fail
    const auto response = Bytes("HTTP/1.1 200 OK\r\n\r\n");
    Packet reply{
        .header = PacketHeader{
            .source = {IpAddress::FromV4Bytes(10, 0, 0, 5), SSDP_PORT},
            .dest = {*target.iface.SourceAddress(IpAddress::Family::V4), reserved_port},
            .ttl = 4,
        },
        .payload = response,
    };
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(target, reply);
    });

    EXPECT_TRUE(source.sent.empty());  // nothing reflected to the searcher
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, IgnoresUnicastResponseWithNoMatchingSession) {
    const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A stray 200 OK to a port we never reserved matches no capture registration, so it is never
    // dispatched to the handler and nothing reaches the searcher. (Deliver(packet) matches on filter
    // alone, ignoring which socket captured it.)
    const auto response = Bytes("HTTP/1.1 200 OK\r\n\r\n");
    Packet reply{
        .header = PacketHeader{
            .source = {IpAddress::FromV4Bytes(10, 0, 0, 5), SSDP_PORT},
            .dest = {*target.iface.SourceAddress(IpAddress::Family::V4), 55555},
            .ttl = 4,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(reply);
    EXPECT_TRUE(source.sent.empty());
}

TEST_F(SsdpReflectorTest, EvictionTimerKeepsUnexpiredSessions) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();  // multicast registrations only

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(RegistrationCount(), base + 1);  // + the session's response capture

    // MX=2 + 2s grace hasn't elapsed, so firing the eviction timer now keeps the session — and the
    // timer stays armed because the table is still non-empty.
    packet_dispatcher.dispatcher.FireTimers(std::chrono::steady_clock::now());
    EXPECT_EQ(RegistrationCount(), base + 1);
    EXPECT_EQ(packet_dispatcher.dispatcher.TimerCount(), 1u);
}

TEST_F(SsdpReflectorTest, ArmsEvictionTimerOnlyWhenSessionsExist) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    EXPECT_EQ(packet_dispatcher.dispatcher.TimerCount(), 0u);  // no in-flight searches -> no timer

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    EXPECT_EQ(packet_dispatcher.dispatcher.TimerCount(), 1u);  // armed for the first session
}

TEST_F(SsdpReflectorTest, EvictionTimerDropsExpiredSessionsAndDisarmsWhenEmpty) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(RegistrationCount(), base + 1);
    ASSERT_EQ(packet_dispatcher.dispatcher.TimerCount(), 1u);

    // MX=2 + 2s grace = 4s lifetime; firing 10s ahead drops the session (releasing its capture) and,
    // with the table now empty, the sweep disarms its own timer (a callback unregistering itself).
    packet_dispatcher.dispatcher.FireTimers(std::chrono::steady_clock::now() + std::chrono::seconds{10});
    EXPECT_EQ(RegistrationCount(), base);
    EXPECT_EQ(packet_dispatcher.dispatcher.TimerCount(), 0u);
}

TEST_F(SsdpReflectorTest, CapDropsSessionsBeyondTheLimit) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A full table of in-flight searches fills it; one more is dropped before reserving a port (no
    // reflect). Hoist the payload so each Packet's span outlives its Deliver (MakeSearch()'s temporary
    // would die at the semicolon otherwise).
    const auto search_payload = MakeSearch();
    for (uint16_t i = 0; i < SsdpReflector::MAX_SESSIONS + 1; ++i) {
        Packet search = MakePacket(search_payload, IpAddress::SsdpGroupV4());
        search.header.source.port = static_cast<uint16_t>(20000 + i);
        packet_dispatcher.Deliver(source, search);
    }
    EXPECT_EQ(target.sent.size(), SsdpReflector::MAX_SESSIONS);  // the one past the cap not reflected
}

// MAX_SESSIONS caps the whole sessions_ table, not each group's slice of it: distinct searchers spread
// across all three SSDP groups (v4, v6 link-local, v6 site-local) fill the table, and one more distinct
// searcher is dropped no matter which group it targets. A per-group cap would leave headroom in every
// group (round-robin puts only about a third in site-local) and wrongly accept it.
TEST_F(SsdpReflectorTest, SessionCapIsGlobalAcrossGroups) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
    ASSERT_TRUE(reflector.IsValid());

    const std::vector<IpAddress> groups{
        IpAddress::SsdpGroupV4(), IpAddress::SsdpGroupV6LinkLocal(), IpAddress::SsdpGroupV6SiteLocal()};
    const auto search_payload = MakeSearch();
    for (uint16_t i = 0; i < SsdpReflector::MAX_SESSIONS; ++i) {
        Packet search = MakePacket(search_payload, groups[i % groups.size()]);
        search.header.source.port = static_cast<uint16_t>(20000 + i);
        packet_dispatcher.Deliver(source, search);
    }
    ASSERT_EQ(target.sent.size(), SsdpReflector::MAX_SESSIONS);  // all distinct searchers reflected; table full

    // The overflow searcher targets v6 site-local, which so far holds only about a third of the table.
    Packet overflow = MakePacket(search_payload, IpAddress::SsdpGroupV6SiteLocal());
    overflow.header.source.port = static_cast<uint16_t>(20000 + SsdpReflector::MAX_SESSIONS);
    const std::string output = CaptureStdout([&] { packet_dispatcher.Deliver(source, overflow); });

    EXPECT_EQ(target.sent.size(), SsdpReflector::MAX_SESSIONS);  // not reflected: MakeSession returned nullopt before the reflect
    EXPECT_NE(output.find("cap reached"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, RetransmittedMSearchReusesOneSessionAndReflectsEach) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    // A client retransmits the same M-SEARCH (same source ip:port) for UDP reliability. Each is
    // reflected again (so a device that missed an earlier one still gets it), sharing one session.
    const auto search = MakeSearch();
    for (int i = 0; i < 3; ++i) {
        packet_dispatcher.Deliver(source, MakePacket(search, IpAddress::SsdpGroupV4()));
    }

    EXPECT_EQ(target.sent.size(), 3u);          // reflected every time
    EXPECT_EQ(RegistrationCount(), base + 1);   // but only one session / response capture
    const uint16_t port = target.sent.front().src_port;
    EXPECT_NE(port, SSDP_PORT);
    EXPECT_EQ(target.sent[1].src_port, port);   // all reflected from the same reserved port
    EXPECT_EQ(target.sent[2].src_port, port);
}

TEST_F(SsdpReflectorTest, DistinctClientsEachGetTheirOwnSession) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    // Two searchers (distinct source ports) get independent sessions, each with its own reserved port.
    const auto search = MakeSearch();
    Packet first = MakePacket(search, IpAddress::SsdpGroupV4());
    first.header.source.port = 40000;
    Packet second = MakePacket(search, IpAddress::SsdpGroupV4());
    second.header.source.port = 40001;
    packet_dispatcher.Deliver(source, first);
    packet_dispatcher.Deliver(source, second);

    ASSERT_EQ(target.sent.size(), 2u);
    EXPECT_EQ(RegistrationCount(), base + 2);                      // two sessions / captures
    EXPECT_NE(target.sent[0].src_port, target.sent[1].src_port);  // distinct reserved ports
}

TEST_F(SsdpReflectorTest, OneSearcherGetsASessionPerGroup) {
    // One reflector spans both IPv6 groups; each group's reply port is bound to a scope-matched
    // source (link-local for ff02::c, routable for ff05::c). A searcher hitting both groups must get
    // two sessions, or the second group's replies land on the first's unwatched reserved address.
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv6)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    const auto search = MakeSearch();
    packet_dispatcher.Deliver(source, MakePacket(search, IpAddress::SsdpGroupV6LinkLocal()));
    packet_dispatcher.Deliver(source, MakePacket(search, IpAddress::SsdpGroupV6SiteLocal()));

    ASSERT_EQ(target.sent.size(), 2u);
    EXPECT_EQ(RegistrationCount(), base + 2);                      // two sessions, not one reused
    EXPECT_NE(target.sent[0].src_port, target.sent[1].src_port);  // each on its own reserved port
    EXPECT_EQ(target.sent[0].dst_ip, IpAddress::SsdpGroupV6LinkLocal());
    EXPECT_EQ(target.sent[1].dst_ip, IpAddress::SsdpGroupV6SiteLocal());
}

TEST_F(SsdpReflectorTest, SameSearcherAndGroupReusesOneSession) {
    // The dedup key is (searcher, group): a retransmit to the *same* group is still one session, so
    // the group half of the key doesn't split genuine retransmits.
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv6)};
    ASSERT_TRUE(reflector.IsValid());
    const size_t base = RegistrationCount();

    const auto search = MakeSearch();
    for (int i = 0; i < 3; ++i) {
        packet_dispatcher.Deliver(source, MakePacket(search, IpAddress::SsdpGroupV6SiteLocal()));
    }

    EXPECT_EQ(target.sent.size(), 3u);         // reflected every time
    EXPECT_EQ(RegistrationCount(), base + 1);  // but one shared session
}

TEST_F(SsdpReflectorTest, LogsDefaultedMxAtInfoWhenSearchHasNoMx) {
    const ScopedMinLogLevel level{LogLevel::Info};
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A non-conformant M-SEARCH with no MX header: reflected anyway with the default window, and the
    // fallback flagged at INFO so it is visible in normal operation (the reflect line itself is DEBUG).
    const auto search_no_mx = Bytes(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n");
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(search_no_mx, IpAddress::SsdpGroupV4()));
    });

    EXPECT_EQ(target.sent.size(), 1u);  // reflected despite the missing MX
    EXPECT_NE(output.find("no/invalid MX"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, DoesNotInfoLogWhenMxIsPresent) {
    const ScopedMinLogLevel level{LogLevel::Info};
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    // A conformant M-SEARCH (MX present) is reflected at DEBUG only -- nothing about it at INFO.
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(output.find("M-SEARCH"), std::string::npos) << output;
}

// --- DIAL LOCATION rewrite. config.dial engages the proxy: a DIAL advertisement/response forwarded
// target->source has its LOCATION device authority spliced to a minted source_if (loopback) listener.

TEST_F(SsdpReflectorTest, DialRewritesAdvertisementLocationWhenEnabled) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_EQ(text.find(DIAL_DEVICE_AUTHORITY), std::string_view::npos) << text;  // device authority spliced out
    EXPECT_NE(text.find("http://127.0.0.1:"), std::string_view::npos) << text;    // to the minted listener
}

TEST_F(SsdpReflectorTest, DialRewritesPortLessAdvertisementLocation) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // A DIAL NOTIFY whose LOCATION omits the port (device on :80, legal per RFC 3986): the bare host is
    // still spliced to the minted source_if listener authority.
    const auto advertisement = Bytes(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "LOCATION: http://192.168.1.50/dd.xml\r\n"
        "NT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\n\r\n");
    packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_EQ(text.find("192.168.1.50"), std::string_view::npos) << text;       // bare host spliced out
    EXPECT_NE(text.find("http://127.0.0.1:"), std::string_view::npos) << text;  // to the minted listener
}

TEST_F(SsdpReflectorTest, DialRewritesUnicastResponseLocationWhenEnabled) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // An M-SEARCH establishes the session so the 200 OK has a searcher to be injected to.
    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    const auto response = MakeDialResponse();
    Packet reply{
        .header = PacketHeader{
            .source = {IpAddress::FromV4Bytes(10, 0, 0, 5), SSDP_PORT},
            .dest = {*target.iface.SourceAddress(IpAddress::Family::V4), reserved_port},
            .ttl = 4,
        },
        .payload = response,
    };
    packet_dispatcher.Deliver(target, reply);

    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_EQ(text.find(DIAL_DEVICE_AUTHORITY), std::string_view::npos) << text;
    EXPECT_NE(text.find("http://127.0.0.1:"), std::string_view::npos) << text;
}

TEST_F(SsdpReflectorTest, DialDisabledLeavesAdvertisementLocationUnchanged) {
    // config.dial defaults false: the DIAL URN is ignored and the LOCATION is forwarded byte-for-byte.
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());

    const auto advertisement = MakeDialAdvertisement();
    packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, advertisement);
}

TEST_F(SsdpReflectorTest, DialIgnoresNonDialAdvertisement) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // A plain rootdevice NOTIFY carrying a LOCATION but no DIAL service URN: forwarded verbatim.
    const auto advertisement = Bytes(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "LOCATION: http://192.168.1.50:8008/dd.xml\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n\r\n");
    packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, advertisement);
}

TEST_F(SsdpReflectorTest, DialAdvertisementWithoutLocationForwardedUnchanged) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // A DIAL-service NOTIFY with no LOCATION header: nothing to rewrite, so it is forwarded verbatim
    // (and no listener is minted — there is no device authority to mint one for).
    const auto advertisement = Bytes(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "NT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\n\r\n");
    packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, advertisement);
}

TEST_F(SsdpReflectorTest, DialRewriteChangesOnlyTheLocationAuthority) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    // Only the LOCATION authority span changed: "192.168.1.50:8008" -> "127.0.0.1:<ephemeral>". The exact
    // prefix (through "http://127.0.0.1:") and suffix (from "/dd.xml") prove every other byte is verbatim.
    EXPECT_TRUE(text.starts_with(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://127.0.0.1:")) << text;
    EXPECT_TRUE(text.ends_with(
        "/dd.xml\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\n\r\n")) << text;
}

TEST_F(SsdpReflectorTest, DialListenerBindsOnSourceInterfaceNotTarget) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    // A distinct, non-loopback target_if address: if the proxy mistakenly bound its listener on target_if it
    // would fail to bind and forward the LOCATION unchanged. A successful loopback rewrite proves the listener
    // binds on source_if (device on target_if, client on source_if).
    target.iface.SetV4(IpAddress::FromV4Bytes(10, 9, 9, 9));
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));

    ASSERT_EQ(source.sent.size(), 1u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_EQ(text.find(DIAL_DEVICE_AUTHORITY), std::string_view::npos) << text;  // rewritten -> listener bound
    EXPECT_NE(text.find("http://127.0.0.1:"), std::string_view::npos) << text;    // on source_if's address
}

// A source-interface address CHANGE (not just a teardown/restore of the same address) must route through
// SsdpReflector::OnInterfaceChanged into the DIAL proxy: the listener bound to the OLD address is dropped,
// and the next reflected advertisement re-mints one on the NEW address. Without the wiring + drop, the proxy
// would keep advertising a LOCATION on the now-dead old address. The existing DialProxySurvivesAFamilyTeardown
// only toggles the TARGET interface, so the source-bound listener is never stale there — this is the
// source-side path. Mirrors DialListenerBindsOnSourceInterfaceNotTarget's loopback-rewrite observation; a
// distinct second loopback address isn't bindable on every platform (macOS routes only 127.0.0.1 to lo), so
// skip where it can't bind — the Linux docker gate still exercises it.
TEST_F(SsdpReflectorTest, DialReMintsListenerOnSourceAddressChange) {
    const auto changed = IpAddress::FromString("127.0.0.2").value();
    FakeInterface bind_probe;
    bind_probe.SetV4(changed);
    if (!TcpSocket::Listen(bind_probe, IpAddress::Family::V4)) {
        GTEST_SKIP() << "127.0.0.2 is not bindable on this platform";
    }

    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // First advertisement: the listener mints on source_if's original 127.0.0.1.
    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_NE(AsText(source.sent.back().payload).find("http://127.0.0.1:"), std::string_view::npos)
        << AsText(source.sent.back().payload);

    // source_if's V4 source changes; the reflector broadcast must carry that into the proxy.
    source.iface.SetV4(changed);
    reflector.OnInterfaceChanged();

    // Second advertisement: the proxy re-mints on the NEW address — proving the stale listener was dropped and
    // the SsdpReflector -> DialProxy wiring delivered the change (a surviving old listener would still say .1).
    packet_dispatcher.Deliver(target, MakePacket(MakeDialAdvertisement(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(source.sent.size(), 2u);
    const auto text = AsText(source.sent.back().payload);
    EXPECT_NE(text.find("http://127.0.0.2:"), std::string_view::npos) << text;  // re-minted on the new address
    EXPECT_EQ(text.find("http://127.0.0.1:"), std::string_view::npos) << text;  // not the old (dropped) one
}

TEST_F(SsdpReflectorTest, DialForwardsLocationUnchangedWhenListenerMintFails) {
    const ScopedMinLogLevel level{LogLevel::Info};
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());
    source.iface.SetV4(std::nullopt);  // no source_if V4 address -> EnsureDiscoveryListener cannot bind a listener

    const auto advertisement = MakeDialAdvertisement();
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(target, MakePacket(advertisement, IpAddress::SsdpGroupV4()));
    });

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, advertisement);            // forwarded unchanged (benign fallback)
    EXPECT_NE(output.find("no listener"), std::string::npos) << output;  // surfaced at INFO
}

// Same mint-failure fallback as DialForwardsLocationUnchangedWhenListenerMintFails, but on the unicast
// response path (OnUnicastResponse's RewriteDialLocation call) rather than the advertisement path — the
// two call sites are independent branches that could regress separately.
TEST_F(SsdpReflectorTest, DialForwardsResponseLocationUnchangedWhenListenerMintFails) {
    const ScopedMinLogLevel level{LogLevel::Info};
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // An M-SEARCH establishes the session so the 200 OK has a searcher to be injected to.
    packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    ASSERT_EQ(target.sent.size(), 1u);
    const uint16_t reserved_port = target.sent.back().src_port;

    source.iface.SetV4(std::nullopt);  // no source_if V4 address -> EnsureDiscoveryListener cannot bind a listener

    const auto response = MakeDialResponse();
    Packet reply{
        .header = PacketHeader{
            .source = {IpAddress::FromV4Bytes(10, 0, 0, 5), SSDP_PORT},
            .dest = {*target.iface.SourceAddress(IpAddress::Family::V4), reserved_port},
            .ttl = 4,
        },
        .payload = response,
    };
    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(target, reply);
    });

    ASSERT_EQ(source.sent.size(), 1u);
    EXPECT_EQ(source.sent.back().payload, response);                     // forwarded unchanged (benign fallback)
    EXPECT_NE(output.find("no listener"), std::string::npos) << output;  // surfaced at INFO
}

TEST_F(SsdpReflectorTest, LogsErrorWhenReflectingAdvertisementFails) {
    SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
    ASSERT_TRUE(reflector.IsValid());
    source.fail_send = true;  // re-emitting the advertisement to source will fail

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(target, MakePacket(MakeAdvertisement(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(source.sent.empty());  // nothing reflected
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(SsdpReflectorTest, DoesNotRewriteDialContentInAnMSearch) {
    auto config = MakeConfig(AddressFamily::IPv4);
    config.dial = true;
    SsdpReflector reflector{packet_dispatcher, source, target, config};
    ASSERT_TRUE(reflector.IsValid());

    // DIAL rewriting applies only to the target->source advertisement/response paths. An M-SEARCH
    // (source->target) carrying DIAL-like content is reflected verbatim — OnSourcePacket never rewrites.
    const auto search = Bytes(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\nLOCATION: http://192.168.1.50:8008/dd.xml\r\n\r\n");
    packet_dispatcher.Deliver(source, MakePacket(search, IpAddress::SsdpGroupV4()));

    ASSERT_EQ(target.sent.size(), 1u);
    EXPECT_EQ(target.sent.back().payload, search);  // reflected verbatim, no DIAL rewrite
}

} // namespace reflector
