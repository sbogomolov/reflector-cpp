#include "reflector/ssdp_reflector.h"
#include "reflector/ip_address.h"
#include "reflector/mac_address.h"
#include "mocks/fake_link_socket.h"
#include "mocks/fake_packet_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <chrono>
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
    target.source_v4 = std::nullopt;  // e.g. the interface's v4 address vanished after construction

    const std::string output = CaptureStdout([&] {
        packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
    });

    EXPECT_TRUE(target.sent.empty());      // nothing reflected
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
            .source_ip = IpAddress::FromV4Bytes(10, 0, 0, 5),         // the responding device
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),  // our target_if address
            .source_port = SSDP_PORT,
            .dest_port = reserved_port,
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
            .source_ip = IpAddress::FromV4Bytes(10, 0, 0, 5),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = SSDP_PORT,
            .dest_port = reserved_port,
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
            .source_ip = IpAddress::FromV4Bytes(10, 0, 0, 5),
            .dest_ip = *target.SourceAddress(IpAddress::Family::V4),
            .source_port = SSDP_PORT,
            .dest_port = 55555,
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

    // 32 in-flight searches fill the table; the 33rd is dropped before reserving a port (no reflect).
    // Hoist the payload so each Packet's span outlives its Deliver (MakeSearch()'s temporary would
    // die at the semicolon otherwise).
    const auto search_payload = MakeSearch();
    for (uint16_t i = 0; i < 33; ++i) {
        Packet search = MakePacket(search_payload, IpAddress::SsdpGroupV4());
        search.header.source_port = static_cast<uint16_t>(20000 + i);
        packet_dispatcher.Deliver(source, search);
    }
    EXPECT_EQ(target.sent.size(), 32u);  // 33rd search not reflected
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
    first.header.source_port = 40000;
    Packet second = MakePacket(search, IpAddress::SsdpGroupV4());
    second.header.source_port = 40001;
    packet_dispatcher.Deliver(source, first);
    packet_dispatcher.Deliver(source, second);

    ASSERT_EQ(target.sent.size(), 2u);
    EXPECT_EQ(RegistrationCount(), base + 2);                      // two sessions / captures
    EXPECT_NE(target.sent[0].src_port, target.sent[1].src_port);  // distinct reserved ports
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

} // namespace reflector
