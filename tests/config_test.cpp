#include "reflector/config.h"
#include "reflector/logger.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {
using namespace reflector;

std::filesystem::path MakeTempConfigPath(std::string_view test_name) {
    const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto filename = std::string{"reflector_config_test_"} + std::string{test_name} + "_" + std::to_string(timestamp) + ".toml";
    return std::filesystem::temp_directory_path() / filename;
}

std::string TomlWithLogLevel(std::string_view log_level) {
    std::string toml;
    toml += "log_level = \"";
    toml += log_level;
    toml += R"("

[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)";
    return toml;
}

} // namespace

namespace reflector {

// --- struct-level Verify / policy (independent of the TOML format) ---

TEST(ConfigTest, AddressFamilyRuntimePolicy) {
    struct Case {
        AddressFamily address_family;
        bool uses_v4;
        bool uses_v6;
        bool requires_v4;
        bool requires_v6;
    };

    const std::vector<Case> cases{
        {AddressFamily::Default, true, true, true, false},
        {AddressFamily::Dual, true, true, true, true},
        {AddressFamily::IPv4, true, false, true, false},
        {AddressFamily::IPv6, false, true, false, true},
    };

    for (const auto& c : cases) {
        WolConfig wol_config;
        wol_config.address_family = c.address_family;
        EXPECT_EQ(wol_config.UsesIPv4(), c.uses_v4) << std::format("{}", c.address_family);
        EXPECT_EQ(wol_config.UsesIPv6(), c.uses_v6) << std::format("{}", c.address_family);
        EXPECT_EQ(wol_config.RequiresIPv4(), c.requires_v4) << std::format("{}", c.address_family);
        EXPECT_EQ(wol_config.RequiresIPv6(), c.requires_v6) << std::format("{}", c.address_family);
    }
}

TEST(ConfigTest, VerifyRejectsPortZero) {
    const auto mac = MacAddress::FromString("00:11:22:33:44:55");
    ASSERT_TRUE(mac.has_value()) << mac.error().Message();
    const auto wol_config = WolConfig{
        .name = "a",
        .mac = *mac,
        .source_if = "eth0",
        .target_if = "eth1",
        .ports = {0},
    };

    EXPECT_TRUE(wol_config.Verify().has_value());
}

TEST(ConfigTest, VerifyAcceptsMissingMac) {
    const auto wol_config = WolConfig{
        .name = "a",
        .mac = std::nullopt,
        .source_if = "eth0",
        .target_if = "eth1",
    };

    EXPECT_FALSE(wol_config.Verify().has_value());
}

TEST(ConfigTest, VerifyRejectsDuplicatePorts) {
    const auto mac = MacAddress::FromString("00:11:22:33:44:55");
    ASSERT_TRUE(mac.has_value()) << mac.error().Message();
    const auto wol_config = WolConfig{
        .name = "a",
        .mac = *mac,
        .source_if = "eth0",
        .target_if = "eth1",
        .ports = {7, 7},
    };

    EXPECT_TRUE(wol_config.Verify().has_value());
}

// --- entry parsing and protocol expansion ---

TEST(ConfigTest, ParsesSingleProtocolEntry) {
    const auto config = Config::FromString(R"(
[tv]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    EXPECT_TRUE(config->MdnsConfigs().empty());
    EXPECT_TRUE(config->SsdpConfigs().empty());

    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.name, "tv");
    ASSERT_TRUE(wol.mac.has_value());
    EXPECT_EQ(*wol.mac, *MacAddress::FromString("00:11:22:33:44:55"));
    EXPECT_EQ(wol.source_if, "eth0");
    EXPECT_EQ(wol.target_if, "eth1");
    EXPECT_EQ(wol.ports, (std::vector<uint16_t>{7, 9}));  // default
    EXPECT_EQ(wol.address_family, AddressFamily::Default);
}

TEST(ConfigTest, ParsesMultipleEntries) {
    const auto config = Config::FromString(R"(
[a]
mac = "00:00:00:00:00:0a"
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:00:00:00:00:0b"
source_if = "eth2"
target_if = "eth3"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 2);
    // Entry order is preserved within the protocol vector.
    EXPECT_EQ(config->WolConfigs()[0].name, "a");
    EXPECT_EQ(config->WolConfigs()[0].source_if, "eth0");
    EXPECT_EQ(config->WolConfigs()[1].name, "b");
    EXPECT_EQ(config->WolConfigs()[1].source_if, "eth2");
}

TEST(ConfigTest, ParsesExplicitWolPorts) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7, 9, 4000]
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().ports, (std::vector<uint16_t>{7, 9, 4000}));
}

TEST(ConfigTest, ParsesAddressFamily) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv6"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().address_family, AddressFamily::IPv6);
}

TEST(ConfigTest, ExpandsAllThreeProtocolsFromOneEntry) {
    const auto config = Config::FromString(R"(
[tv]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
wol = true
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    ASSERT_EQ(config->MdnsConfigs().size(), 1);
    ASSERT_EQ(config->SsdpConfigs().size(), 1);
    EXPECT_EQ(config->WolConfigs().front().name, "tv");
    EXPECT_EQ(config->MdnsConfigs().front().name, "tv");
    EXPECT_EQ(config->SsdpConfigs().front().name, "tv");
}

TEST(ConfigTest, ExpandsWolAndMdns) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1);
    EXPECT_EQ(config->MdnsConfigs().size(), 1);
    EXPECT_TRUE(config->SsdpConfigs().empty());
}

TEST(ConfigTest, ExpandsWolAndSsdp) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1);
    EXPECT_TRUE(config->MdnsConfigs().empty());
    EXPECT_EQ(config->SsdpConfigs().size(), 1);
}

TEST(ConfigTest, ExpandsMdnsAndSsdp) {
    const auto config = Config::FromString(R"(
[disc]
source_if = "lan"
target_if = "iot"
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->WolConfigs().empty());
    EXPECT_EQ(config->MdnsConfigs().size(), 1);
    EXPECT_EQ(config->SsdpConfigs().size(), 1);
}

TEST(ConfigTest, SharedFieldsPropagateToEachEnabledProtocol) {
    const auto config = Config::FromString(R"(
[tv]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
wol = true
wol_ports = [7, 9, 4000]
mdns = true
ssdp = true
address_family = "dual"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    ASSERT_EQ(config->MdnsConfigs().size(), 1);
    ASSERT_EQ(config->SsdpConfigs().size(), 1);
    const auto mac = *MacAddress::FromString("00:11:22:33:44:55");

    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.mac, mac);
    EXPECT_EQ(wol.source_if, "lan");
    EXPECT_EQ(wol.target_if, "iot");
    EXPECT_EQ(wol.address_family, AddressFamily::Dual);
    EXPECT_EQ(wol.ports, (std::vector<uint16_t>{7, 9, 4000}));  // wol_ports reaches only WoL

    const auto& mdns = config->MdnsConfigs().front();
    EXPECT_EQ(mdns.mac, mac);
    EXPECT_EQ(mdns.source_if, "lan");
    EXPECT_EQ(mdns.target_if, "iot");
    EXPECT_EQ(mdns.address_family, AddressFamily::Dual);

    const auto& ssdp = config->SsdpConfigs().front();
    EXPECT_EQ(ssdp.mac, mac);
    EXPECT_EQ(ssdp.source_if, "lan");
    EXPECT_EQ(ssdp.target_if, "iot");
    EXPECT_EQ(ssdp.address_family, AddressFamily::Dual);
}

TEST(ConfigTest, NetworkEntryHasNoMac) {
    const auto config = Config::FromString(R"(
[net]
source_if = "lan"
target_if = "iot"
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_FALSE(config->MdnsConfigs().front().mac.has_value());
    EXPECT_FALSE(config->SsdpConfigs().front().mac.has_value());
}

TEST(ConfigTest, AcceptsMissingMac) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_FALSE(config->WolConfigs().front().mac.has_value());
}

// --- log_level ---

TEST(ConfigTest, LogLevelDefaultsToInfo) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Info);
}

TEST(ConfigTest, ParsesLogLevelDebug) {
    const auto config = Config::FromString(TomlWithLogLevel("debug"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

TEST(ConfigTest, ParsesLogLevelInfo) {
    const auto config = Config::FromString(TomlWithLogLevel("info"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Info);
}

TEST(ConfigTest, ParsesLogLevelWarning) {
    const auto config = Config::FromString(TomlWithLogLevel("warning"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Warning);
}

TEST(ConfigTest, ParsesLogLevelError) {
    const auto config = Config::FromString(TomlWithLogLevel("error"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Error);
}

TEST(ConfigTest, ParsesLogLevelCaseInsensitive) {
    const auto config = Config::FromString(TomlWithLogLevel("DeBuG"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

TEST(ConfigTest, ParsesLogLevelAlongsideEntries) {
    const auto config = Config::FromString(R"(
log_level = "debug"

[tv]
source_if = "lan"
target_if = "iot"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
    EXPECT_EQ(config->WolConfigs().size(), 1);
}

TEST(ConfigTest, RejectsUnknownLogLevel) {
    EXPECT_FALSE(Config::FromString(TomlWithLogLevel("verbose")).has_value());
}

TEST(ConfigTest, RejectsNonStringLogLevel) {
    EXPECT_FALSE(Config::FromString(R"(
log_level = 5

[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

// --- FromFile and malformed input ---

TEST(ConfigTest, RejectsEmptyDocument) {
    EXPECT_FALSE(Config::FromString("").has_value());
}

TEST(ConfigTest, RejectsMalformedToml) {
    EXPECT_FALSE(Config::FromString("[tv\n").has_value());
}

TEST(ConfigTest, MalformedTomlErrorIncludesLineAndColumn) {
    const auto config = Config::FromString("\n\nname = ===\n");
    ASSERT_FALSE(config.has_value());
    const auto message = config.error().Message();
    EXPECT_NE(message.find("line"), std::string::npos) << "message: " << message;
    EXPECT_NE(message.find("column"), std::string::npos) << "message: " << message;
}

TEST(ConfigTest, FromFileMissingFails) {
    const auto path = MakeTempConfigPath("missing");

    std::error_code ec;
    std::filesystem::remove(path, ec);

    const auto path_string = path.string();
    EXPECT_FALSE(Config::FromFile(path_string.c_str()).has_value());
}

TEST(ConfigTest, FromFileParsesConfig) {
    const auto path = MakeTempConfigPath("valid");
    {
        std::ofstream file{path};
        ASSERT_TRUE(file);
        file << R"(
[file]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)";
    }

    const auto path_string = path.string();
    const auto config = Config::FromFile(path_string.c_str());

    std::error_code ec;
    std::filesystem::remove(path, ec);

    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);

    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.name, "file");
    ASSERT_TRUE(wol.mac.has_value());
    EXPECT_EQ(*wol.mac, *MacAddress::FromString("00:11:22:33:44:55"));
    EXPECT_EQ(wol.source_if, "eth0");
    EXPECT_EQ(wol.target_if, "eth1");
}

// --- top-level structure ---

TEST(ConfigTest, RejectsConfigWithNoReflectors) {
    EXPECT_FALSE(Config::FromString(R"(log_level = "info")").has_value());
}

TEST(ConfigTest, RejectsUnknownTopLevelScalar) {
    EXPECT_FALSE(Config::FromString(R"(
log_levle = "debug"

[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

// --- entry field validation ---

TEST(ConfigTest, RejectsEntryEnablingNoProtocol) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
)").has_value());
}

TEST(ConfigTest, RejectsWolPortsWithoutWol) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
mdns = true
wol_ports = [7, 9]
)").has_value());
}

TEST(ConfigTest, RejectsNonBooleanProtocolFlag) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = "yes"
)").has_value());
}

TEST(ConfigTest, RejectsMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth0"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyName) {
    // The entry name is the table key; an empty key fails the per-protocol Verify (name required).
    EXPECT_FALSE(Config::FromString(R"(
[""]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsUnknownEntryField) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
extra = "x"
)").has_value());
}

TEST(ConfigTest, RejectsNonStringField) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = 123
target_if = "eth1"
wol = true
)").has_value());
}

// --- MAC validation ---

TEST(ConfigTest, RejectsInvalidMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = "not-a-mac"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsTooShortMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = "00:11:22:33:44"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsNonHexMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = "GG:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsDashSeparatedMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = "00-11-22-33-44-55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = ""
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsUppercaseMac) {
    EXPECT_TRUE(Config::FromString(R"(
[tv]
mac = "B0:37:95:C5:60:BE"
source_if = "en0"
target_if = "lo0"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsLowercaseMac) {
    EXPECT_TRUE(Config::FromString(R"(
[tv]
mac = "b0:37:95:c5:60:be"
source_if = "en0"
target_if = "lo0"
wol = true
)").has_value());
}

// --- address_family validation ---

TEST(ConfigTest, RejectsUnknownAddressFamily) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipx"
)").has_value());
}

TEST(ConfigTest, RejectsNonStringAddressFamily) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = 4
)").has_value());
}

// --- wol_ports validation ---

TEST(ConfigTest, RejectsEmptyPortsArray) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = []
)").has_value());
}

TEST(ConfigTest, RejectsNonArrayPorts) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = "7"
)").has_value());
}

TEST(ConfigTest, RejectsNonIntegerPort) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = ["7"]
)").has_value());
}

TEST(ConfigTest, RejectsPortZeroFromToml) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [0]
)").has_value());
}

TEST(ConfigTest, RejectsDuplicatePorts) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7, 9, 7]
)").has_value());
}

TEST(ConfigTest, RejectsOutOfRangePort) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [65536]
)").has_value());
}

// --- per-protocol dedup across entries (WoL) ---

TEST(ConfigTest, RejectsDuplicateEntryName) {
    // TOML itself rejects two tables with the same name, which is why the parser needs no name
    // dedup of its own (see the comment on AppendWol).
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true

[tv]
source_if = "eth2"
target_if = "eth3"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsDuplicateMacSourceTargetTriple) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsDuplicateUnfilteredSourceTargetRule) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsSpecificRuleOverlappedByUnfilteredRule) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsSameMacWithDifferentTargets) {
    const auto config = Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth2"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDisjointPorts) {
    const auto config = Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7]

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [9]
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDifferentSources) {
    const auto config = Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:55"
source_if = "eth2"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDifferentTargets) {
    const auto config = Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth2"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

// An ipv4-only and an ipv6-only rule never handle the same packet, so an otherwise identical pair
// is not a duplicate — it is just the long form of one "dual" rule.
TEST(ConfigTest, AcceptsIdenticalRuleWithDisjointAddressFamilies) {
    const auto config = Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv4"

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv6"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

// "default" handles IPv4 too, so it overlaps an ipv4-only rule on the same triple.
TEST(ConfigTest, RejectsOverlappingRuleWhenDefaultCoversIpv4) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "default"

[b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv4"
)").has_value());
}

// --- per-protocol dedup across entries (mDNS / SSDP) and cross-protocol independence ---

TEST(ConfigTest, RejectsDuplicateMdnsRuleAcrossEntries) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true

[b]
source_if = "lan"
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsDuplicateSsdpRuleAcrossEntries) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
source_if = "lan"
target_if = "iot"
ssdp = true
)").has_value());
}

TEST(ConfigTest, AcceptsOverlappingDifferentProtocolsAcrossEntries) {
    // Same source/target, but one entry does WoL and the other mDNS — different protocol vectors,
    // so no dedup collision.
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
wol = true

[b]
source_if = "lan"
target_if = "iot"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1);
    EXPECT_EQ(config->MdnsConfigs().size(), 1);
}

TEST(ConfigTest, AcceptsDisjointEntries) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
source_if = "lan"
target_if = "guest"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}

// --- single-service expansion for mdns / ssdp (completes the 0/1/2/3 matrix) ---

TEST(ConfigTest, ExpandsMdnsOnly) {
    const auto config = Config::FromString(R"(
[disc]
source_if = "lan"
target_if = "iot"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->WolConfigs().empty());
    ASSERT_EQ(config->MdnsConfigs().size(), 1);
    EXPECT_TRUE(config->SsdpConfigs().empty());
    const auto& mdns = config->MdnsConfigs().front();
    EXPECT_EQ(mdns.name, "disc");
    EXPECT_EQ(mdns.source_if, "lan");
    EXPECT_EQ(mdns.target_if, "iot");
    EXPECT_EQ(mdns.address_family, AddressFamily::Default);
    EXPECT_FALSE(mdns.mac.has_value());
}

TEST(ConfigTest, ExpandsSsdpOnly) {
    const auto config = Config::FromString(R"(
[disc]
source_if = "lan"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->WolConfigs().empty());
    EXPECT_TRUE(config->MdnsConfigs().empty());
    ASSERT_EQ(config->SsdpConfigs().size(), 1);
    const auto& ssdp = config->SsdpConfigs().front();
    EXPECT_EQ(ssdp.name, "disc");
    EXPECT_EQ(ssdp.source_if, "lan");
    EXPECT_EQ(ssdp.target_if, "iot");
    EXPECT_EQ(ssdp.address_family, AddressFamily::Default);
    EXPECT_FALSE(ssdp.mac.has_value());
}

// --- protocol enable flags ---

TEST(ConfigTest, ExplicitFalseFlagDoesNotEnable) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = false
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->WolConfigs().empty());
    EXPECT_EQ(config->MdnsConfigs().size(), 1);
}

TEST(ConfigTest, AllExplicitFalseRejected) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = false
mdns = false
ssdp = false
)").has_value());
}

// --- wol_ports boundaries and replacement ---

TEST(ConfigTest, WolPortsFullyReplaceDefaults) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [40000]
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().ports, (std::vector<uint16_t>{40000}));  // not {7, 9, 40000}
}

TEST(ConfigTest, AcceptsMaxPort) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [65535]
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().ports, (std::vector<uint16_t>{65535}));
}

TEST(ConfigTest, RejectsNegativePort) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [-1]
)").has_value());
}

// --- top-level key classification ---

TEST(ConfigTest, LogLevelAsTableIsEntryNotScalar) {
    // A [log_level] table is classified as an entry (table wins over the scalar name), so it is sent
    // to ReadEntry and rejected for enabling no protocol — not parsed as the log_level setting.
    EXPECT_FALSE(Config::FromString(R"(
[log_level]
source_if = "eth0"
target_if = "eth1"
)").has_value());
}

// --- non-string field types ---

TEST(ConfigTest, RejectsNonStringMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
mac = 123
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsNonStringTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = 123
wol = true
)").has_value());
}

// --- address_family enumerator coverage (default/ipv6/dual are covered elsewhere) ---

TEST(ConfigTest, ParsesAddressFamilyIpv4) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv4"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().address_family, AddressFamily::IPv4);
}

// --- per-protocol Verify reached through the parser (AppendMdns / AppendSsdp call their own
//     MdnsConfig::Verify / SsdpConfig::Verify, independent of WoL) ---

TEST(ConfigTest, RejectsMdnsMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsMdnsMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
source_if = "lan"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsMdnsSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
source_if = "lan"
target_if = "lan"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
target_if = "iot"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
source_if = "lan"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[disc]
source_if = "lan"
target_if = "lan"
ssdp = true
)").has_value());
}

// --- WoL dedup: branches not exercised by the migrated matrix ---

TEST(ConfigTest, AcceptsDistinctConcreteMacsSameTriple) {
    // Two different concrete MACs on the same source/target/ports do not collide: MacSelectionsOverlap
    // is false only when both are set and unequal.
    const auto config = Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true

[b]
mac = "00:11:22:33:44:66"
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, RejectsPartialPortOverlap) {
    // Sharing a single port (9) is enough to collide — PortsOverlap is any-shared-element, not set
    // equality.
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7, 9]

[b]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [9, 40000]
)").has_value());
}

// --- mDNS dedup matrix (AppendMdns is independent of AppendWol) ---

TEST(ConfigTest, RejectsMdnsDuplicateMacTriple) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
mdns = true

[b]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsMdnsSpecificOverlappedByUnfiltered) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true

[b]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, AcceptsMdnsDistinctMacs) {
    const auto config = Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
mdns = true

[b]
mac = "00:11:22:33:44:66"
source_if = "lan"
target_if = "iot"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MdnsConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsMdnsDifferentSources) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true

[b]
source_if = "lan2"
target_if = "iot"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MdnsConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsMdnsDifferentTargets) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true

[b]
source_if = "lan"
target_if = "iot2"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MdnsConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsMdnsDisjointAddressFamilies) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true
address_family = "ipv4"

[b]
source_if = "lan"
target_if = "iot"
mdns = true
address_family = "ipv6"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MdnsConfigs().size(), 2);
}

TEST(ConfigTest, RejectsMdnsDefaultOverlapsIpv4) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true
address_family = "default"

[b]
source_if = "lan"
target_if = "iot"
mdns = true
address_family = "ipv4"
)").has_value());
}

// --- SSDP dedup matrix (AppendSsdp is independent of AppendWol / AppendMdns) ---

TEST(ConfigTest, RejectsSsdpDuplicateMacTriple) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpSpecificOverlappedByUnfiltered) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
ssdp = true
)").has_value());
}

TEST(ConfigTest, AcceptsSsdpDistinctMacs) {
    const auto config = Config::FromString(R"(
[a]
mac = "00:11:22:33:44:55"
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
mac = "00:11:22:33:44:66"
source_if = "lan"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsSsdpDifferentSources) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
source_if = "lan2"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsSsdpDifferentTargets) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
source_if = "lan"
target_if = "iot2"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsSsdpDisjointAddressFamilies) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "ipv4"

[b]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "ipv6"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}

TEST(ConfigTest, RejectsSsdpDefaultOverlapsIpv4) {
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "default"

[b]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "ipv4"
)").has_value());
}

// --- SSDP dial flag: struct-level Verify + formatter, and the TOML parse ---

TEST(ConfigTest, SsdpVerifyAcceptsDialWithSsdpDefaultFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot", .dial = true,
    };  // default family has IPv4
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyAcceptsDialWithDualFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::Dual, .dial = true,
    };
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyAcceptsDialWithIpv4Family) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv4, .dial = true,
    };
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpVerifyRejectsDialWithIpv6OnlyFamily) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv6, .dial = true,
    };  // DIAL is IPv4-only: an ipv6-only entry has no IPv4 address to bind
    const auto error = ssdp.Verify();
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->Message().find("dial"), std::string::npos) << error->Message();
}

TEST(ConfigTest, SsdpVerifyAcceptsDialFalseWithIpv6) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv6, .dial = false,
    };  // the ipv6 rejection is gated on dial being on
    EXPECT_FALSE(ssdp.Verify().has_value());
}

TEST(ConfigTest, SsdpFormatterPrintsDial) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = std::nullopt, .source_if = "lan", .target_if = "iot", .dial = true,
    };
    EXPECT_NE(std::format("{}", ssdp).find("dial: true"), std::string::npos);
}

TEST(ConfigTest, ParsesSsdpDialFlagFromToml) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = true
)");
    ASSERT_TRUE(config.has_value());
    ASSERT_EQ(config->SsdpConfigs().size(), 1u);
    EXPECT_TRUE(config->SsdpConfigs()[0].dial);
}

TEST(ConfigTest, SsdpDialDefaultsFalse) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value());
    ASSERT_EQ(config->SsdpConfigs().size(), 1u);
    EXPECT_FALSE(config->SsdpConfigs()[0].dial);
}

TEST(ConfigTest, RejectsDialWithoutSsdp) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
dial = true
)");
    ASSERT_FALSE(config.has_value());  // dial requires ssdp (rejected at parse, no config appended)
    EXPECT_NE(config.error().Message().find("ssdp"), std::string::npos) << config.error().Message();
}

TEST(ConfigTest, RejectsNonBooleanDial) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
dial = "yes"
)");
    ASSERT_FALSE(config.has_value());
    EXPECT_NE(config.error().Message().find("dial"), std::string::npos) << config.error().Message();
}

TEST(ConfigTest, RejectsDialWithIpv6OnlyFamilyFromToml) {
    // The IPv4-only rejection (struct-level Verify is tested separately) also fires through the parser:
    // AppendSsdp runs Verify before appending, so a dial+ipv6 entry is rejected, not stored.
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "ipv6"
dial = true
)");
    ASSERT_FALSE(config.has_value());
    EXPECT_NE(config.error().Message().find("dial"), std::string::npos) << config.error().Message();
}

}  // namespace reflector
