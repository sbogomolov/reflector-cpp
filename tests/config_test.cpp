#include "reflector/config/config.h"
#include "reflector/logger.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
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

[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)";
    return toml;
}

// Builds an EnvVar list from literal key/value pairs. The views reference the string literals (static
// storage), so the returned vector stays valid for as long as it lives.
std::vector<EnvVar> Env(std::initializer_list<std::pair<std::string_view, std::string_view>> vars) {
    std::vector<EnvVar> env;
    env.reserve(vars.size());
    for (const auto& [key, value] : vars) {
        env.push_back(EnvVar{key, value});
    }
    return env;
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

TEST(ConfigTest, VerifyRejectsEmptyPorts) {
    // Reachable only by a direct caller: the parser defaults ports to {7,9} and rejects an empty
    // wol_ports array before assignment, so this branch has no TOML/env path.
    const auto wol_config = WolConfig{
        .name = "a",
        .mac = std::nullopt,
        .source_if = "eth0",
        .target_if = "eth1",
        .ports = {},
    };

    EXPECT_TRUE(wol_config.Verify().has_value());
}

// --- entry parsing and protocol expansion ---

TEST(ConfigTest, ParsesSingleProtocolEntry) {
    const auto config = Config::FromString(R"(
[reflectors.tv]
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
[reflectors.a]
mac = "00:00:00:00:00:0a"
source_if = "eth0"
target_if = "eth1"
wol = true

[reflectors.b]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.disc]
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
[reflectors.tv]
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
[reflectors.net]
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
[reflectors.tv]
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
[reflectors.tv]
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

[reflectors.tv]
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

[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

// --- file reading and malformed input ---

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

TEST(ConfigTest, ReadFileToStringMissingFails) {
    const auto path = MakeTempConfigPath("missing");

    std::error_code ec;
    std::filesystem::remove(path, ec);

    const auto path_string = path.string();
    EXPECT_FALSE(Config::ReadFileToString(path_string.c_str()).has_value());
}

TEST(ConfigTest, ReadsAndParsesFileConfig) {
    const auto path = MakeTempConfigPath("valid");
    {
        std::ofstream file{path};
        ASSERT_TRUE(file);
        file << R"(
[reflectors.file]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)";
    }

    const auto path_string = path.string();
    const auto contents = Config::ReadFileToString(path_string.c_str());

    std::error_code ec;
    std::filesystem::remove(path, ec);

    ASSERT_TRUE(contents.has_value()) << contents.error().Message();
    const auto config = Config::FromString(*contents);
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

[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

// --- entry field validation ---

TEST(ConfigTest, RejectsEntryEnablingNoProtocol) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
)").has_value());
}

TEST(ConfigTest, RejectsWolPortsWithoutWol) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
mdns = true
wol_ports = [7, 9]
)").has_value());
}

TEST(ConfigTest, RejectsNonBooleanProtocolFlag) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = "yes"
)").has_value());
}

TEST(ConfigTest, RejectsMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth0"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyName) {
    // The entry name is the table key; an empty key fails the per-protocol Verify (name required).
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.""]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyNameMdns) {
    // Same invariant via MdnsConfig::Verify (empty name reaches a different protocol's check).
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.""]
source_if = "eth0"
target_if = "eth1"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyNameSsdp) {
    // Same invariant via SsdpConfig::Verify.
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.""]
source_if = "eth0"
target_if = "eth1"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsUnknownEntryField) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
extra = "x"
)").has_value());
}

TEST(ConfigTest, RejectsNonStringField) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = 123
target_if = "eth1"
wol = true
)").has_value());
}

// --- MAC validation ---

TEST(ConfigTest, RejectsInvalidMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = "not-a-mac"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsTooShortMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = "00:11:22:33:44"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsNonHexMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = "GG:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsDashSeparatedMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = "00-11-22-33-44-55"
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsEmptyMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = ""
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsUppercaseMac) {
    EXPECT_TRUE(Config::FromString(R"(
[reflectors.tv]
mac = "B0:37:95:C5:60:BE"
source_if = "en0"
target_if = "lo0"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsLowercaseMac) {
    EXPECT_TRUE(Config::FromString(R"(
[reflectors.tv]
mac = "b0:37:95:c5:60:be"
source_if = "en0"
target_if = "lo0"
wol = true
)").has_value());
}

// --- address_family validation ---

TEST(ConfigTest, RejectsUnknownAddressFamily) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipx"
)").has_value());
}

TEST(ConfigTest, RejectsNonStringAddressFamily) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = 4
)").has_value());
}

// --- wol_ports validation ---

TEST(ConfigTest, RejectsEmptyPortsArray) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = []
)").has_value());
}

TEST(ConfigTest, RejectsNonArrayPorts) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = "7"
)").has_value());
}

TEST(ConfigTest, RejectsNonIntegerPort) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = ["7"]
)").has_value());
}

TEST(ConfigTest, RejectsPortZeroFromToml) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [0]
)").has_value());
}

TEST(ConfigTest, RejectsDuplicatePorts) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7, 9, 7]
)").has_value());
}

TEST(ConfigTest, RejectsOutOfRangePort) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [65536]
)").has_value());
}

// --- per-protocol dedup across entries (WoL) ---

TEST(ConfigTest, RejectsDuplicateEntryName) {
    // TOML itself rejects two tables with the same name, which is why the parser needs no name
    // dedup of its own (see the comment on AppendConfig).
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true

[reflectors.tv]
source_if = "eth2"
target_if = "eth3"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsCaseFoldedDuplicateName) {
    // "TV" and "tv" are distinct TOML keys, so the parser accepts both; they canonicalize to one
    // name, so they must be rejected rather than silently become two reflectors sharing it.
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.TV]
source_if = "eth0"
target_if = "eth1"
wol = true

[reflectors.tv]
source_if = "eth2"
target_if = "eth3"
wol = true
)").has_value());
}

TEST(ConfigTest, TrimsAndLowercasesReflectorName) {
    // The display name is the canonical form: surrounding whitespace trimmed, ASCII-lowercased,
    // internal spaces kept.
    const auto config = Config::FromString(R"(
[reflectors."  Living Room  "]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().name, "living room");
}

TEST(ConfigTest, RejectsWhitespaceInInterfaceName) {
    // A padded interface name would miss the interface and slip past source_if == target_if.
    for (const std::string_view name : {"eth0 ", " eth0", "e th0"}) {
        const auto config = Config::FromString(std::format(R"(
[reflectors.tv]
source_if = "{}"
target_if = "eth1"
wol = true
)", name));
        EXPECT_FALSE(config.has_value()) << "source_if=\"" << name << "\" should be rejected";
    }
}

TEST(ConfigTest, EnvNameIsTrimmedAndLowercased) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_TV_SOURCE_IF", "eth0"},
        {"REFLECTOR_TV_TARGET_IF", "eth1"},
        {"REFLECTOR_TV_WOL", "true"},
        {"REFLECTOR_TV_NAME", "  Living Room  "},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().name, "living room");
}

TEST(ConfigTest, RejectsEnvTagFoldingWithFileName) {
    // An env tag "TV" and a file key "tv" canonicalize equal: the env source is a duplicate of the
    // file reflector, not a separate one.
    EXPECT_FALSE(Config::Load(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({
        {"REFLECTOR_TV_SOURCE_IF", "eth2"},
        {"REFLECTOR_TV_TARGET_IF", "eth3"},
        {"REFLECTOR_TV_MDNS", "true"},
    })).has_value());
}

// --- Cross-protocol duplicate-rule matrix ---
// AppendConfig<T> implements duplicate detection once, but each protocol is a separate
// instantiation over its own config vector: the matrix runs against every protocol so each
// protocol's contract stays pinned even if the shared template is ever split apart. The
// port-dependent corners are WoL-only and live in their own section further down.
class ConfigDedupMatrixTest : public ::testing::TestWithParam<std::string_view> {
protected:
    // Two-entry TOML enabling the parameterized protocol on both entries; `a` and `b` carry each
    // entry's remaining fields (mac / interfaces / address_family) as raw TOML lines.
    [[nodiscard]] std::string TwoEntries(std::string_view a, std::string_view b) const {
        return std::format("[reflectors.a]{1}\n{0} = true\n\n[reflectors.b]{2}\n{0} = true\n",
            GetParam(), a, b);
    }

    [[nodiscard]] size_t ConfigCount(const Config& config) const {
        if (GetParam() == "wol") {
            return config.WolConfigs().size();
        }
        if (GetParam() == "mdns") {
            return config.MdnsConfigs().size();
        }
        if (GetParam() == "ssdp") {
            return config.SsdpConfigs().size();
        }
        // A protocol added to the instantiation must extend this dispatch, not silently count some
        // other vector and pass.
        ADD_FAILURE() << "ConfigCount has no case for protocol \"" << GetParam() << "\"";
        return 0;
    }

    // The pair must be rejected as this protocol's duplicate — the message names the protocol,
    // which also pins AppendConfig's error text (WoL runs its ports-mentioning branch, the other
    // protocols the ports-less one).
    void ExpectDuplicate(std::string_view a, std::string_view b) const {
        const auto config = Config::FromString(TwoEntries(a, b));
        ASSERT_FALSE(config.has_value());
        EXPECT_NE(config.error().Message().find(std::format("duplicate {} rule", GetParam())),
            std::string::npos) << config.error().Message();
    }

    void ExpectBothAccepted(std::string_view a, std::string_view b) const {
        const auto config = Config::FromString(TwoEntries(a, b));
        ASSERT_TRUE(config.has_value()) << config.error().Message();
        EXPECT_EQ(ConfigCount(*config), 2u);
    }
};

INSTANTIATE_TEST_SUITE_P(Protocols, ConfigDedupMatrixTest,
    ::testing::Values(std::string_view{"wol"}, std::string_view{"mdns"}, std::string_view{"ssdp"}),
    [](const ::testing::TestParamInfo<std::string_view>& param_info) { return std::string{param_info.param}; });

TEST_P(ConfigDedupMatrixTest, RejectsDuplicateMacSourceTargetTriple) {
    ExpectDuplicate(R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1")");
}

TEST_P(ConfigDedupMatrixTest, RejectsDuplicateUnfilteredSourceTargetRule) {
    ExpectDuplicate(R"(
source_if = "eth0"
target_if = "eth1")", R"(
source_if = "eth0"
target_if = "eth1")");
}

TEST_P(ConfigDedupMatrixTest, RejectsSpecificRuleOverlappedByUnfilteredRule) {
    ExpectDuplicate(R"(
source_if = "eth0"
target_if = "eth1")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1")");
}

// "default" handles IPv4 too, so it overlaps an ipv4-only rule on the same triple.
TEST_P(ConfigDedupMatrixTest, RejectsOverlappingRuleWhenDefaultCoversIpv4) {
    ExpectDuplicate(R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "default")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv4")");
}

TEST_P(ConfigDedupMatrixTest, RejectsDuplicateIpv6OnlyRules) {
    // Two ipv6-only rules on the same triple collide via the IPv6 disjunct of AddressFamiliesOverlap
    // (the IPv4 disjunct is false for both) -- the mirror of the default/ipv4 case above.
    ExpectDuplicate(R"(
source_if = "eth0"
target_if = "eth1"
address_family = "ipv6")", R"(
source_if = "eth0"
target_if = "eth1"
address_family = "ipv6")");
}

TEST_P(ConfigDedupMatrixTest, AcceptsDistinctConcreteMacs) {
    // Two different concrete MACs on the same source/target do not collide: MacSelectionsOverlap
    // is false only when both are set and unequal.
    ExpectBothAccepted(R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1")", R"(
mac = "00:11:22:33:44:66"
source_if = "eth0"
target_if = "eth1")");
}

TEST_P(ConfigDedupMatrixTest, AcceptsOverlappingMacSelectionWithDifferentSources) {
    ExpectBothAccepted(R"(
source_if = "eth0"
target_if = "eth1")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth2"
target_if = "eth1")");
}

TEST_P(ConfigDedupMatrixTest, AcceptsSameMacWithDifferentTargets) {
    ExpectBothAccepted(R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth2")");
}

// An ipv4-only and an ipv6-only rule never handle the same packet, so an otherwise identical pair
// is not a duplicate — it is just the long form of one "dual" rule.
TEST_P(ConfigDedupMatrixTest, AcceptsIdenticalRuleWithDisjointAddressFamilies) {
    ExpectBothAccepted(R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv4")", R"(
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv6")");
}

// --- cross-protocol independence: the same rule under different protocols never collides ---



TEST(ConfigTest, AcceptsOverlappingDifferentProtocolsAcrossEntries) {
    // Same source/target, but one entry does WoL and the other mDNS — different protocol vectors,
    // so no dedup collision.
    const auto config = Config::FromString(R"(
[reflectors.a]
source_if = "lan"
target_if = "iot"
wol = true

[reflectors.b]
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
[reflectors.a]
source_if = "lan"
target_if = "iot"
ssdp = true

[reflectors.b]
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
[reflectors.disc]
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
[reflectors.disc]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
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
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [-1]
)").has_value());
}

// --- top-level key classification ---

TEST(ConfigTest, RejectsTopLevelEntryTable) {
    // The pre-0.7 form: a bare [tv] table at the top level. Entries now live only under
    // [reflectors.<name>], so a top-level table other than `reflectors` is an unexpected key.
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsLogLevelAsTable) {
    // log_level is a top-level scalar; a [log_level] table is rejected (must be a string), not read
    // as a reflector entry.
    EXPECT_FALSE(Config::FromString(R"(
[log_level]
source_if = "eth0"
target_if = "eth1"
)").has_value());
}

TEST(ConfigTest, RejectsReflectorsScalar) {
    // `reflectors` must be a table of entries, not a scalar.
    EXPECT_FALSE(Config::FromString(R"(
reflectors = "oops"
)").has_value());
}

TEST(ConfigTest, RejectsNonTableReflectorEntry) {
    // A non-table value inside the reflectors map (here a scalar) is not a valid entry.
    EXPECT_FALSE(Config::FromString(R"(
[reflectors]
tv = "oops"
)").has_value());
}

// --- non-string field types ---

TEST(ConfigTest, RejectsNonStringMac) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
mac = 123
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsNonStringTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = 123
wol = true
)").has_value());
}

// --- address_family enumerator coverage (default/ipv6/dual are covered elsewhere) ---

TEST(ConfigTest, ParsesAddressFamilyIpv4) {
    const auto config = Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
address_family = "ipv4"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().address_family, AddressFamily::IPv4);
}

// --- per-protocol Verify reached through the parser (AppendConfig runs each protocol's own
//     MdnsConfig::Verify / SsdpConfig::Verify, independent of WoL) ---

TEST(ConfigTest, RejectsMdnsMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsMdnsMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
source_if = "lan"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsMdnsSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
source_if = "lan"
target_if = "lan"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
target_if = "iot"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpMissingTargetIf) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
source_if = "lan"
ssdp = true
)").has_value());
}

TEST(ConfigTest, RejectsSsdpSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[reflectors.disc]
source_if = "lan"
target_if = "lan"
ssdp = true
)").has_value());
}

// --- WoL dedup: the port-dependent branches the cross-protocol matrix cannot reach ---

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDisjointPorts) {
    const auto config = Config::FromString(R"(
[reflectors.a]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7]

[reflectors.b]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [9]
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, RejectsPartialPortOverlap) {
    // Sharing a single port (9) is enough to collide — PortsOverlap is any-shared-element, not set
    // equality. The error runs AppendConfig's WoL-only branch, whose message lists the ports.
    const auto config = Config::FromString(R"(
[reflectors.a]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [7, 9]

[reflectors.b]
source_if = "eth0"
target_if = "eth1"
wol = true
wol_ports = [9, 40000]
)");
    ASSERT_FALSE(config.has_value());
    EXPECT_NE(config.error().Message().find("ports"), std::string::npos) << config.error().Message();
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

TEST(ConfigTest, AddressFamilyFormatter) {
    EXPECT_EQ(std::format("{}", AddressFamily::Default), "default");
    EXPECT_EQ(std::format("{}", AddressFamily::Dual), "dual");
    EXPECT_EQ(std::format("{}", AddressFamily::IPv4), "ipv4");
    EXPECT_EQ(std::format("{}", AddressFamily::IPv6), "ipv6");
}

TEST(ConfigTest, WolConfigFormatter) {
    const auto with_mac = WolConfig{
        .name = "tv", .mac = *MacAddress::FromString("00:11:22:33:44:55"),
        .source_if = "eth0", .target_if = "eth1", .ports = {7, 9, 42},
    };
    const auto s = std::format("{}", with_mac);
    EXPECT_NE(s.find("\"tv\""), std::string::npos) << s;
    EXPECT_NE(s.find("eth0"), std::string::npos) << s;
    EXPECT_NE(s.find("eth1"), std::string::npos) << s;
    EXPECT_NE(s.find("ports: ["), std::string::npos) << s;
    EXPECT_NE(s.find("42"), std::string::npos) << s;
    EXPECT_EQ(s.find("any"), std::string::npos) << s;  // mac present, so not "any"

    const auto no_mac = WolConfig{.name = "net", .mac = std::nullopt, .source_if = "eth0", .target_if = "eth1"};
    EXPECT_NE(std::format("{}", no_mac).find("any"), std::string::npos);
}

TEST(ConfigTest, MdnsConfigFormatter) {
    const auto mdns = MdnsConfig{
        .name = "disc", .mac = std::nullopt, .source_if = "lan", .target_if = "iot",
        .address_family = AddressFamily::IPv6,
    };
    const auto s = std::format("{}", mdns);
    EXPECT_NE(s.find("\"disc\""), std::string::npos) << s;
    EXPECT_NE(s.find("any"), std::string::npos) << s;   // no mac
    EXPECT_NE(s.find("ipv6"), std::string::npos) << s;  // address_family rendered
}

TEST(ConfigTest, SsdpFormatterPrintsMacAndDialFalse) {
    const auto ssdp = SsdpConfig{
        .name = "tv", .mac = *MacAddress::FromString("00:11:22:33:44:55"),
        .source_if = "lan", .target_if = "iot", .dial = false,
    };
    const auto s = std::format("{}", ssdp);
    EXPECT_NE(s.find("dial: false"), std::string::npos) << s;
    EXPECT_EQ(s.find("any"), std::string::npos) << s;  // mac present
}

TEST(ConfigTest, ConfigFormatterRendersAllSections) {
    const auto config = Config::FromString(R"(
log_level = "warning"
[reflectors.tv]
source_if = "lan"
target_if = "iot"
wol = true
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    const auto s = std::format("{}", *config);
    EXPECT_NE(s.find("log_level:"), std::string::npos) << s;
    EXPECT_NE(s.find("wol: ["), std::string::npos) << s;
    EXPECT_NE(s.find("mdns: ["), std::string::npos) << s;
    EXPECT_NE(s.find("ssdp: ["), std::string::npos) << s;
}

TEST(ConfigTest, ParsesSsdpDialFlagFromToml) {
    const auto config = Config::FromString(R"(
[reflectors.tv]
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
[reflectors.tv]
source_if = "lan"
target_if = "iot"
ssdp = true
)");
    ASSERT_TRUE(config.has_value());
    ASSERT_EQ(config->SsdpConfigs().size(), 1u);
    EXPECT_FALSE(config->SsdpConfigs()[0].dial);
}

TEST(ConfigTest, RejectsDialWithoutSsdp) {
    // wol is enabled so the entry passes the "enables no protocol" check and actually reaches the
    // dial-without-ssdp branch; asserting on "dial" ensures the dial-specific error fired (the
    // no-protocol message also contains "ssdp", so a "ssdp" assertion would pass via the wrong path).
    const auto config = Config::FromString(R"(
[reflectors.tv]
source_if = "lan"
target_if = "iot"
wol = true
dial = true
)");
    ASSERT_FALSE(config.has_value());  // dial requires ssdp (rejected at parse, no config appended)
    EXPECT_NE(config.error().Message().find("dial"), std::string::npos) << config.error().Message();
}

TEST(ConfigTest, RejectsNonBooleanDial) {
    const auto config = Config::FromString(R"(
[reflectors.tv]
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
    // AppendConfig runs Verify before appending, so a dial+ipv6 entry is rejected, not stored.
    const auto config = Config::FromString(R"(
[reflectors.tv]
source_if = "lan"
target_if = "iot"
ssdp = true
address_family = "ipv6"
dial = true
)");
    ASSERT_FALSE(config.has_value());
    EXPECT_NE(config.error().Message().find("dial"), std::string::npos) << config.error().Message();
}

// --- environment-variable configuration (Config::Load) ---

TEST(ConfigTest, EnvParsesSingleWolEntry) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_NAME", "tv"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_MAC", "B0:37:95:C5:60:BE"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1u);
    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.name, "tv");
    EXPECT_EQ(wol.source_if, "eth0");
    EXPECT_EQ(wol.target_if, "eth1");
    ASSERT_TRUE(wol.mac.has_value());
    EXPECT_EQ(*wol.mac, *MacAddress::FromString("B0:37:95:C5:60:BE"));
}

TEST(ConfigTest, EnvNameDefaultsToTag) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_lan_SOURCE_IF", "eth0"},
        {"REFLECTOR_lan_TARGET_IF", "eth1"},
        {"REFLECTOR_lan_MDNS", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->MdnsConfigs().size(), 1u);
    EXPECT_EQ(config->MdnsConfigs().front().name, "lan");
}

TEST(ConfigTest, EnvParamNamesAreCaseInsensitive) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_source_if", "eth0"},
        {"REFLECTOR_1_Target_If", "eth1"},
        {"REFLECTOR_1_WoL", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1u);
}

TEST(ConfigTest, EnvAcceptsTrueBooleanSpellings) {
    for (const std::string_view value : {"true", "TRUE", "True", "1"}) {
        const auto config = Config::Load(std::nullopt, Env({
            {"REFLECTOR_1_SOURCE_IF", "eth0"},
            {"REFLECTOR_1_TARGET_IF", "eth1"},
            {"REFLECTOR_1_WOL", value},
        }));
        ASSERT_TRUE(config.has_value()) << "value=" << value << ": " << config.error().Message();
        EXPECT_EQ(config->WolConfigs().size(), 1u) << "value=" << value;
    }
}

TEST(ConfigTest, EnvAcceptsFalseBooleanSpellings) {
    for (const std::string_view value : {"false", "FALSE", "0"}) {
        const auto config = Config::Load(std::nullopt, Env({
            {"REFLECTOR_1_SOURCE_IF", "eth0"},
            {"REFLECTOR_1_TARGET_IF", "eth1"},
            {"REFLECTOR_1_WOL", value},
            {"REFLECTOR_1_MDNS", "true"},
        }));
        ASSERT_TRUE(config.has_value()) << "value=" << value << ": " << config.error().Message();
        EXPECT_TRUE(config->WolConfigs().empty()) << "value=" << value;
        EXPECT_EQ(config->MdnsConfigs().size(), 1u) << "value=" << value;
    }
}

TEST(ConfigTest, EnvRejectsInvalidBoolean) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "yes"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvParsesWolPortsCsv) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_1_WOL_PORTS", "7, 9, 4000"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().ports, (std::vector<uint16_t>{7, 9, 4000}));
}

TEST(ConfigTest, EnvRejectsInvalidWolPorts) {
    for (const std::string_view value : {"7,x", "7,,9", "70000", "", "7,0"}) {
        const auto config = Config::Load(std::nullopt, Env({
            {"REFLECTOR_1_SOURCE_IF", "eth0"},
            {"REFLECTOR_1_TARGET_IF", "eth1"},
            {"REFLECTOR_1_WOL", "true"},
            {"REFLECTOR_1_WOL_PORTS", value},
        }));
        EXPECT_FALSE(config.has_value()) << "value=" << value;
    }
}

TEST(ConfigTest, EnvParsesAddressFamily) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_SSDP", "true"},
        {"REFLECTOR_1_ADDRESS_FAMILY", "ipv4"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().front().address_family, AddressFamily::IPv4);
}

TEST(ConfigTest, EnvAddressFamilyIsCaseInsensitive) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_MDNS", "true"},
        {"REFLECTOR_1_ADDRESS_FAMILY", "DuAl"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MdnsConfigs().front().address_family, AddressFamily::Dual);
}

TEST(ConfigTest, EnvRejectsInvalidAddressFamily) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_MDNS", "true"},
        {"REFLECTOR_1_ADDRESS_FAMILY", "ipx"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsInvalidMac) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_1_MAC", "not-a-mac"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvParsesDialFlag) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_SSDP", "true"},
        {"REFLECTOR_1_DIAL", "1"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->SsdpConfigs().size(), 1u);
    EXPECT_TRUE(config->SsdpConfigs().front().dial);
}

TEST(ConfigTest, EnvEnablesMultipleProtocolsFromOneTag) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_NAME", "tv"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_1_MDNS", "true"},
        {"REFLECTOR_1_SSDP", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1u);
    EXPECT_EQ(config->MdnsConfigs().size(), 1u);
    EXPECT_EQ(config->SsdpConfigs().size(), 1u);
    EXPECT_EQ(config->WolConfigs().front().name, "tv");
    EXPECT_EQ(config->SsdpConfigs().front().name, "tv");
}

TEST(ConfigTest, EnvParsesMultipleTags) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_2_SOURCE_IF", "eth2"},
        {"REFLECTOR_2_TARGET_IF", "eth3"},
        {"REFLECTOR_2_MDNS", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1u);
    EXPECT_EQ(config->MdnsConfigs().size(), 1u);
}

TEST(ConfigTest, EnvSetsLogLevel) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_LOG_LEVEL", "debug"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

TEST(ConfigTest, EnvLogLevelIsCaseInsensitive) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_LOG_LEVEL", "WARNING"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Warning);
}

TEST(ConfigTest, EnvRejectsInvalidLogLevel) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_LOG_LEVEL", "verbose"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvIgnoresUnrelatedVariables) {
    const auto config = Config::Load(std::nullopt, Env({
        {"PATH", "/usr/bin"},
        {"REFLECTORISH", "x"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1u);
}

TEST(ConfigTest, EnvRejectsUnknownParameter) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_1_BOGUS", "x"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsReservedLogTag) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_LOG_FORMAT", "json"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsTagWithoutParameter) {
    EXPECT_FALSE(Config::Load(std::nullopt, Env({{"REFLECTOR_1", "x"}})).has_value());
    EXPECT_FALSE(Config::Load(std::nullopt, Env({{"REFLECTOR_1_", "x"}})).has_value());
}

TEST(ConfigTest, EnvRejectsEmptyTag) {
    // REFLECTOR__SOURCE_IF: nothing between the prefix and the first underscore -> empty tag.
    EXPECT_FALSE(Config::Load(std::nullopt, Env({{"REFLECTOR__SOURCE_IF", "eth0"}})).has_value());
}

TEST(ConfigTest, EnvRejectsNonAlphanumericTag) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_a.b_SOURCE_IF", "eth0"},
        {"REFLECTOR_a.b_TARGET_IF", "eth1"},
        {"REFLECTOR_a.b_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsDuplicateNameAcrossTags) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_1_NAME", "tv"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
        {"REFLECTOR_2_NAME", "tv"},
        {"REFLECTOR_2_SOURCE_IF", "eth2"},
        {"REFLECTOR_2_TARGET_IF", "eth3"},
        {"REFLECTOR_2_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsEmptyConfiguration) {
    EXPECT_FALSE(Config::Load(std::nullopt, std::span<const EnvVar>{}).has_value());
    EXPECT_FALSE(Config::Load(std::nullopt, Env({{"PATH", "/usr/bin"}})).has_value());
}

// --- merging a TOML file with environment variables ---

TEST(ConfigTest, MergeCombinesFileAndEnvEntries) {
    const auto config = Config::Load(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({
        {"REFLECTOR_radio_SOURCE_IF", "eth2"},
        {"REFLECTOR_radio_TARGET_IF", "eth3"},
        {"REFLECTOR_radio_MDNS", "true"},
    }));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1u);
    ASSERT_EQ(config->MdnsConfigs().size(), 1u);
    EXPECT_EQ(config->WolConfigs().front().name, "tv");
    EXPECT_EQ(config->MdnsConfigs().front().name, "radio");
}

TEST(ConfigTest, MergeDetectsCrossSourceDuplicate) {
    const auto config = Config::Load(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({
        {"REFLECTOR_other_SOURCE_IF", "eth0"},
        {"REFLECTOR_other_TARGET_IF", "eth1"},
        {"REFLECTOR_other_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, MergeDetectsDuplicateNameAcrossSources) {
    const auto config = Config::Load(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({
        {"REFLECTOR_x_NAME", "tv"},
        {"REFLECTOR_x_SOURCE_IF", "eth2"},
        {"REFLECTOR_x_TARGET_IF", "eth3"},
        {"REFLECTOR_x_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvLogLevelOverridesFile) {
    const auto config = Config::Load(R"(
log_level = "error"
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({{"REFLECTOR_LOG_LEVEL", "debug"}}));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

TEST(ConfigTest, FileLogLevelKeptWhenEnvUnset) {
    const auto config = Config::Load(R"(
log_level = "warning"
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", std::span<const EnvVar>{});
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Warning);
}

TEST(ConfigTest, EnvLogLevelSetsWhenFileOmitsIt) {
    // File contributes an entry but no log_level; the env supplies it (sole setter, not an override).
    const auto config = Config::Load(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({{"REFLECTOR_LOG_LEVEL", "debug"}}));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

// --- debug_memory ---

TEST(ConfigTest, DebugMemoryDefaultsToFalse) {
    const auto config = Config::FromString(R"(
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_FALSE(config->DebugMemory());
}

TEST(ConfigTest, ParsesDebugMemoryTrue) {
    const auto config = Config::FromString(R"(
debug_memory = true
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->DebugMemory());
}

TEST(ConfigTest, ParsesDebugMemoryFalse) {
    const auto config = Config::FromString(R"(
debug_memory = false
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_FALSE(config->DebugMemory());
}

TEST(ConfigTest, RejectsNonBoolDebugMemory) {
    EXPECT_FALSE(Config::FromString(R"(
debug_memory = "yes"
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)").has_value());
}

TEST(ConfigTest, EnvSetsDebugMemory) {
    for (const auto* value : {"true", "1"}) {
        const auto config = Config::Load(std::nullopt, Env({
            {"REFLECTOR_DEBUG_MEMORY", value},
            {"REFLECTOR_1_SOURCE_IF", "eth0"},
            {"REFLECTOR_1_TARGET_IF", "eth1"},
            {"REFLECTOR_1_WOL", "true"},
        }));
        ASSERT_TRUE(config.has_value()) << config.error().Message();
        EXPECT_TRUE(config->DebugMemory());
    }
}

TEST(ConfigTest, EnvDisablesDebugMemory) {
    for (const auto* value : {"false", "0"}) {
        const auto config = Config::Load(std::nullopt, Env({
            {"REFLECTOR_DEBUG_MEMORY", value},
            {"REFLECTOR_1_SOURCE_IF", "eth0"},
            {"REFLECTOR_1_TARGET_IF", "eth1"},
            {"REFLECTOR_1_WOL", "true"},
        }));
        ASSERT_TRUE(config.has_value()) << config.error().Message();
        EXPECT_FALSE(config->DebugMemory());
    }
}

TEST(ConfigTest, EnvRejectsInvalidDebugMemory) {
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_DEBUG_MEMORY", "maybe"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvRejectsReservedDebugTag) {
    // A REFLECTOR_DEBUG_<x> other than the special-cased MEMORY must not be read as an entry "debug".
    const auto config = Config::Load(std::nullopt, Env({
        {"REFLECTOR_DEBUG_VERBOSE", "true"},
        {"REFLECTOR_1_SOURCE_IF", "eth0"},
        {"REFLECTOR_1_TARGET_IF", "eth1"},
        {"REFLECTOR_1_WOL", "true"},
    }));
    EXPECT_FALSE(config.has_value());
}

TEST(ConfigTest, EnvDebugMemoryOverridesFile) {
    const auto config = Config::Load(R"(
debug_memory = false
[reflectors.tv]
source_if = "eth0"
target_if = "eth1"
wol = true
)", Env({{"REFLECTOR_DEBUG_MEMORY", "true"}}));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_TRUE(config->DebugMemory());
}

}  // namespace reflector
