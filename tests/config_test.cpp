#include "reflector/config.h"
#include "reflector/logger.h"
#include "reflector/mac_address.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace reflector;

namespace {

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

[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";
    return toml;
}

} // namespace

TEST(ConfigTest, ParsesDefaultWolOptions) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);

    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.name, "tv");
    ASSERT_TRUE(wol.mac.has_value());
    EXPECT_EQ(*wol.mac, *MacAddress::FromString("00:11:22:33:44:55"));
    EXPECT_EQ(wol.source_if, "eth0");
    EXPECT_EQ(wol.target_if, "eth1");
    const std::vector<uint16_t> expected_ports{7, 9};
    EXPECT_EQ(wol.ports, expected_ports);
    EXPECT_EQ(wol.address_family, WolAddressFamily::Default);
}

TEST(ConfigTest, ParsesMultipleWolEntries) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:00:00:00:00:0a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:00:00:00:00:0b"
source_if = "eth2"
target_if = "eth3"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 2);
    EXPECT_EQ(config->WolConfigs()[0].name, "a");
    ASSERT_TRUE(config->WolConfigs()[0].mac.has_value());
    EXPECT_EQ(*config->WolConfigs()[0].mac, *MacAddress::FromString("00:00:00:00:00:0a"));
    EXPECT_EQ(config->WolConfigs()[0].source_if, "eth0");
    EXPECT_EQ(config->WolConfigs()[0].target_if, "eth1");
    EXPECT_EQ(config->WolConfigs()[1].name, "b");
    ASSERT_TRUE(config->WolConfigs()[1].mac.has_value());
    EXPECT_EQ(*config->WolConfigs()[1].mac, *MacAddress::FromString("00:00:00:00:00:0b"));
    EXPECT_EQ(config->WolConfigs()[1].source_if, "eth2");
    EXPECT_EQ(config->WolConfigs()[1].target_if, "eth3");
}

TEST(ConfigTest, ParsesExplicitPorts) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = [7, 9, 40000]
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);

    const std::vector<uint16_t> expected_ports{7, 9, 40000};
    EXPECT_EQ(config->WolConfigs().front().ports, expected_ports);
}

TEST(ConfigTest, ParsesAddressFamily) {
    const std::vector<std::pair<std::string_view, WolAddressFamily>> cases{
        {"default", WolAddressFamily::Default},
        {"dual", WolAddressFamily::Dual},
        {"ipv4", WolAddressFamily::IPv4},
        {"ipv6", WolAddressFamily::IPv6},
        {"IPv6", WolAddressFamily::IPv6},
    };

    for (const auto& [value, expected] : cases) {
        std::string toml = R"(
[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = ")";
        toml += value;
        toml += "\"\n";

        const auto config = Config::FromString(toml);
        ASSERT_TRUE(config.has_value()) << value << ": " << config.error().Message();
        ASSERT_EQ(config->WolConfigs().size(), 1);
        EXPECT_EQ(config->WolConfigs().front().address_family, expected) << value;
    }
}

TEST(ConfigTest, AddressFamilyRuntimePolicy) {
    struct Case {
        WolAddressFamily address_family;
        bool uses_v4;
        bool uses_v6;
        bool requires_v4;
        bool requires_v6;
    };

    const std::vector<Case> cases{
        {WolAddressFamily::Default, true, true, true, false},
        {WolAddressFamily::Dual, true, true, true, true},
        {WolAddressFamily::IPv4, true, false, true, false},
        {WolAddressFamily::IPv6, false, true, false, true},
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

TEST(ConfigTest, RejectsEmptyDocument) {
    const auto config = Config::FromString("");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsMalformedToml) {
    const auto config = Config::FromString("[[wol]\n");
    ASSERT_FALSE(config.has_value());
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
    const auto config = Config::FromFile(path_string.c_str());
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, FromFileParsesConfig) {
    const auto path = MakeTempConfigPath("valid");
    {
        std::ofstream file{path};
        ASSERT_TRUE(file);
        file << R"(
[[wol]]
name = "file"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
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

TEST(ConfigTest, RejectsUnknownRootSection) {
    const auto config = Config::FromString("other = \"value\"\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsExtraRootSection) {
    std::string toml = R"(
other = "value"

[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsWolObject) {
    const auto config = Config::FromString("wol = {}\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptyWolArrayAsNoReflectors) {
    const auto config = Config::FromString("wol = []\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsConfigWithNoReflectors) {
    const auto config = Config::FromString("log_level = \"info\"\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsWolScalar) {
    const auto config = Config::FromString("wol = \"foo\"\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonTableWolEntry) {
    const auto config = Config::FromString("wol = [\"bad\"]\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsMissingName) {
    std::string toml = R"(
[[wol]]
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, AcceptsMissingMac) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    EXPECT_FALSE(config->WolConfigs().front().mac.has_value());
}

TEST(ConfigTest, RejectsMissingSourceIf) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonStringWolField) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = 123
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsMissingTargetIf) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsUnknownWolOption) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
extra_option = "abc"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsUnknownAddressFamily) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipx"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonStringAddressFamily) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = ["ipv4"]
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptyPortsArray) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = []
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonArrayPorts) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = 7
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonIntegerPort) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = ["7"]
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsPortZeroFromToml) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = [0]
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
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

    const auto error = wol_config.Verify();

    EXPECT_TRUE(error.has_value());
}

TEST(ConfigTest, VerifyAcceptsMissingMac) {
    const auto wol_config = WolConfig{
        .name = "a",
        .mac = std::nullopt,
        .source_if = "eth0",
        .target_if = "eth1",
    };

    const auto error = wol_config.Verify();

    EXPECT_FALSE(error.has_value());
}

TEST(ConfigTest, RejectsDuplicatePorts) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = [7, 9, 7]
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
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

    const auto error = wol_config.Verify();

    EXPECT_TRUE(error.has_value());
}

TEST(ConfigTest, RejectsOutOfRangePort) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = [65536]
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptyName) {
    std::string toml = R"(
[[wol]]
name = ""
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptyMac) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = ""
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptySourceIf) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = ""
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsEmptyTargetIf) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = ""
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsSameInterfaces) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth0"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsDuplicateName) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "00:00:00:00:00:0a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "tv"
mac = "00:00:00:00:00:0b"
source_if = "eth2"
target_if = "eth3"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsDuplicateMacSourceTargetTriple) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsDuplicateUnfilteredSourceTargetRule) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsSpecificRuleOverlappedByUnfilteredRule) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, AcceptsSameMacWithDifferentTargets) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth2"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDisjointPorts) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"
ports = [7]

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
ports = [9]
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDifferentSources) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth2"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

TEST(ConfigTest, AcceptsOverlappingMacSelectionWithDifferentTargets) {
    std::string toml = R"(
[[wol]]
name = "a"
source_if = "eth0"
target_if = "eth1"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth2"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

// An ipv4-only and an ipv6-only rule never handle the same packet, so an otherwise
// identical pair is not a duplicate — it is just the long form of one "dual" rule.
TEST(ConfigTest, AcceptsIdenticalRuleWithDisjointAddressFamilies) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv4"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv6"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 2);
}

// "default" handles IPv4 too, so it overlaps an ipv4-only rule on the same triple.
TEST(ConfigTest, RejectsOverlappingRuleWhenDefaultCoversIpv4) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "default"

[[wol]]
name = "b"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
address_family = "ipv4"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsTooShortMac) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00:11:22:33:44"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonHexMac) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "GG:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsDashSeparatedMac) {
    std::string toml = R"(
[[wol]]
name = "a"
mac = "00-11-22-33-44-55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, AcceptsUppercaseMac) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "B0:37:95:C5:60:BE"
source_if = "en0"
target_if = "lo0"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
}

TEST(ConfigTest, AcceptsLowercaseMac) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "b0:37:95:c5:60:be"
source_if = "en0"
target_if = "lo0"
)";

    const auto config = Config::FromString(toml);
    ASSERT_TRUE(config.has_value()) << config.error().Message();
}

TEST(ConfigTest, LogLevelDefaultsToInfo) {
    std::string toml = R"(
[[wol]]
name = "tv"
mac = "00:11:22:33:44:55"
source_if = "eth0"
target_if = "eth1"
)";

    const auto config = Config::FromString(toml);
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
    const auto config = Config::FromString(TomlWithLogLevel("DEBUG"));
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
}

TEST(ConfigTest, RejectsUnknownLogLevel) {
    const auto config = Config::FromString("log_level = \"trace\"\n");
    ASSERT_FALSE(config.has_value());
}

TEST(ConfigTest, RejectsNonStringLogLevel) {
    const auto config = Config::FromString("log_level = 7\n");
    ASSERT_FALSE(config.has_value());
}
