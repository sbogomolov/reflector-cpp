#pragma once

#include "error.h"
#include "logger.h"
#include "mac_address.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace reflector {

enum class AddressFamily : uint8_t {
    Default,
    Dual,
    IPv4,
    IPv6,
};

// Which IP versions a reflector handles. "Uses" = will attempt the family; "Requires" = startup
// fails if it can't be initialized. Default attempts both but only requires IPv4 (IPv6 is
// best-effort); Dual requires both; IPv4 / IPv6 use only that one.
[[nodiscard]] constexpr bool UsesIPv4(AddressFamily family) noexcept {
    return family != AddressFamily::IPv6;
}
[[nodiscard]] constexpr bool UsesIPv6(AddressFamily family) noexcept {
    return family != AddressFamily::IPv4;
}
[[nodiscard]] constexpr bool RequiresIPv4(AddressFamily family) noexcept {
    return family == AddressFamily::Default || family == AddressFamily::Dual
        || family == AddressFamily::IPv4;
}
[[nodiscard]] constexpr bool RequiresIPv6(AddressFamily family) noexcept {
    return family == AddressFamily::Dual || family == AddressFamily::IPv6;
}

struct WolConfig {
    std::string name;
    std::optional<MacAddress> mac;
    std::string source_if;
    std::string target_if;
    std::vector<uint16_t> ports{7, 9};
    AddressFamily address_family = AddressFamily::Default;

    [[nodiscard]] constexpr bool UsesIPv4() const noexcept { return reflector::UsesIPv4(address_family); }
    [[nodiscard]] constexpr bool UsesIPv6() const noexcept { return reflector::UsesIPv6(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv4() const noexcept { return reflector::RequiresIPv4(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv6() const noexcept { return reflector::RequiresIPv6(address_family); }

    [[nodiscard]] std::optional<Error> Verify() const;
};

// An mDNS reflector entry: reflects multicast DNS between source_if and target_if on UDP 5353.
// Queries flow source->target and responses target->source; `mac`, when set, restricts the
// target->source direction to frames whose L2 source MAC matches it (expose only that device).
struct MdnsConfig {
    std::string name;
    std::optional<MacAddress> mac;
    std::string source_if;
    std::string target_if;
    AddressFamily address_family = AddressFamily::Default;

    [[nodiscard]] constexpr bool UsesIPv4() const noexcept { return reflector::UsesIPv4(address_family); }
    [[nodiscard]] constexpr bool UsesIPv6() const noexcept { return reflector::UsesIPv6(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv4() const noexcept { return reflector::RequiresIPv4(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv6() const noexcept { return reflector::RequiresIPv6(address_family); }

    [[nodiscard]] std::optional<Error> Verify() const;
};

// An SSDP reflector entry: reflects UPnP/DLNA discovery between source_if and target_if on UDP 1900.
// M-SEARCH searches flow source->target and NOTIFY advertisements target->source; `mac`, when set,
// restricts the target->source direction to frames whose L2 source MAC matches it (expose only that
// device).
struct SsdpConfig {
    std::string name;
    std::optional<MacAddress> mac;
    std::string source_if;
    std::string target_if;
    AddressFamily address_family = AddressFamily::Default;
    bool dial = false;  // enable the DIAL application proxy for this entry (IPv4-only; see DialProxy)

    [[nodiscard]] constexpr bool UsesIPv4() const noexcept { return reflector::UsesIPv4(address_family); }
    [[nodiscard]] constexpr bool UsesIPv6() const noexcept { return reflector::UsesIPv6(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv4() const noexcept { return reflector::RequiresIPv4(address_family); }
    [[nodiscard]] constexpr bool RequiresIPv6() const noexcept { return reflector::RequiresIPv6(address_family); }

    [[nodiscard]] std::optional<Error> Verify() const;
};

// One environment variable, split into its name and value (the '=' itself is dropped). Both views
// reference storage owned by the caller (the process environment, or test fixtures); Config::Load
// reads them synchronously and copies out anything it keeps.
struct EnvVar {
    std::string_view key;
    std::string_view value;
};

class Config {
public:
    // Reads a config file into a string. Separated from FromString/Load so the caller (main) can pass
    // the same text to Load alongside the environment.
    [[nodiscard]] static std::expected<std::string, Error> ReadFileToString(const char* path);
    [[nodiscard]] static std::expected<Config, Error> FromString(std::string_view str);
    // The unified entry point: merges an optional TOML document with REFLECTOR_* environment variables
    // into one configuration. Reflector entries from both sources share the same duplicate detection;
    // REFLECTOR_LOG_LEVEL overrides the file's log_level. Fails if the merged result has no reflectors.
    [[nodiscard]] static std::expected<Config, Error> Load(std::optional<std::string_view> toml_text,
        std::span<const EnvVar> env_vars);
    [[nodiscard]] const std::vector<WolConfig>& WolConfigs() const noexcept { return wol_configs_; }
    [[nodiscard]] const std::vector<MdnsConfig>& MdnsConfigs() const noexcept { return mdns_configs_; }
    [[nodiscard]] const std::vector<SsdpConfig>& SsdpConfigs() const noexcept { return ssdp_configs_; }
    [[nodiscard]] LogLevel MinLogLevel() const noexcept { return log_level_; }

private:
    // Test-only: builds a Config programmatically, bypassing TOML parsing.
    friend class TestConfigBuilder;

    Config() noexcept = default;
    [[nodiscard]] size_t ReflectorCount() const noexcept {
        return wol_configs_.size() + mdns_configs_.size() + ssdp_configs_.size();
    }

    std::vector<WolConfig> wol_configs_;
    std::vector<MdnsConfig> mdns_configs_;
    std::vector<SsdpConfig> ssdp_configs_;
    LogLevel log_level_ = LogLevel::Info;
};

} // namespace reflector

template <>
struct std::formatter<reflector::AddressFamily, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for AddressFamily");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(reflector::AddressFamily address_family, FmtContext& ctx) const {
        switch (address_family) {
        using enum reflector::AddressFamily;
        case Default: return std::format_to(ctx.out(), "default");
        case Dual: return std::format_to(ctx.out(), "dual");
        case IPv4: return std::format_to(ctx.out(), "ipv4");
        case IPv6: return std::format_to(ctx.out(), "ipv6");
        }

        std::unreachable();
    }
};

template <>
struct std::formatter<reflector::WolConfig, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for WolConfig");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::WolConfig& c, FmtContext& ctx) const {
        std::format_to(ctx.out(), "{{name: \"{}\", mac: ", c.name);
        if (c.mac) {
            std::format_to(ctx.out(), "\"{}\"", *c.mac);
        } else {
            std::format_to(ctx.out(), "any");
        }
        std::format_to(ctx.out(), ", source_if: \"{}\", target_if: \"{}\", address_family: {}, ports: [",
            c.source_if, c.target_if, c.address_family);
        bool first = true;
        for (const auto port : c.ports) {
            if (first) {
                first = false;
            } else {
                std::format_to(ctx.out(), ", ");
            }
            std::format_to(ctx.out(), "{}", port);
        }
        return std::format_to(ctx.out(), "]}}");
    }
};

template <>
struct std::formatter<reflector::MdnsConfig, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for MdnsConfig");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::MdnsConfig& c, FmtContext& ctx) const {
        std::format_to(ctx.out(), "{{name: \"{}\", mac: ", c.name);
        if (c.mac) {
            std::format_to(ctx.out(), "\"{}\"", *c.mac);
        } else {
            std::format_to(ctx.out(), "any");
        }
        return std::format_to(ctx.out(), ", source_if: \"{}\", target_if: \"{}\", address_family: {}}}",
            c.source_if, c.target_if, c.address_family);
    }
};

template <>
struct std::formatter<reflector::SsdpConfig, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for SsdpConfig");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::SsdpConfig& c, FmtContext& ctx) const {
        std::format_to(ctx.out(), "{{name: \"{}\", mac: ", c.name);
        if (c.mac) {
            std::format_to(ctx.out(), "\"{}\"", *c.mac);
        } else {
            std::format_to(ctx.out(), "any");
        }
        return std::format_to(ctx.out(), ", source_if: \"{}\", target_if: \"{}\", address_family: {}, dial: {}}}",
            c.source_if, c.target_if, c.address_family, c.dial);
    }
};

template <>
struct std::formatter<reflector::Config, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for Config");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::Config& c, FmtContext& ctx) const
    {
        std::format_to(ctx.out(), "{{log_level: {}, wol: [", c.MinLogLevel());
        bool first = true;
        for (const auto& wol_config : c.WolConfigs()) {
            if (first) {
                first = false;
            } else {
                std::format_to(ctx.out(), ", ");
            }
            std::format_to(ctx.out(), "{}", wol_config);
        }

        std::format_to(ctx.out(), "], mdns: [");
        first = true;
        for (const auto& mdns_config : c.MdnsConfigs()) {
            if (first) {
                first = false;
            } else {
                std::format_to(ctx.out(), ", ");
            }
            std::format_to(ctx.out(), "{}", mdns_config);
        }

        std::format_to(ctx.out(), "], ssdp: [");
        first = true;
        for (const auto& ssdp_config : c.SsdpConfigs()) {
            if (first) {
                first = false;
            } else {
                std::format_to(ctx.out(), ", ");
            }
            std::format_to(ctx.out(), "{}", ssdp_config);
        }

        return std::format_to(ctx.out(), "]}}");
    }
};
