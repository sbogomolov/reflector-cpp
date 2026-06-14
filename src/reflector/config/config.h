#pragma once

#include "entries.h"

#include "reflector/error.h"
#include "reflector/logger.h"

#include <cstddef>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reflector {

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
