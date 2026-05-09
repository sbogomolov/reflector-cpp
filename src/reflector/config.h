#pragma once

#include "error.h"
#include "logger.h"
#include "mac_address.h"

#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace reflector {

struct WolConfig {
    std::string name;
    MacAddress mac;
    std::string source_if;
    std::string target_if;
    std::vector<uint16_t> ports{7, 9};

    [[nodiscard]] std::optional<Error> Verify() const;
};

class Config {
public:
    [[nodiscard]] static std::expected<Config, Error> FromFile(const char* path);
    [[nodiscard]] static std::expected<Config, Error> FromString(std::string_view str);
    [[nodiscard]] const std::vector<WolConfig>& WolConfigs() const noexcept { return wol_configs_; }
    [[nodiscard]] LogLevel MinLogLevel() const noexcept { return log_level_; }

private:
    Config() noexcept = default;
    std::vector<WolConfig> wol_configs_;
    LogLevel log_level_ = LogLevel::Info;
};

} // namespace reflector

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
        const auto& mac_bytes = c.mac.Bytes();
        std::format_to(ctx.out(), "{{name: \"{}\", mac: \"{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\", source_if: \"{}\", target_if: \"{}\", ports: [",
            c.name,
            static_cast<uint8_t>(mac_bytes[0]), static_cast<uint8_t>(mac_bytes[1]),
            static_cast<uint8_t>(mac_bytes[2]), static_cast<uint8_t>(mac_bytes[3]),
            static_cast<uint8_t>(mac_bytes[4]), static_cast<uint8_t>(mac_bytes[5]),
            c.source_if, c.target_if);
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

        return std::format_to(ctx.out(), "]}}");
    }
};
