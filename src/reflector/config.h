#pragma once

#include "error.h"
#include "logger.h"
#include "mac_address.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace reflector {

enum class WolAddressFamily : uint8_t {
    Default,
    Dual,
    IPv4,
    IPv6,
};

struct WolConfig {
    std::string name;
    std::optional<MacAddress> mac;
    std::string source_if;
    std::string target_if;
    std::vector<uint16_t> ports{7, 9};
    WolAddressFamily address_family = WolAddressFamily::Default;

    [[nodiscard]] constexpr bool UsesIPv4() const noexcept {
        return address_family != WolAddressFamily::IPv6;
    }

    [[nodiscard]] constexpr bool UsesIPv6() const noexcept {
        return address_family != WolAddressFamily::IPv4;
    }

    [[nodiscard]] constexpr bool RequiresIPv4() const noexcept {
        return address_family == WolAddressFamily::Default
            || address_family == WolAddressFamily::Dual
            || address_family == WolAddressFamily::IPv4;
    }

    [[nodiscard]] constexpr bool RequiresIPv6() const noexcept {
        return address_family == WolAddressFamily::Dual
            || address_family == WolAddressFamily::IPv6;
    }

    [[nodiscard]] std::optional<Error> Verify() const;
};

class Config {
public:
    [[nodiscard]] static std::expected<Config, Error> FromFile(const char* path);
    [[nodiscard]] static std::expected<Config, Error> FromString(std::string_view str);
    [[nodiscard]] const std::vector<WolConfig>& WolConfigs() const noexcept { return wol_configs_; }
    [[nodiscard]] LogLevel MinLogLevel() const noexcept { return log_level_; }

private:
    // Test-only: builds a Config programmatically, bypassing TOML parsing.
    friend class TestConfigBuilder;

    Config() noexcept = default;
    [[nodiscard]] size_t ReflectorCount() const noexcept { return wol_configs_.size(); }

    std::vector<WolConfig> wol_configs_;
    LogLevel log_level_ = LogLevel::Info;
};

} // namespace reflector

template <>
struct std::formatter<reflector::WolAddressFamily, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for WolAddressFamily");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(reflector::WolAddressFamily address_family, FmtContext& ctx) const {
        switch (address_family) {
        using enum reflector::WolAddressFamily;
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
        if (c.mac.has_value()) {
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
