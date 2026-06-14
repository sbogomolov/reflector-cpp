#pragma once

#include "address_family.h"

#include "reflector/error.h"
#include "reflector/mac_address.h"

#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace reflector {

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
