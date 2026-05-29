#include "config.h"
#include "mac_address.h"

#include <toml++/toml.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>

namespace {

using namespace reflector;

std::string_view ToStringView(const toml::key& key) {
    return std::string_view{key.data(), key.length()};
}

std::expected<std::string_view, Error> ReadStringField(const toml::node& field_node,
        std::string_view section, std::string_view field_name) {
    const auto field_value = field_node.value<std::string_view>();
    if (!field_value.has_value()) {
        // The key is present (we only reach here while iterating existing keys); it just
        // isn't a string. Absent required fields are caught later by the config's Verify().
        return std::unexpected(Error{"{} {} must be a string", section, field_name});
    }
    return *field_value;
}

std::string ToLower(std::string_view s) {
    std::string lower;
    lower.reserve(s.size());
    std::ranges::transform(s, std::back_inserter(lower), [](unsigned char c) {
        // std::tolower requires EOF or a value representable as unsigned char.
        return static_cast<char>(std::tolower(c));
    });
    return lower;
}

std::expected<LogLevel, Error> LogLevelFromString(std::string_view s) {
    const auto lower = ToLower(s);
    if (lower == "debug") return LogLevel::Debug;
    if (lower == "info") return LogLevel::Info;
    if (lower == "warning") return LogLevel::Warning;
    if (lower == "error") return LogLevel::Error;
    return std::unexpected(Error{"log_level must be one of: debug, info, warning, error; got \"{}\"", s});
}

std::expected<AddressFamily, Error> AddressFamilyFromString(std::string_view section, std::string_view s) {
    const auto lower = ToLower(s);
    if (lower == "default") return AddressFamily::Default;
    if (lower == "dual") return AddressFamily::Dual;
    if (lower == "ipv4") return AddressFamily::IPv4;
    if (lower == "ipv6") return AddressFamily::IPv6;
    return std::unexpected(Error{
        "{} address_family must be one of: default, dual, ipv4, ipv6; got \"{}\"", section, s});
}

std::expected<std::vector<uint16_t>, Error> ReadPorts(const toml::node& ports_node) {
    const auto* ports_array = ports_node.as_array();
    if (!ports_array) {
        return std::unexpected(Error{"wol ports is not an array"});
    }
    if (ports_array->empty()) {
        return std::unexpected(Error{"wol ports is empty"});
    }

    std::vector<uint16_t> ports;
    ports.reserve(ports_array->size());
    for (const auto& port_node : *ports_array) {
        const auto port = port_node.value<uint16_t>();
        if (!port.has_value()) {
            return std::unexpected(Error{"wol ports entry is not an integer"});
        }
        ports.push_back(*port);
    }

    return ports;
}

bool MacSelectionsOverlap(const std::optional<MacAddress>& lhs, const std::optional<MacAddress>& rhs) noexcept {
    return !lhs.has_value() || !rhs.has_value() || lhs == rhs;
}

bool PortsOverlap(const std::vector<uint16_t>& lhs, const std::vector<uint16_t>& rhs) noexcept {
    for (const auto port : lhs) {
        if (std::ranges::find(rhs, port) != rhs.end()) {
            return true;
        }
    }
    return false;
}

// Two rules can reflect the same captured packet only if they both handle its IP version.
// A captured datagram is v4 or v6, so an ipv4-only rule and an ipv6-only rule never
// collide; "default"/"dual" handle both and overlap with either.
bool AddressFamiliesOverlap(AddressFamily lhs, AddressFamily rhs) noexcept {
    return (UsesIPv4(lhs) && UsesIPv4(rhs)) || (UsesIPv6(lhs) && UsesIPv6(rhs));
}

std::expected<WolConfig, Error> ReadWolConfig(const toml::table& entry_table) {
    WolConfig wol_config{};
    for (const auto& [field_key, field_node] : entry_table) {
        const auto field_name = ToStringView(field_key);
        if (field_name == "name") {
            auto field_value = ReadStringField(field_node, "wol", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.name = *field_value;
        } else if (field_name == "mac") {
            auto field_value = ReadStringField(field_node, "wol", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            auto mac = MacAddress::FromString(*field_value);
            if (!mac.has_value()) {
                return std::unexpected(Error{"wol mac is not a valid MAC address: \"{}\": {}", *field_value, mac.error()});
            }
            wol_config.mac = *mac;
        } else if (field_name == "source_if") {
            auto field_value = ReadStringField(field_node, "wol", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.source_if = *field_value;
        } else if (field_name == "target_if") {
            auto field_value = ReadStringField(field_node, "wol", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.target_if = *field_value;
        } else if (field_name == "ports") {
            auto ports = ReadPorts(field_node);
            if (!ports.has_value()) {
                return std::unexpected(std::move(ports).error());
            }
            wol_config.ports = std::move(*ports);
        } else if (field_name == "address_family") {
            const auto field_value = field_node.value<std::string_view>();
            if (!field_value.has_value()) {
                return std::unexpected(Error{"wol address_family must be a string"});
            }
            auto address_family = AddressFamilyFromString("wol", *field_value);
            if (!address_family.has_value()) {
                return std::unexpected(std::move(address_family).error());
            }
            wol_config.address_family = *address_family;
        } else {
            return std::unexpected(Error{"unexpected wol option: {}", field_name});
        }
    }
    return wol_config;
}

std::expected<std::vector<WolConfig>, Error> ReadWolConfigs(const toml::node& wol_node) {
    const auto* wol_array = wol_node.as_array();
    if (!wol_array) {
        return std::unexpected(Error{"wol node is not an array"});
    }

    std::vector<WolConfig> wol_configs;
    wol_configs.reserve(wol_array->size());

    for (const auto& entry_node : *wol_array) {
        const auto* entry_table = entry_node.as_table();
        if (!entry_table) {
            return std::unexpected(Error{"wol entry is not a table"});
        }

        auto wol_config = ReadWolConfig(*entry_table);
        if (!wol_config.has_value()) {
            return std::unexpected(std::move(wol_config).error());
        }
        if (auto error = wol_config->Verify()) {
            return std::unexpected(*std::move(error));
        }
        for (const auto& existing : wol_configs) {
            if (existing.name == wol_config->name) {
                return std::unexpected(Error{"duplicate wol name: \"{}\"", wol_config->name});
            }
            if (MacSelectionsOverlap(existing.mac, wol_config->mac)
                    && existing.source_if == wol_config->source_if
                    && existing.target_if == wol_config->target_if
                    && PortsOverlap(existing.ports, wol_config->ports)
                    && AddressFamiliesOverlap(existing.address_family, wol_config->address_family)) {
                return std::unexpected(Error{
                    "duplicate wol rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, ports, and address family",
                    existing.name, wol_config->name});
            }
        }
        wol_configs.push_back(std::move(*wol_config));
    }

    return wol_configs;
}

std::expected<MdnsConfig, Error> ReadMdnsConfig(const toml::table& entry_table) {
    MdnsConfig mdns_config{};
    for (const auto& [field_key, field_node] : entry_table) {
        const auto field_name = ToStringView(field_key);
        if (field_name == "name") {
            auto field_value = ReadStringField(field_node, "mdns", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            mdns_config.name = *field_value;
        } else if (field_name == "mac") {
            auto field_value = ReadStringField(field_node, "mdns", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            auto mac = MacAddress::FromString(*field_value);
            if (!mac.has_value()) {
                return std::unexpected(Error{"mdns mac is not a valid MAC address: \"{}\": {}", *field_value, mac.error()});
            }
            mdns_config.mac = *mac;
        } else if (field_name == "source_if") {
            auto field_value = ReadStringField(field_node, "mdns", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            mdns_config.source_if = *field_value;
        } else if (field_name == "target_if") {
            auto field_value = ReadStringField(field_node, "mdns", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            mdns_config.target_if = *field_value;
        } else if (field_name == "address_family") {
            const auto field_value = field_node.value<std::string_view>();
            if (!field_value.has_value()) {
                return std::unexpected(Error{"mdns address_family must be a string"});
            }
            auto address_family = AddressFamilyFromString("mdns", *field_value);
            if (!address_family.has_value()) {
                return std::unexpected(std::move(address_family).error());
            }
            mdns_config.address_family = *address_family;
        } else {
            return std::unexpected(Error{"unexpected mdns option: {}", field_name});
        }
    }
    return mdns_config;
}

std::expected<std::vector<MdnsConfig>, Error> ReadMdnsConfigs(const toml::node& mdns_node) {
    const auto* mdns_array = mdns_node.as_array();
    if (!mdns_array) {
        return std::unexpected(Error{"mdns node is not an array"});
    }

    std::vector<MdnsConfig> mdns_configs;
    mdns_configs.reserve(mdns_array->size());
    for (const auto& entry_node : *mdns_array) {
        const auto* entry_table = entry_node.as_table();
        if (!entry_table) {
            return std::unexpected(Error{"mdns entry is not a table"});
        }

        auto mdns_config = ReadMdnsConfig(*entry_table);
        if (!mdns_config.has_value()) {
            return std::unexpected(std::move(mdns_config).error());
        }
        if (auto error = mdns_config->Verify()) {
            return std::unexpected(*std::move(error));
        }
        for (const auto& existing : mdns_configs) {
            if (existing.name == mdns_config->name) {
                return std::unexpected(Error{"duplicate mdns name: \"{}\"", mdns_config->name});
            }
            if (MacSelectionsOverlap(existing.mac, mdns_config->mac)
                    && existing.source_if == mdns_config->source_if
                    && existing.target_if == mdns_config->target_if
                    && AddressFamiliesOverlap(existing.address_family, mdns_config->address_family)) {
                return std::unexpected(Error{
                    "duplicate mdns rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                    existing.name, mdns_config->name});
            }
        }
        mdns_configs.push_back(std::move(*mdns_config));
    }

    return mdns_configs;
}

std::expected<SsdpConfig, Error> ReadSsdpConfig(const toml::table& entry_table) {
    SsdpConfig ssdp_config{};
    for (const auto& [field_key, field_node] : entry_table) {
        const auto field_name = ToStringView(field_key);
        if (field_name == "name") {
            auto field_value = ReadStringField(field_node, "ssdp", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            ssdp_config.name = *field_value;
        } else if (field_name == "mac") {
            auto field_value = ReadStringField(field_node, "ssdp", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            auto mac = MacAddress::FromString(*field_value);
            if (!mac.has_value()) {
                return std::unexpected(Error{"ssdp mac is not a valid MAC address: \"{}\": {}", *field_value, mac.error()});
            }
            ssdp_config.mac = *mac;
        } else if (field_name == "source_if") {
            auto field_value = ReadStringField(field_node, "ssdp", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            ssdp_config.source_if = *field_value;
        } else if (field_name == "target_if") {
            auto field_value = ReadStringField(field_node, "ssdp", field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            ssdp_config.target_if = *field_value;
        } else if (field_name == "address_family") {
            const auto field_value = field_node.value<std::string_view>();
            if (!field_value.has_value()) {
                return std::unexpected(Error{"ssdp address_family must be a string"});
            }
            auto address_family = AddressFamilyFromString("ssdp", *field_value);
            if (!address_family.has_value()) {
                return std::unexpected(std::move(address_family).error());
            }
            ssdp_config.address_family = *address_family;
        } else {
            return std::unexpected(Error{"unexpected ssdp option: {}", field_name});
        }
    }
    return ssdp_config;
}

std::expected<std::vector<SsdpConfig>, Error> ReadSsdpConfigs(const toml::node& ssdp_node) {
    const auto* ssdp_array = ssdp_node.as_array();
    if (!ssdp_array) {
        return std::unexpected(Error{"ssdp node is not an array"});
    }

    std::vector<SsdpConfig> ssdp_configs;
    ssdp_configs.reserve(ssdp_array->size());
    for (const auto& entry_node : *ssdp_array) {
        const auto* entry_table = entry_node.as_table();
        if (!entry_table) {
            return std::unexpected(Error{"ssdp entry is not a table"});
        }

        auto ssdp_config = ReadSsdpConfig(*entry_table);
        if (!ssdp_config.has_value()) {
            return std::unexpected(std::move(ssdp_config).error());
        }
        if (auto error = ssdp_config->Verify()) {
            return std::unexpected(*std::move(error));
        }
        for (const auto& existing : ssdp_configs) {
            if (existing.name == ssdp_config->name) {
                return std::unexpected(Error{"duplicate ssdp name: \"{}\"", ssdp_config->name});
            }
            if (MacSelectionsOverlap(existing.mac, ssdp_config->mac)
                    && existing.source_if == ssdp_config->source_if
                    && existing.target_if == ssdp_config->target_if
                    && AddressFamiliesOverlap(existing.address_family, ssdp_config->address_family)) {
                return std::unexpected(Error{
                    "duplicate ssdp rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                    existing.name, ssdp_config->name});
            }
        }
        ssdp_configs.push_back(std::move(*ssdp_config));
    }

    return ssdp_configs;
}

} // namespace

namespace reflector {

std::optional<Error> WolConfig::Verify() const {
    if (name.empty()) {
        return Error{"wol name is not configured"};
    }
    if (source_if.empty()) {
        return Error{"wol source_if is not configured"};
    }
    if (target_if.empty()) {
        return Error{"wol target_if is not configured"};
    }
    if (source_if == target_if) {
        return Error{"wol source_if and target_if must be different: \"{}\"", source_if};
    }
    if (ports.empty()) {
        return Error{"wol ports is empty"};
    }
    for (const auto port : ports) {
        if (port == 0) {
            return Error{"wol port cannot be 0"};
        }
    }
    auto sorted_ports = ports;
    std::ranges::sort(sorted_ports);
    if (const auto it = std::ranges::adjacent_find(sorted_ports); it != sorted_ports.end()) {
        return Error{"wol ports contains duplicate port: {}", *it};
    }
    return std::nullopt;
}

std::optional<Error> MdnsConfig::Verify() const {
    if (name.empty()) {
        return Error{"mdns name is not configured"};
    }
    if (source_if.empty()) {
        return Error{"mdns source_if is not configured"};
    }
    if (target_if.empty()) {
        return Error{"mdns target_if is not configured"};
    }
    if (source_if == target_if) {
        return Error{"mdns source_if and target_if must be different: \"{}\"", source_if};
    }
    return std::nullopt;
}

std::optional<Error> SsdpConfig::Verify() const {
    if (name.empty()) {
        return Error{"ssdp name is not configured"};
    }
    if (source_if.empty()) {
        return Error{"ssdp source_if is not configured"};
    }
    if (target_if.empty()) {
        return Error{"ssdp target_if is not configured"};
    }
    if (source_if == target_if) {
        return Error{"ssdp source_if and target_if must be different: \"{}\"", source_if};
    }
    return std::nullopt;
}

std::expected<Config, Error> Config::FromFile(const char* path) {
    std::ifstream file{path};
    if (!file) {
        return std::unexpected(Error{"cannot open file \"{}\"", path});
    }

    std::error_code ec;
    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(Error{"cannot get file size for \"{}\": {} ({})", path, ec.message(), ec.value()});
    }

    std::string contents;
    contents.resize_and_overwrite(static_cast<std::string::size_type>(file_size), [&file](char* buf, size_t buf_size) {
        file.read(buf, static_cast<std::streamsize>(buf_size));
        return static_cast<size_t>(file.gcount());
    });

    return FromString(contents);
}

std::expected<Config, Error> Config::FromString(std::string_view str) {
    auto config = Config{};
    auto parsed = toml::parse(str);
    if (!parsed) {
        const auto& err = parsed.error();
        const auto& src = err.source();
        return std::unexpected(Error{
            "invalid configuration at line {}, column {}: {}",
            src.begin.line, src.begin.column, err.description()});
    }

    const auto root_table = std::move(parsed).table();
    if (root_table.empty()) {
        return std::unexpected(Error{"invalid configuration"});
    }

    for (const auto& [key, value] : root_table) {
        const auto section_name = ToStringView(key);
        if (section_name == "wol") {
            auto wol_configs = ReadWolConfigs(value);
            if (!wol_configs.has_value()) {
                return std::unexpected(Error{"cannot read wol configuration: {}", wol_configs.error().Message()});
            }
            config.wol_configs_ = std::move(*wol_configs);
        } else if (section_name == "mdns") {
            auto mdns_configs = ReadMdnsConfigs(value);
            if (!mdns_configs.has_value()) {
                return std::unexpected(Error{"cannot read mdns configuration: {}", mdns_configs.error().Message()});
            }
            config.mdns_configs_ = std::move(*mdns_configs);
        } else if (section_name == "ssdp") {
            auto ssdp_configs = ReadSsdpConfigs(value);
            if (!ssdp_configs.has_value()) {
                return std::unexpected(Error{"cannot read ssdp configuration: {}", ssdp_configs.error().Message()});
            }
            config.ssdp_configs_ = std::move(*ssdp_configs);
        } else if (section_name == "log_level") {
            const auto field_value = value.value<std::string_view>();
            if (!field_value.has_value()) {
                return std::unexpected(Error{"log_level must be a string"});
            }
            auto level = LogLevelFromString(*field_value);
            if (!level.has_value()) {
                return std::unexpected(std::move(level).error());
            }
            config.log_level_ = *level;
        } else {
            return std::unexpected(Error{"unexpected configuration section: {}", section_name});
        }
    }

    if (config.ReflectorCount() == 0) {
        return std::unexpected(Error{"configuration must contain at least one reflector"});
    }

    return config;
}

} // namespace reflector
