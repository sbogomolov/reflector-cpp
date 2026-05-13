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

std::expected<std::string_view, Error> ReadStringField(const toml::node& field_node, std::string_view field_name) {
    const auto field_value = field_node.value<std::string_view>();
    if (!field_value.has_value()) {
        return std::unexpected(Error{"wol {} is not configured", field_name});
    }
    return *field_value;
}

std::expected<LogLevel, Error> LogLevelFromString(std::string_view s) {
    std::string lower;
    lower.reserve(s.size());
    std::ranges::transform(s, std::back_inserter(lower), [](unsigned char c) { return std::tolower(c); });
    if (lower == "debug") return LogLevel::Debug;
    if (lower == "info") return LogLevel::Info;
    if (lower == "warning") return LogLevel::Warning;
    if (lower == "error") return LogLevel::Error;
    return std::unexpected(Error{"log_level must be one of: debug, info, warning, error; got \"{}\"", s});
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

std::expected<WolConfig, Error> ReadWolConfig(const toml::table& entry_table) {
    WolConfig wol_config{};
    for (const auto& [field_key, field_node] : entry_table) {
        const auto field_name = ToStringView(field_key);
        if (field_name == "name") {
            auto field_value = ReadStringField(field_node, field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.name = *field_value;
        }
        else if (field_name == "mac") {
            auto field_value = ReadStringField(field_node, field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            auto mac = MacAddress::FromString(*field_value);
            if (!mac.has_value()) {
                return std::unexpected(Error{"wol mac is not a valid MAC address: \"{}\": {}", *field_value, mac.error()});
            }
            wol_config.mac = *mac;
        }
        else if (field_name == "source_if") {
            auto field_value = ReadStringField(field_node, field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.source_if = *field_value;
        }
        else if (field_name == "target_if") {
            auto field_value = ReadStringField(field_node, field_name);
            if (!field_value.has_value()) {
                return std::unexpected(std::move(field_value).error());
            }
            wol_config.target_if = *field_value;
        }
        else if (field_name == "ports") {
            auto ports = ReadPorts(field_node);
            if (!ports.has_value()) {
                return std::unexpected(std::move(ports).error());
            }
            wol_config.ports = std::move(*ports);
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
            if (existing.mac == wol_config->mac
                    && existing.source_if == wol_config->source_if
                    && existing.target_if == wol_config->target_if) {
                return std::unexpected(Error{
                    "duplicate wol rule: \"{}\" and \"{}\" share mac, source_if, and target_if",
                    existing.name, wol_config->name});
            }
        }
        wol_configs.push_back(std::move(*wol_config));
    }

    return wol_configs;
}

} // namespace

namespace reflector {

std::optional<Error> WolConfig::Verify() const {
    if (name.empty()) {
        return Error{"wol name is not configured"};
    }
    if (!mac.IsValid()) {
        return Error{"wol mac is not configured (or is the unsupported all-zero address)"};
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
