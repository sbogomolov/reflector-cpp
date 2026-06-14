#include "config.h"
#include "mac_address.h"
#include "util/ascii.h"

#include <toml++/toml.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <ios>
#include <map>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <system_error>

namespace {

using namespace reflector;

std::string_view ToStringView(const toml::key& key) {
    return std::string_view{key.data(), key.length()};
}

std::expected<LogLevel, Error> LogLevelFromString(std::string_view s) {
    const auto lower = AsciiToLower(s);
    if (lower == "debug") return LogLevel::Debug;
    if (lower == "info") return LogLevel::Info;
    if (lower == "warning") return LogLevel::Warning;
    if (lower == "error") return LogLevel::Error;
    return std::unexpected(Error{"log_level must be one of: debug, info, warning, error; got \"{}\"", s});
}

std::expected<AddressFamily, Error> AddressFamilyFromString(std::string_view section, std::string_view s) {
    const auto lower = AsciiToLower(s);
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
        if (!port) {
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

// Verify one reflector config and reject it if it duplicates an already-accepted one of the same
// protocol, then append it. Two rules collide when they could reflect the same captured packet:
// overlapping MAC selection, same source_if and target_if, and overlapping address family (WoL also
// requires an overlapping port). Names are not checked here: ConfigAccumulator::AddEntry rejects
// duplicate entry names across every source before an entry's configs are appended.
template <typename ConfigType>
std::optional<Error> AppendConfig(std::vector<ConfigType>& configs, ConfigType config, std::string_view protocol) {
    if (auto error = config.Verify()) {
        return error;
    }
    for (const auto& existing : configs) {
        if (!MacSelectionsOverlap(existing.mac, config.mac)
                || existing.source_if != config.source_if
                || existing.target_if != config.target_if
                || !AddressFamiliesOverlap(existing.address_family, config.address_family)) {
            continue;
        }
        // WoL additionally needs a shared port to collide; mDNS/SSDP carry no ports. if constexpr discards
        // the ports branch for the protocols that lack a `ports` member.
        if constexpr (requires { config.ports; }) {
            if (!PortsOverlap(existing.ports, config.ports)) {
                continue;
            }
            return Error{
                "duplicate {} rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, ports, and address family",
                protocol, existing.name, config.name};
        } else {
            return Error{
                "duplicate {} rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                protocol, existing.name, config.name};
        }
    }
    configs.push_back(std::move(config));
    return std::nullopt;
}

// A single reflector entry's fields, addressed by their lowercase config key. ReadEntry consumes
// this interface so the field parsing and validation are shared and independent of where the values
// come from: a source only surfaces the fields it holds and hands back each one as the type that
// field expects (string, bool, or a port list). TomlSource reads a parsed toml::table; EnvSource
// reads REFLECTOR_* environment variables, coercing their string values to the expected types.
class ConfigSource {
public:
    ConfigSource() = default;
    ConfigSource(const ConfigSource&) = delete;
    ConfigSource& operator=(const ConfigSource&) = delete;
    virtual ~ConfigSource() = default;

    // The entry's display name (TOML table key, or env tag / NAME), used in errors and as the label.
    [[nodiscard]] virtual std::string_view Name() const = 0;
    // The field keys present in this entry, so the caller can dispatch known fields and reject unknown ones.
    [[nodiscard]] virtual std::vector<std::string_view> Keys() const = 0;
    // The three value shapes reflector fields reduce to. `key` is always one returned by Keys().
    [[nodiscard]] virtual std::expected<std::string_view, Error> GetString(std::string_view key) const = 0;
    [[nodiscard]] virtual std::expected<bool, Error> GetBool(std::string_view key) const = 0;
    [[nodiscard]] virtual std::expected<std::vector<uint16_t>, Error> GetPorts(std::string_view key) const = 0;
};

// --- TOML backend: extract field values from a parsed toml::table ---

class TomlSource final : public ConfigSource {
public:
    TomlSource(std::string_view name, const toml::table& table) noexcept : name_{name}, table_{&table} {}

    [[nodiscard]] std::string_view Name() const override { return name_; }

    [[nodiscard]] std::vector<std::string_view> Keys() const override {
        // toml++'s iterator pair isn't tuple-like, so std::views::keys doesn't apply; transform .first.
        return *table_
            | std::views::transform([](const auto& entry) { return ToStringView(entry.first); })
            | std::ranges::to<std::vector<std::string_view>>();
    }

    [[nodiscard]] std::expected<std::string_view, Error> GetString(std::string_view key) const override {
        const auto value = table_->get(key)->value<std::string_view>();
        if (!value) {
            return std::unexpected(Error{"entry \"{}\" {} must be a string", name_, key});
        }
        return *value;
    }

    [[nodiscard]] std::expected<bool, Error> GetBool(std::string_view key) const override {
        const auto value = table_->get(key)->value<bool>();
        if (!value) {
            return std::unexpected(Error{"entry \"{}\" {} must be a boolean", name_, key});
        }
        return *value;
    }

    [[nodiscard]] std::expected<std::vector<uint16_t>, Error> GetPorts(std::string_view key) const override {
        return ReadPorts(*table_->get(key));
    }

private:
    std::string_view name_;
    const toml::table* table_;
};

// --- Environment backend: extract field values from REFLECTOR_<tag>_<param> strings ---

using EnvParams = std::map<std::string, std::string, std::less<>>;

// Environment values are strings, so a boolean must be spelled out. true/false mirror TOML; 1/0 are
// accepted too since they are the natural booleans for shell/Docker env files.
std::expected<bool, Error> ParseEnvBool(std::string_view name, std::string_view key, std::string_view value) {
    const auto lower = AsciiToLower(value);
    if (lower == "true" || lower == "1") {
        return true;
    }
    if (lower == "false" || lower == "0") {
        return false;
    }
    return std::unexpected(Error{"entry \"{}\" {} must be true/false or 1/0; got \"{}\"", name, key, value});
}

// Environment arrays are comma-separated (e.g. "7,9"), since env vars can't hold a TOML array.
std::expected<std::vector<uint16_t>, Error> ParseEnvPorts(std::string_view name, std::string_view value) {
    std::vector<uint16_t> ports;
    for (size_t pos = 0; pos <= value.size();) {
        const auto comma = value.find(',', pos);
        const auto end = comma == std::string_view::npos ? value.size() : comma;
        auto token = value.substr(pos, end - pos);
        const auto first = token.find_first_not_of(" \t");
        const auto last = token.find_last_not_of(" \t");
        token = first == std::string_view::npos ? std::string_view{} : token.substr(first, last - first + 1);
        if (token.empty()) {
            return std::unexpected(Error{"entry \"{}\" wol_ports has an empty entry in \"{}\"", name, value});
        }
        uint16_t port = 0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), port);
        if (ec != std::errc{} || ptr != token.data() + token.size()) {
            return std::unexpected(Error{"entry \"{}\" wol_ports entry is not a valid port: \"{}\"", name, token});
        }
        ports.push_back(port);
        if (comma == std::string_view::npos) {
            break;
        }
        pos = comma + 1;
    }
    return ports;
}

class EnvSource final : public ConfigSource {
public:
    EnvSource(std::string name, EnvParams params) : name_{std::move(name)}, params_{std::move(params)} {}

    [[nodiscard]] std::string_view Name() const override { return name_; }

    [[nodiscard]] std::vector<std::string_view> Keys() const override {
        return params_ | std::views::keys | std::ranges::to<std::vector<std::string_view>>();
    }

    [[nodiscard]] std::expected<std::string_view, Error> GetString(std::string_view key) const override {
        return std::string_view{params_.find(key)->second};
    }

    [[nodiscard]] std::expected<bool, Error> GetBool(std::string_view key) const override {
        return ParseEnvBool(name_, key, params_.find(key)->second);
    }

    [[nodiscard]] std::expected<std::vector<uint16_t>, Error> GetPorts(std::string_view key) const override {
        return ParseEnvPorts(name_, params_.find(key)->second);
    }

private:
    std::string name_;
    EnvParams params_;
};

// Reads one entry from any source and appends a reflector config for each protocol it enables. The
// entry's shared fields (mac, source_if, target_if, address_family) flow to every enabled protocol;
// for a real device the one mac is both the WoL target and the mDNS/SSDP frame source.
std::optional<Error> ReadEntry(const ConfigSource& source,
        std::vector<WolConfig>& wol_configs, std::vector<MdnsConfig>& mdns_configs,
        std::vector<SsdpConfig>& ssdp_configs) {
    const auto name = source.Name();
    std::string source_if;
    std::string target_if;
    std::optional<MacAddress> mac;
    std::optional<std::vector<uint16_t>> wol_ports;
    bool wol = false;
    bool mdns = false;
    bool ssdp = false;
    bool dial = false;
    AddressFamily address_family = AddressFamily::Default;

    for (const auto field_name : source.Keys()) {
        if (field_name == "source_if") {
            auto value = source.GetString(field_name);
            if (!value) {
                return std::move(value).error();
            }
            source_if = *value;
        } else if (field_name == "target_if") {
            auto value = source.GetString(field_name);
            if (!value) {
                return std::move(value).error();
            }
            target_if = *value;
        } else if (field_name == "mac") {
            auto value = source.GetString(field_name);
            if (!value) {
                return std::move(value).error();
            }
            auto parsed = MacAddress::FromString(*value);
            if (!parsed) {
                return Error{"entry \"{}\" mac is not a valid MAC address: \"{}\": {}", name, *value, parsed.error()};
            }
            mac = *parsed;
        } else if (field_name == "wol_ports") {
            auto ports = source.GetPorts(field_name);
            if (!ports) {
                return std::move(ports).error();
            }
            wol_ports = std::move(*ports);
        } else if (field_name == "wol" || field_name == "mdns" || field_name == "ssdp"
                || field_name == "dial") {
            auto flag = source.GetBool(field_name);
            if (!flag) {
                return std::move(flag).error();
            }
            if (field_name == "wol") {
                wol = *flag;
            } else if (field_name == "mdns") {
                mdns = *flag;
            } else if (field_name == "ssdp") {
                ssdp = *flag;
            } else {
                dial = *flag;
            }
        } else if (field_name == "address_family") {
            auto value = source.GetString(field_name);
            if (!value) {
                return std::move(value).error();
            }
            auto parsed = AddressFamilyFromString("entry", *value);
            if (!parsed) {
                return std::move(parsed).error();
            }
            address_family = *parsed;
        } else {
            return Error{"unexpected option in entry \"{}\": {}", name, field_name};
        }
    }

    if (!wol && !mdns && !ssdp) {
        return Error{"entry \"{}\" enables no protocol (set wol, mdns, or ssdp)", name};
    }
    if (wol_ports && !wol) {
        return Error{"entry \"{}\" sets wol_ports but does not enable wol", name};
    }
    if (dial && !ssdp) {
        return Error{"entry \"{}\" sets dial but does not enable ssdp", name};
    }

    if (wol) {
        WolConfig config{
            .name = std::string{name},
            .mac = mac,
            .source_if = source_if,
            .target_if = target_if,
            .address_family = address_family,
        };
        if (wol_ports) {
            config.ports = *wol_ports;
        }
        if (auto error = AppendConfig(wol_configs, std::move(config), "wol")) {
            return error;
        }
    }
    if (mdns) {
        if (auto error = AppendConfig(mdns_configs, MdnsConfig{
                .name = std::string{name}, .mac = mac, .source_if = source_if,
                .target_if = target_if, .address_family = address_family}, "mdns")) {
            return error;
        }
    }
    if (ssdp) {
        if (auto error = AppendConfig(ssdp_configs, SsdpConfig{
                .name = std::string{name}, .mac = mac, .source_if = source_if,
                .target_if = target_if, .address_family = address_family, .dial = dial}, "ssdp")) {
            return error;
        }
    }
    return std::nullopt;
}

// Accumulates reflector entries (and the optional log level) from one or more sources. Entry names
// must be unique across every source. Sources are applied in order and the last log level set wins,
// which is how the environment overrides the file's log_level.
struct ConfigAccumulator {
    std::vector<WolConfig> wol;
    std::vector<MdnsConfig> mdns;
    std::vector<SsdpConfig> ssdp;
    std::optional<LogLevel> log_level;
    std::vector<std::string> entry_names;

    std::optional<Error> AddEntry(const ConfigSource& source) {
        const auto name = source.Name();
        if (std::ranges::find(entry_names, name) != entry_names.end()) {
            return Error{"duplicate entry name \"{}\"", name};
        }
        entry_names.emplace_back(name);
        return ReadEntry(source, wol, mdns, ssdp);
    }
};

std::optional<Error> ApplyToml(ConfigAccumulator& acc, std::string_view str) {
    auto parsed = toml::parse(str);
    if (!parsed) {
        const auto& err = parsed.error();
        const auto& src = err.source();
        return Error{"invalid configuration at line {}, column {}: {}",
            src.begin.line, src.begin.column, err.description()};
    }

    const auto root_table = std::move(parsed).table();
    for (const auto& [key, value] : root_table) {
        const auto key_name = ToStringView(key);
        // A top-level table is a reflector entry (its key is the entry name); the lone known scalar
        // is log_level; any other top-level scalar is a mistyped setting.
        if (const auto* entry_table = value.as_table()) {
            const TomlSource source{key_name, *entry_table};
            if (auto error = acc.AddEntry(source)) {
                return error;
            }
        } else if (key_name == "log_level") {
            const auto field_value = value.value<std::string_view>();
            if (!field_value) {
                return Error{"log_level must be a string"};
            }
            auto level = LogLevelFromString(*field_value);
            if (!level) {
                return std::move(level).error();
            }
            acc.log_level = *level;
        } else {
            return Error{"unexpected top-level key: \"{}\" (expected an entry table or log_level)", key_name};
        }
    }
    return std::nullopt;
}

// A tag is the <tag> in REFLECTOR_<tag>_<param>. Restricting it to alphanumerics keeps the split on
// the first underscore unambiguous even though parameter names contain underscores (source_if, etc.).
bool IsAlnumTag(std::string_view tag) noexcept {
    return !tag.empty() && std::ranges::all_of(tag, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    });
}

std::optional<Error> ApplyEnv(ConfigAccumulator& acc, std::span<const EnvVar> env_vars) {
    constexpr std::string_view prefix = "REFLECTOR_";
    constexpr std::string_view log_level_var = "REFLECTOR_LOG_LEVEL";

    std::optional<std::string_view> log_level_value;
    // tag -> (lowercase param -> value). std::map gives a deterministic (sorted) entry order so that
    // duplicate-detection errors and tests don't depend on environ ordering.
    std::map<std::string, EnvParams, std::less<>> tags;

    for (const auto& var : env_vars) {
        if (!var.key.starts_with(prefix)) {
            continue;
        }
        if (var.key == log_level_var) {
            log_level_value = var.value;
            continue;
        }
        const auto rest = var.key.substr(prefix.size());
        const auto underscore = rest.find('_');
        if (underscore == std::string_view::npos) {
            return Error{"environment variable \"{}\" is not of the form REFLECTOR_<tag>_<param>", var.key};
        }
        const auto tag = rest.substr(0, underscore);
        const auto param = rest.substr(underscore + 1);
        if (!IsAlnumTag(tag)) {
            return Error{"environment variable \"{}\" has an invalid tag \"{}\" (use letters and digits only)", var.key, tag};
        }
        if (AsciiToLower(tag) == "log") {
            return Error{"environment variable \"{}\": \"{}\" is a reserved tag (use REFLECTOR_LOG_LEVEL for the log level)", var.key, tag};
        }
        if (param.empty()) {
            return Error{"environment variable \"{}\" is missing a parameter name after the tag", var.key};
        }
        tags[std::string{tag}].insert_or_assign(AsciiToLower(param), std::string{var.value});
    }

    if (log_level_value) {
        auto level = LogLevelFromString(*log_level_value);
        if (!level) {
            return std::move(level).error();
        }
        acc.log_level = *level;
    }

    for (auto& [tag, params] : tags) {
        // NAME, when given, becomes the entry name; otherwise the tag doubles as the name. NAME is not
        // a reflector field, so it never reaches ReadEntry.
        std::string name = tag;
        if (const auto it = params.find("name"); it != params.end()) {
            name = it->second;
            params.erase(it);
        }
        const EnvSource source{std::move(name), std::move(params)};
        if (auto error = acc.AddEntry(source)) {
            return error;
        }
    }
    return std::nullopt;
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
    if (dial && !UsesIPv4()) {
        return Error{"ssdp entry \"{}\" enables dial but has no IPv4 family (DIAL is IPv4-only)", name};
    }
    return std::nullopt;
}

std::expected<std::string, Error> Config::ReadFileToString(const char* path) {
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

    return contents;
}

std::expected<Config, Error> Config::FromString(std::string_view str) {
    return Load(str, std::span<const EnvVar>{});
}

std::expected<Config, Error> Config::Load(std::optional<std::string_view> toml_text,
        std::span<const EnvVar> env_vars) {
    ConfigAccumulator acc;
    if (toml_text) {
        if (auto error = ApplyToml(acc, *toml_text)) {
            return std::unexpected(*std::move(error));
        }
    }
    if (auto error = ApplyEnv(acc, env_vars)) {
        return std::unexpected(*std::move(error));
    }

    Config config;
    config.wol_configs_ = std::move(acc.wol);
    config.mdns_configs_ = std::move(acc.mdns);
    config.ssdp_configs_ = std::move(acc.ssdp);
    config.log_level_ = acc.log_level.value_or(LogLevel::Info);
    if (config.ReflectorCount() == 0) {
        return std::unexpected(Error{"configuration must contain at least one reflector"});
    }
    return config;
}

} // namespace reflector
