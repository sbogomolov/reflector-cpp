#include "entries.h"

#include <algorithm>
#include <optional>

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

} // namespace reflector
