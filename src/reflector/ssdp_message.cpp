#include "ssdp_message.h"

#include <cstddef>
#include <cstring>
#include <span>
#include <string_view>

namespace reflector {

namespace {

// True if `payload` begins with the ASCII bytes of `token`. Case-sensitive; a payload shorter than
// the token never matches.
bool StartsWith(std::span<const std::byte> payload, std::string_view token) noexcept {
    return payload.size() >= token.size()
        && std::memcmp(payload.data(), token.data(), token.size()) == 0;
}

// The method tokens include the trailing space that separates the method from the request URI, so
// "NOTIFYING" does not match "NOTIFY".
constexpr std::string_view SEARCH_TOKEN = "M-SEARCH ";
constexpr std::string_view ADVERTISEMENT_TOKEN = "NOTIFY ";

} // namespace

std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept {
    if (StartsWith(payload, SEARCH_TOKEN)) {
        return SsdpMessageKind::Search;
    }
    if (StartsWith(payload, ADVERTISEMENT_TOKEN)) {
        return SsdpMessageKind::Advertisement;
    }
    return std::nullopt;
}

} // namespace reflector
