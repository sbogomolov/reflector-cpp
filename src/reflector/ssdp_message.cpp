#include "ssdp_message.h"

#include "http_message.h"
#include "logger.h"
#include "util/ascii.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

namespace {

using namespace reflector;

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

constexpr uint8_t MX_MIN = 1;
constexpr uint8_t MX_MAX = 5;

// The stable prefix of the DIAL service-type URN (the trailing ":1" version is dropped to match any version).
constexpr std::string_view DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial";

Logger& GetLogger() noexcept {
    static Logger logger{"SsdpMessage"};
    return logger;
}

} // namespace

namespace reflector {

std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept {
    if (StartsWith(payload, SEARCH_TOKEN)) {
        return SsdpMessageKind::Search;
    }
    if (StartsWith(payload, ADVERTISEMENT_TOKEN)) {
        return SsdpMessageKind::Advertisement;
    }
    return std::nullopt;
}

std::optional<uint8_t> ParseMSearchMx(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    size_t pos = 0;
    while (pos < text.size()) {
        const auto end = text.find("\r\n", pos);
        const auto line = text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
        if (StartsWithNoCase(line, "MX:")) {
            const auto value = TrimLeadingSpace(line.substr(3));
            if (!value.empty()) {
                unsigned parsed = 0;
                const auto* begin = value.data();
                const auto* stop = value.data() + value.size();
                if (std::from_chars(begin, stop, parsed).ec == std::errc{}) {
                    return static_cast<uint8_t>(std::clamp<unsigned>(parsed, MX_MIN, MX_MAX));
                }
            }
            return std::nullopt;  // MX present but unparseable
        }
        if (end == std::string_view::npos) {
            break;
        }
        pos = end + 2;
    }
    return std::nullopt;  // no MX header at all
}

bool IsDialServiceMessage(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    return ContainsNoCase(text, DIAL_SERVICE_TYPE);
}

std::optional<Authority> ParseDialLocationAuthority(std::span<const std::byte> payload) noexcept {
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};
    constexpr std::string_view header{"LOCATION:"};
    size_t pos = 0;
    while (pos < text.size()) {
        const auto end = text.find("\r\n", pos);
        const auto line = text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
        if (StartsWithNoCase(line, header)) {
            const auto url = TrimLeadingSpace(line.substr(header.size()));  // the LOCATION URL, a view into `text`
            if (url.empty()) {
                return std::nullopt;
            }
            const auto found = ParseAuthority(url, /*bare=*/false);
            if (!found) {
                // A DIAL message carrying a LOCATION we cannot rewrite (an https URL, a hostname rather than
                // an IPv4 literal, or a malformed port). The caller forwards it unchanged, so surface why.
                GetLogger().Info("DIAL LOCATION \"{}\" is not a rewritable http://ip:port URL", url);
                return std::nullopt;
            }
            // Map the authority's offset within the URL back to an offset within the whole payload.
            const size_t offset = static_cast<size_t>(url.data() - text.data()) + found->offset;
            return Authority{found->endpoint, offset, found->length};
        }
        if (end == std::string_view::npos) {
            break;
        }
        pos = end + 2;
    }
    return std::nullopt;
}

} // namespace reflector
