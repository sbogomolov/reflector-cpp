#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace reflector {

// ASCII lowercase of one byte. std::tolower requires an argument representable as unsigned char (or EOF),
// hence the cast through unsigned char.
[[nodiscard]] inline char AsciiToLower(char c) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

// ASCII lowercase copy of `s`.
[[nodiscard]] inline std::string AsciiToLower(std::string_view s) {
    std::string lower;
    lower.reserve(s.size());
    for (const char c : s) {
        lower.push_back(AsciiToLower(c));
    }
    return lower;
}

// Case-insensitive (ASCII) prefix test: does `text` begin with `prefix`? Used to match HTTP/SSDP header
// names (e.g. "application-url:" against "Application-URL:").
[[nodiscard]] inline bool StartsWithNoCase(std::string_view text, std::string_view prefix) noexcept {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (AsciiToLower(text[i]) != AsciiToLower(prefix[i])) {
            return false;
        }
    }
    return true;
}

// Case-insensitive (ASCII) substring test: does `needle` appear anywhere in `haystack`? A naive scan,
// fine for the short strings this matches against (an SSDP datagram, an HTTP header block).
[[nodiscard]] inline bool ContainsNoCase(std::string_view haystack, std::string_view needle) noexcept {
    if (haystack.size() < needle.size()) {
        return false;
    }
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        if (StartsWithNoCase(haystack.substr(i), needle)) {
            return true;
        }
    }
    return false;
}

// `s` with leading ASCII spaces and tabs removed — empty when `s` is entirely spaces/tabs. Skips the
// optional whitespace after an HTTP/SSDP header field's ':'.
[[nodiscard]] inline std::string_view TrimLeadingSpace(std::string_view s) noexcept {
    const size_t first = s.find_first_not_of(" \t");
    return first == std::string_view::npos ? std::string_view{} : s.substr(first);
}

} // namespace reflector
