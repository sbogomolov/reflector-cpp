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

} // namespace reflector
