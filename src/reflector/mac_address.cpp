#include "mac_address.h"

#include <cstring>

namespace {

int HexValue(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

} // namespace

namespace reflector {

std::expected<MacAddress, Error> MacAddress::FromString(std::string_view mac) {
    constexpr size_t MAC_ADDRESS_LENGTH = 17; // "XX:XX:XX:XX:XX:XX"
    if (mac.size() != MAC_ADDRESS_LENGTH) {
        return std::unexpected(Error{"MAC address has invalid length: {}", mac.size()});
    }

    ByteArray bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        const auto high = HexValue(mac[i * 3]);
        const auto low = HexValue(mac[i * 3 + 1]);
        if (high < 0 || low < 0) {
            return std::unexpected(Error{"MAC address contains non-hex byte at index {}", i});
        }
        if (i < bytes.size() - 1 && mac[i * 3 + 2] != ':') {
            return std::unexpected(Error{"MAC address separator at index {} is not ':'", i});
        }
        bytes[i] = static_cast<std::byte>((high << 4) | low);
    }

    return MacAddress{bytes};
}

MacAddress MacAddress::FromBytes(std::span<const std::byte, 6> bytes) noexcept {
    ByteArray copy{};
    std::memcpy(copy.data(), bytes.data(), bytes.size());
    return MacAddress{copy};
}

} // namespace reflector
