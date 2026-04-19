#include "ip_address.h"

#include "reflector/error.h"

#include <arpa/inet.h>
#include <netinet/in.h>

namespace reflector {

IpAddress IpAddress::Loopback() noexcept {
    return FromBytes(127, 0, 0, 1);
}

IpAddress IpAddress::FromBytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept {
    const auto host_order_address = (static_cast<uint32_t>(a) << 24)
        | (static_cast<uint32_t>(b) << 16)
        | (static_cast<uint32_t>(c) << 8)
        | static_cast<uint32_t>(d);
    return IpAddress{htonl(host_order_address)};
}

std::optional<IpAddress> IpAddress::FromString(std::string_view address) {
    if (address.empty() || address == "*" || address == "0.0.0.0") {
        return Any();
    }

    in_addr parsed{};
    const auto address_str = std::string{address};
    const auto parse_result = inet_pton(AF_INET, address_str.c_str(), &parsed);
    if (parse_result == 0) {
        logger_.Error("Cannot parse IPv4 address \"{}\"", address);
        return std::nullopt;
    }
    if (parse_result < 0) {
        logger_.Error("Cannot parse IPv4 address \"{}\": {}", address, Error::FromErrno());
        return std::nullopt;
    }

    return FromInAddr(parsed.s_addr);
}

std::string IpAddress::ToString() const {
    in_addr address{};
    address.s_addr = address_;

    std::string result;
    result.resize(INET_ADDRSTRLEN);
    if (inet_ntop(AF_INET, &address, result.data(), result.size()) == nullptr) {
        logger_.Error("Cannot convert IPv4 address to string: {}", Error::FromErrno());
        return {};
    }

    result.resize(std::char_traits<char>::length(result.c_str()));
    return result;
}

} // namespace reflector
