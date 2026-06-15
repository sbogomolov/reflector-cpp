#include "interface.h"

#include "error.h"
#include "platform.h"

#include <format>
#include <net/if.h>

namespace reflector {

Interface::Interface(std::string_view name)
        : logger_{std::format("Interface:{}", name)}
        , name_{name} {
    // Guard before any name lookup: if_nametoindex (and BPF's BIOCSETIF) copy into a fixed
    // IFNAMSIZ buffer, so an over-long name would be silently truncated and could match the
    // wrong interface.
    if (name_.size() >= IFNAMSIZ) {
        logger_.Error("Interface name \"{}\" is too long (max {} characters)", name_, IFNAMSIZ - 1);
        return;
    }
    index_ = if_nametoindex(name_.c_str());
    if (index_ == 0) {
        logger_.Error("Cannot resolve interface index: {}", Error::FromErrno());
        return;
    }
    // In-constructor dispatch resolves to Interface::Refresh — intended: construction always
    // performs a real resolve, regardless of what a derived test fake overrides.
    Refresh();
}

Interface::Interface(std::string_view name, unsigned index, const InterfaceAddresses& addresses) noexcept
        : addresses_{addresses}
        , logger_{std::format("Interface:{}", name)}
        , name_{name}
        , index_{index} {}

std::optional<IpAddress> Interface::SourceAddress(IpAddress::Family family) const noexcept {
    return family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6;
}

bool Interface::CanSend(IpAddress::Family family) const noexcept {
    return SourceAddress(family).has_value();
}

void Interface::Refresh() noexcept {
#if defined(__linux__)
    addresses_ = ResolveInterfaceAddresses(index_);
#else
    addresses_ = ResolveInterfaceAddresses(name_);
#endif
    logger_.Debug("Resolved addresses (index {}): MAC {}, IPv4 {}, IPv6 {}", index_,
        addresses_.mac, addresses_.v4 ? addresses_.v4->ToString() : "none",
        addresses_.v6 ? addresses_.v6->ToString() : "none");
}

} // namespace reflector
