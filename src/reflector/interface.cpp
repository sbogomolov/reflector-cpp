#include "interface.h"

#include "error.h"
#include "platform.h"

#include <cerrno>
#include <format>
#include <optional>
#include <utility>
#include <net/if.h>

namespace {
// The errnos that mean the lookup could not run, as opposed to naming no interface. Anything else
// still reads as absent, so an errno missing from this list cannot mask a genuinely removed one.
bool LookupCouldNotRun(int error) noexcept {
    return error == EMFILE || error == ENFILE || error == ENOMEM || error == ENOBUFS;
}
} // namespace

namespace reflector {

Interface::Interface(std::string_view name)
        : logger_{std::format("Interface:{}", name)}
        , name_{name} {
    if (name_.size() >= IFNAMSIZ) {
        logger_.Error("Interface name \"{}\" is too long (max {} characters)", name_, IFNAMSIZ - 1);
        return;
    }
    index_ = ResolveIndex().value_or(0);
    if (index_ == 0) {
        logger_.Error("Cannot resolve interface index: {}", Error::FromErrno());
        return;
    }
    // In-constructor dispatch resolves to Interface::Refresh — intended: construction always
    // performs a real resolve, regardless of what a derived test fake overrides.
    Refresh();
}

std::optional<unsigned> Interface::ResolveIndex() const noexcept {
    // Guard before any name lookup: if_nametoindex (and BPF's BIOCSETIF) copy into a fixed
    // IFNAMSIZ buffer, so an over-long name would be silently truncated and could match the
    // wrong interface. Silent here — the constructor reports it once, and this runs on a retry
    // loop where the name cannot have changed.
    if (name_.size() >= IFNAMSIZ) {
        return 0U;
    }
    const unsigned index = if_nametoindex(name_.c_str());
    if (index != 0) {
        return index;
    }
    // if_nametoindex reaches a 0 return only through a failed socket() or ioctl(), so errno is
    // this call's own rather than something left over.
    return LookupCouldNotRun(errno) ? std::nullopt : std::optional{0U};
}

Interface::IdentityChange Interface::Reidentify() noexcept {
    const auto resolved = ResolveIndex();
    if (!resolved) {
        logger_.Error("Cannot resolve interface index: {}; keeping index {}", Error::FromErrno(), index_);
        return IdentityChange::Unresolved;
    }
    if (*resolved == index_) {
        return IdentityChange::Unchanged;  // covers still-absent, so a retry loop stays quiet
    }

    const unsigned previous = std::exchange(index_, *resolved);
    if (index_ == 0) {
        addresses_ = {};  // nothing may send or join against an identity that is gone
        logger_.Info("Interface is gone (was index {}); parked until it returns", previous);
        return IdentityChange::Parked;
    }

    Refresh();
    logger_.Info("Interface reappeared as index {} (was {})", index_, previous);
    return IdentityChange::Repointed;
}

Interface::Interface(std::string_view name, unsigned index, const InterfaceAddresses& addresses) noexcept
        : addresses_{addresses}
        , index_{index}
        , logger_{std::format("Interface:{}", name)}
        , name_{name} {}

std::optional<IpAddress> Interface::SourceAddress(IpAddress::Family family) const noexcept {
    return family == IpAddress::Family::V4 ? addresses_.v4 : addresses_.v6;
}

std::optional<IpAddress> Interface::SourceAddressFor(const IpAddress& destination) const noexcept {
    if (destination.IsV4()) {
        return addresses_.v4;
    }
    if (destination.IsLinkLocalScoped()) {
        return addresses_.v6;  // best overall — link-local when the interface has one
    }
    return addresses_.v6_routable ? addresses_.v6_routable : addresses_.v6;
}

bool Interface::CanSend(IpAddress::Family family) const noexcept {
    return SourceAddress(family).has_value();
}

void Interface::Refresh() noexcept {
#if defined(__linux__)
    auto resolved = ResolveInterfaceAddresses(index_);
#else
    auto resolved = ResolveInterfaceAddresses(name_);
#endif
    if (!resolved) {
        // The enumeration could not run (it logged why), which says nothing about the interface.
        // Keeping the last known addresses beats closing a live interface's egress gate over a
        // transient shortage.
        return;
    }
    addresses_ = *resolved;
    logger_.Debug("Resolved addresses (index {}): MAC {}, IPv4 {}, IPv6 {}, IPv6 routable {}", index_,
        addresses_.mac, addresses_.v4 ? addresses_.v4->ToString() : "none",
        addresses_.v6 ? addresses_.v6->ToString() : "none",
        addresses_.v6_routable ? addresses_.v6_routable->ToString() : "none");
}

} // namespace reflector
