#pragma once

#include "link_socket.h"
#include "logger.h"
#include "packet_dispatcher.h"
#include "util/no_move.h"

#include <string>
#include <utility>
#include <vector>

namespace reflector {

// Base for the per-protocol reflectors (WoL, mDNS, SSDP). Holds what every reflector
// shares: a named logger, the packet-dispatcher registrations that keep its capture callbacks
// alive, and the validity contract. Application owns reflectors through Reflector pointers and
// tears them down uniformly — destroying registrations_ unregisters every callback. Immovable
// (NoMove): the dispatcher holds callbacks bound to `this`.
//
// Subclasses validate their own config and gate address families (which differ per protocol),
// then push the registrations they create into registrations_.
class Reflector : NoMove {
public:
    virtual ~Reflector() noexcept = default;

    // A reflector is valid once it has registered at least one capture callback.
    [[nodiscard]] bool IsValid() const noexcept { return !registrations_.empty(); }

    // Called (by Application) after an interface's addresses may have changed, so the reflector can
    // react to a family gaining or losing its source address — log a capability transition, and
    // join/leave the family's groups. Default no-op (a reflector that gates only at construction
    // needs nothing); the reflector reads live interface state, so one call after the refresh is
    // enough, regardless of which interface changed.
    virtual void OnInterfaceChanged() noexcept {}

protected:
    explicit Reflector(std::string logger_name) : logger_{std::move(logger_name)} {}

    Logger logger_;
    std::vector<PacketDispatcher::Registration> registrations_;
    // Multicast group memberships this reflector holds (mDNS/SSDP join their groups; WoL joins
    // none). Dropping a membership leaves the group; destroying the reflector leaves them all.
    std::vector<LinkSocket::MulticastMembership> memberships_;
};

} // namespace reflector
