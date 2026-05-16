#include "udp_listener.h"

#include "logger.h"

namespace reflector {

namespace {

Logger& GetLogger() noexcept {
    static Logger logger{"UdpListener"};
    return logger;
}

} // namespace

UdpListener::UdpListener(const Options& options)
        : socket_{options.local_ip.AddressFamily()} {
    if (!socket_.IsValid()) {
        GetLogger().Warning("Cannot create UDP listener on interface \"{}\": socket setup failed", options.interface);
        return;
    }
    if (!options.interface.empty() && !socket_.SetInterface(options.interface)) {
        GetLogger().Error("Cannot create UDP listener on interface \"{}\"", options.interface);
        socket_.Close();
        return;
    }
    if (options.local_ip.IsV6() && !socket_.SetV6Only(true)) {
        GetLogger().Error("Cannot create UDP listener on interface \"{}\": IPV6_V6ONLY setup failed",
            options.interface);
        socket_.Close();
        return;
    }
    if (!socket_.SetReuseAddr(true)) {
        GetLogger().Error("Cannot create UDP listener on interface \"{}\": SO_REUSEADDR setup failed", options.interface);
        socket_.Close();
        return;
    }
    if (!socket_.Bind(options.local_ip, options.local_port)) {
        GetLogger().Error("Cannot create UDP listener on interface \"{}\" bound to {}:{}",
            options.interface, options.local_ip, options.local_port);
        socket_.Close();
        return;
    }
}

} // namespace reflector
