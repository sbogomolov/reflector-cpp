#include "application.h"

#include <memory>
#include <string_view>
#include <utility>

namespace reflector {

Application::Application()
        : Application{[](std::string_view interface) {
              return std::make_unique<RawSocket>(interface);
          }} {}

Application::Application(CaptureSocketFactory capture_socket_factory)
        : capture_socket_factory_{std::move(capture_socket_factory)}
        , logger_{"Application"} {}

bool Application::Configure(const Config& config) {
    for (const auto& wol_config : config.WolConfigs()) {
        // One capture socket per source interface, shared by every reflector that listens
        // on it; created lazily on first use via the (overridable) factory.
        auto [entry, inserted] = capture_sockets_.try_emplace(wol_config.source_if);
        if (inserted) {
            entry->second = capture_socket_factory_(wol_config.source_if);
        }
        auto& capture = entry->second;
        if (!capture || !capture->IsValid()) {
            logger_.Error("Cannot configure wol reflector \"{}\": capture socket on interface \"{}\" is invalid",
                wol_config.name, wol_config.source_if);
            return false;
        }

        auto& listener = wol_listeners_.try_emplace(
            wol_config.source_if, packet_dispatcher_, *capture).first->second;

        auto reflector = std::make_unique<WolReflector>(listener, wol_config);
        if (!reflector->IsValid()) {
            logger_.Error("Cannot configure wol reflector \"{}\": setup failed", wol_config.name);
            return false;
        }
        reflectors_.push_back(std::move(reflector));
    }
    return true;
}

void Application::Run(const volatile std::sig_atomic_t& stop_requested) {
    dispatcher_.Run(stop_requested);
}

} // namespace reflector
