#include "reflector/config.h"
#include "reflector/dispatcher.h"
#include "reflector/ip_address.h"
#include "reflector/logger.h"
#include "reflector/wol_listener.h"
#include "reflector/wol_reflector.h"

#include <cstdio>
#include <csignal>
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {
volatile std::sig_atomic_t g_stop_requested = 0;

void SignalHandler(int) {
    g_stop_requested = 1;
}

void ConfigureStdoutBuffering() noexcept {
    if (!isatty(fileno(stdout))) {
        // Docker and service managers capture stdout through a pipe; line buffering keeps log lines visible before shutdown.
        std::setvbuf(stdout, nullptr, _IOLBF, 0);
    }
}

bool UsesIPv4(reflector::WolAddressFamily address_family) noexcept {
    return address_family != reflector::WolAddressFamily::IPv6;
}

bool UsesIPv6(reflector::WolAddressFamily address_family) noexcept {
    return address_family != reflector::WolAddressFamily::IPv4;
}

bool RequiresEveryRequestedFamily(reflector::WolAddressFamily address_family) noexcept {
    return address_family != reflector::WolAddressFamily::Default;
}

int Run(int argc, char* argv[]) {
    ConfigureStdoutBuffering();

    reflector::Logger logger("main");
    if (argc > 2) {
        logger.Error("Usage: {} [config.toml]", argv[0]);
        return 2;
    }

    const auto* config_path = argc == 2 ? argv[1] : "config.toml";
    auto config = reflector::Config::FromFile(config_path);
    if (!config.has_value()) {
        logger.Error("Cannot read configuration file: {}", config.error());
        return 1;
    }

    logger.Info("Setting minimum log level to {}", config->MinLogLevel());
    reflector::Logger::SetMinLevel(config->MinLogLevel());

    logger.Debug("Config: {}", *config);

    reflector::Dispatcher dispatcher;
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    std::unordered_map<std::string, reflector::WolListener> v4_wol_listeners;
    std::unordered_map<std::string, reflector::WolListener> v6_wol_listeners;
    std::vector<std::unique_ptr<reflector::WolReflector>> reflectors;
    for (const auto& wol_config : config->WolConfigs()) {
        std::unique_ptr<reflector::WolReflector> v4_reflector;
        std::unique_ptr<reflector::WolReflector> v6_reflector;

        if (UsesIPv4(wol_config.address_family)) {
            auto& v4_listener = v4_wol_listeners.try_emplace(
                wol_config.source_if, dispatcher, wol_config.source_if, reflector::IpAddress::Family::V4).first->second;
            v4_reflector = std::make_unique<reflector::WolReflector>(v4_listener, wol_config);
        }
        if (UsesIPv6(wol_config.address_family)) {
            auto& v6_listener = v6_wol_listeners.try_emplace(
                wol_config.source_if, dispatcher, wol_config.source_if, reflector::IpAddress::Family::V6).first->second;
            v6_reflector = std::make_unique<reflector::WolReflector>(v6_listener, wol_config);
        }

        const auto v4_valid = v4_reflector && v4_reflector->IsValid();
        const auto v6_valid = v6_reflector && v6_reflector->IsValid();
        if (RequiresEveryRequestedFamily(wol_config.address_family)) {
            if (v4_reflector && !v4_valid) {
                logger.Error("Cannot configure wol reflector \"{}\": IPv4 did not come up",
                    wol_config.name);
                return 1;
            }
            if (v6_reflector && !v6_valid) {
                logger.Error("Cannot configure wol reflector \"{}\": IPv6 did not come up",
                    wol_config.name);
                return 1;
            }
        } else if (!v4_valid && !v6_valid) {
            logger.Error("Cannot configure wol reflector \"{}\": neither IPv4 nor IPv6 came up",
                wol_config.name);
            return 1;
        }

        if (v4_valid) {
            reflectors.push_back(std::move(v4_reflector));
        }
        if (v6_valid) {
            reflectors.push_back(std::move(v6_reflector));
        }
    }

    dispatcher.Run(g_stop_requested);

    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        return Run(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("Fatal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputc('\n', stderr);
        return 1;
    } catch (...) {
        std::fputs("Fatal error: unknown exception\n", stderr);
        return 1;
    }
}
