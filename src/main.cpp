#include "reflector/application.h"
#include "reflector/config.h"
#include "reflector/logger.h"

#include <cstdio>
#include <csignal>
#include <exception>

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

int Run(int argc, char* argv[]) {
    ConfigureStdoutBuffering();
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

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

    reflector::Application app;
    if (!app.Configure(*config)) {
        return 1;
    }

    app.Run(g_stop_requested);

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
