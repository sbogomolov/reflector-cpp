#include "reflector/application.h"
#include "reflector/config/config.h"
#include "reflector/logger.h"
#include "reflector/util/narrow_cast.h"

#include <cstdio>
#include <csignal>
#include <signal.h>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unistd.h>
#include <vector>

#if defined(__APPLE__)
#include <crt_externs.h>
#else
// Provided by libc. Declared at global scope (not inside the anonymous namespace, where it would
// become an undefined internal-linkage symbol) and extern "C" so it binds to the libc symbol.
extern "C" char** environ;
#endif

namespace {
// The process environment as a NULL-terminated array of "KEY=VALUE" strings.
char** Environment() noexcept {
#if defined(__APPLE__)
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

// Collects the environment into key/value views (split on the first '='). The views borrow the
// environ strings, which live for the whole process, so they stay valid through Config::Load.
std::vector<reflector::EnvVar> GatherEnvironment() {
    std::vector<reflector::EnvVar> vars;
    for (char** entry = Environment(); entry != nullptr && *entry != nullptr; ++entry) {
        const std::string_view text{*entry};
        const auto eq = text.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        vars.push_back({text.substr(0, eq), text.substr(eq + 1)});
    }
    return vars;
}

volatile std::sig_atomic_t g_stop_requested = 0;
// The write end of Application's signal-wakeup self-pipe, or -1 until PrepareSignalWakeup sets it. Writing
// one byte breaks the dispatcher's blocking poll at once so shutdown doesn't wait up to a poll interval.
volatile std::sig_atomic_t g_wakeup_fd = -1;

void SignalHandler(int) {
    g_stop_requested = 1;
    // std::sig_atomic_t is wider than int on some platforms (long on FreeBSD), so narrow explicitly.
    // narrow_cast is a plain static_cast — async-signal-safe (no runtime check) for use in the handler.
    const int wakeup_fd = reflector::narrow_cast<int>(g_wakeup_fd);
    if (wakeup_fd >= 0) {
        // write() is async-signal-safe; best-effort, so a full/not-ready pipe (the result we ignore) is
        // fine -- a byte already pending is enough to wake the loop, which then re-checks g_stop_requested.
        const unsigned char byte = 1;
        std::ignore = ::write(wakeup_fd, &byte, 1);
    }
}

// Registers SignalHandler for SIGINT/SIGTERM with SA_RESTART, so the kernel auto-restarts a
// send/recv/read/write interrupted by one of them: the data path never observes EINTR and so never
// loops on it. Only epoll_wait/kevent (never restarted regardless of SA_RESTART) still surface EINTR,
// handled in EventLoopDispatcher::PollOnce. sigaction, not std::signal, because signal()'s restart
// semantics are platform- and feature-macro-dependent (System V vs BSD); we want SA_RESTART guaranteed.
void InstallSignalHandler(int signal_number) {
    struct sigaction action{};
    action.sa_handler = SignalHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    sigaction(signal_number, &action, nullptr);
}

void ConfigureStdoutBuffering() noexcept {
    if (!isatty(fileno(stdout))) {
        // Docker and service managers capture stdout through a pipe; line buffering keeps log lines visible before shutdown.
        std::setvbuf(stdout, nullptr, _IOLBF, 0);
    }
}

int Run(int argc, char* argv[]) {
    ConfigureStdoutBuffering();
    InstallSignalHandler(SIGINT);
    InstallSignalHandler(SIGTERM);

    reflector::Logger logger("main");
    if (argc > 2) {
        logger.Error("Usage: {} [config.toml]", argv[0]);
        return 2;
    }

    // A config file is optional: with no argument, the configuration comes entirely from
    // REFLECTOR_* environment variables. When given, the file and the environment are merged.
    std::optional<std::string> file_contents;
    if (argc == 2) {
        auto contents = reflector::Config::ReadFileToString(argv[1]);
        if (!contents) {
            logger.Error("Cannot read configuration file: {}", contents.error());
            return 1;
        }
        file_contents = *std::move(contents);
    }

    const auto env_vars = GatherEnvironment();
    const std::optional<std::string_view> toml_text =
        file_contents ? std::optional<std::string_view>{*file_contents} : std::nullopt;
    auto config = reflector::Config::Load(toml_text, env_vars);
    if (!config) {
        logger.Error("Invalid configuration: {}", config.error());
        return 1;
    }

    logger.Info("Setting minimum log level to {}", config->MinLogLevel());
    reflector::Logger::SetMinLevel(config->MinLogLevel());

    logger.Debug("Config: {}", *config);

    reflector::Application app;
    if (!app.Configure(*config)) {
        return 1;
    }

    // Let SIGINT/SIGTERM break the dispatcher's poll at once instead of waiting up to a poll interval.
    // Best-effort: -1 (setup failed, already logged) leaves the signal handler to only set the stop flag.
    g_wakeup_fd = app.PrepareSignalWakeup();

    app.Run(g_stop_requested);

    // The pipe closes with `app`; stop the handler from writing a stale fd during teardown.
    g_wakeup_fd = -1;

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
