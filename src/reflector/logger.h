#pragma once

#include "reflector/util/no_copy.h"

#include <cstdint>
#include <format>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace reflector {

// Ordered by severity, so filtering is a plain comparison. Off is above Error and no record carries
// it, so selecting it admits nothing.
enum class LogLevel : uint8_t {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
};

// Trace costs nothing in a release build: the macros discard the statement rather than testing a
// level for it. The arguments are still compiled and type-checked, so a Trace line cannot rot
// unnoticed in the configuration that omits it.
#if defined(NDEBUG)
inline constexpr LogLevel STATIC_MIN_LOG_LEVEL = LogLevel::Debug;
#else
inline constexpr LogLevel STATIC_MIN_LOG_LEVEL = LogLevel::Trace;
#endif

namespace detail {

template <typename... Args>
struct LogFmt {
    std::format_string<Args...> fmt;
    std::source_location loc;

    template <typename T>
    consteval LogFmt(const T& s, std::source_location l = std::source_location::current()) noexcept
            : fmt{s}, loc{l} {}
};

// One-based, so a reading is never 0 and RateGate can spend 0 on "never emitted". Whole seconds, so
// a window under a second lets every call through.
constexpr uint32_t MonotonicSecsFrom(int64_t nanos) noexcept {
    return 1 + static_cast<uint32_t>(nanos / 1'000'000'000);
}

// MonotonicSecsFrom applied to the steady clock, which counts from boot.
uint32_t MonotonicSecs() noexcept;

// The emit-or-count decision for one call site. The NFL_LOG_*_RATE macros keep one of these in a
// static, so a window covers a statement rather than an interface or a peer. The caller passes the
// time in, which is what makes the arithmetic testable without waiting on a clock. Plain integers
// rather than atomics: the loop is single-threaded and no log runs from a signal handler.
class RateGate {
public:
    // consteval, so a site cannot hand over a window that varies between calls, and the gate is
    // constant-initialized rather than carrying a thread-safe init guard into every call.
    consteval explicit RateGate(uint32_t window_secs) noexcept : window_secs_{window_secs} {}

    // How many records were suppressed since the last emission, or nullopt to suppress this one.
    // Takes readings from MonotonicSecs, which never decrease and are never 0, so the subtraction
    // cannot underflow and last_emit_ of 0 can only mean nothing has been emitted yet.
    constexpr std::optional<uint32_t> Admit(uint32_t now_secs) noexcept {
        if (last_emit_ == 0 || now_secs - last_emit_ >= window_secs_) {
            last_emit_ = now_secs;
            return std::exchange(suppressed_, 0);
        }
        ++suppressed_;
        return std::nullopt;
    }

private:
    uint32_t window_secs_;
    uint32_t last_emit_ = 0;
    uint32_t suppressed_ = 0;
};

} // namespace detail

class Logger : NoCopy {
public:
    explicit Logger(std::string_view name) : name_{name} {}

    Logger(Logger&&) noexcept = default;
    Logger& operator=(Logger&&) noexcept = default;

    void SetName(std::string_view name) { name_ = name; }

    static void SetMinLevel(LogLevel level) noexcept { min_level_ = level; }
    [[nodiscard]] static LogLevel MinLevel() noexcept { return min_level_; }

    // Ungated: the NFL_LOG macros check the level before they reach here. Type-erasing the
    // arguments keeps the record builder to one instantiation rather than one per combination of
    // argument types across every call site.
    template <typename... Args>
    void Emit(LogLevel level, detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        EmitRecord(level, {}, fmt.fmt.get(), std::make_format_args(args...), fmt.loc);
    }

    // For the NFL_LOG_*_RATE macros, which have a count of what the window swallowed to disclose.
    template <typename... Args>
    void EmitRated(LogLevel level, uint32_t suppressed,
        detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        EmitRatedRecord(level, suppressed, fmt.fmt.get(), std::make_format_args(args...), fmt.loc);
    }

private:
    // note is interpolated as it stands, so the rate-limited path owns the decision of whether
    // there is anything to disclose and the ordinary path never tests for it.
    void EmitRecord(LogLevel level, std::string_view note, std::string_view fmt, std::format_args args,
        const std::source_location& loc) noexcept;
    void EmitRatedRecord(LogLevel level, uint32_t suppressed, std::string_view fmt,
        std::format_args args, const std::source_location& loc) noexcept;

    inline static LogLevel min_level_ = LogLevel::Info;

    std::string name_;
};

} // namespace reflector

template <>
struct std::formatter<reflector::LogLevel>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for LogLevel");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::LogLevel& l, FmtContext& ctx) const {
        switch (l) {
        using enum reflector::LogLevel;
        case Trace: return std::format_to(ctx.out(), "TRACE");
        case Debug: return std::format_to(ctx.out(), "DEBUG");
        case Info: return std::format_to(ctx.out(), "INFO");
        case Warn: return std::format_to(ctx.out(), "WARN");
        case Error: return std::format_to(ctx.out(), "ERROR");
        // Never reaches a record, but it is a level a config can name.
        case Off: return std::format_to(ctx.out(), "OFF");
        }

        std::unreachable();
    }
};

// The only level gate. A filtered record never reaches Emit, so it never evaluates its arguments:
// a suppressed Debug line would otherwise still build every Error::FromErrno() and ToString() it
// passes. NFL_ rather than a bare LOG_, which syslog.h already defines.
#define NFL_LOG(logger, level, ...)                                                        \
    do {                                                                                   \
        if constexpr (::reflector::LogLevel::level >= ::reflector::STATIC_MIN_LOG_LEVEL) { \
            if (::reflector::LogLevel::level >= ::reflector::Logger::MinLevel()) {         \
                (logger).Emit(::reflector::LogLevel::level, __VA_ARGS__);                  \
            }                                                                              \
        }                                                                                  \
    } while (false)

#define NFL_LOG_TRACE(logger, ...) NFL_LOG(logger, Trace, __VA_ARGS__)
#define NFL_LOG_DEBUG(logger, ...) NFL_LOG(logger, Debug, __VA_ARGS__)
#define NFL_LOG_INFO(logger, ...) NFL_LOG(logger, Info, __VA_ARGS__)
#define NFL_LOG_WARN(logger, ...) NFL_LOG(logger, Warn, __VA_ARGS__)
#define NFL_LOG_ERROR(logger, ...) NFL_LOG(logger, Error, __VA_ARGS__)

// Emits at most once per window per call site. A call landing inside a closed window is counted
// instead, and the next line that does emit discloses the count.
#define NFL_LOG_RATE(logger, level, window_secs, ...)                                               \
    do {                                                                                            \
        if constexpr (::reflector::LogLevel::level >= ::reflector::STATIC_MIN_LOG_LEVEL) {          \
            if (::reflector::LogLevel::level >= ::reflector::Logger::MinLevel()) {                  \
                static ::reflector::detail::RateGate nfl_rate_gate{(window_secs)};                  \
                const auto nfl_suppressed =                                                         \
                    nfl_rate_gate.Admit(::reflector::detail::MonotonicSecs());                      \
                if (nfl_suppressed) {                                                               \
                    (logger).EmitRated(::reflector::LogLevel::level, *nfl_suppressed, __VA_ARGS__); \
                }                                                                                   \
            }                                                                                       \
        }                                                                                           \
    } while (false)

#define NFL_LOG_WARN_RATE(logger, window_secs, ...) \
    NFL_LOG_RATE(logger, Warn, window_secs, __VA_ARGS__)
#define NFL_LOG_ERROR_RATE(logger, window_secs, ...) \
    NFL_LOG_RATE(logger, Error, window_secs, __VA_ARGS__)
