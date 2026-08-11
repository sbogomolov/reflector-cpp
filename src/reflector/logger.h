#pragma once

#include "reflector/util/no_copy.h"

#include <cstdint>
#include <format>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace reflector {

enum class LogLevel : uint8_t {
    Debug,
    Info,
    Warn,
    Error,
};

namespace detail {

template <typename... Args>
struct LogFmt {
    std::format_string<Args...> fmt;
    std::source_location loc;

    template <typename T>
    consteval LogFmt(const T& s, std::source_location l = std::source_location::current()) noexcept
            : fmt{s}, loc{l} {}
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
        EmitRecord(level, fmt.fmt.get(), std::make_format_args(args...), fmt.loc);
    }

private:
    void EmitRecord(LogLevel level, std::string_view fmt, std::format_args args,
        const std::source_location& loc) noexcept;

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
        case Debug: return std::format_to(ctx.out(), "DEBUG");
        case Info: return std::format_to(ctx.out(), "INFO");
        case Warn: return std::format_to(ctx.out(), "WARN");
        case Error: return std::format_to(ctx.out(), "ERROR");
        }

        std::unreachable();
    }
};

// The only level gate. A filtered record never reaches Emit, so it never evaluates its arguments:
// a suppressed Debug line would otherwise still build every Error::FromErrno() and ToString() it
// passes. NFL_ rather than a bare LOG_, which syslog.h already defines.
#define NFL_LOG(logger, level, ...)                                             \
    do {                                                                        \
        if (::reflector::LogLevel::level >= ::reflector::Logger::MinLevel()) {  \
            (logger).Emit(::reflector::LogLevel::level, __VA_ARGS__);           \
        }                                                                       \
    } while (false)

#define NFL_LOG_DEBUG(logger, ...) NFL_LOG(logger, Debug, __VA_ARGS__)
#define NFL_LOG_INFO(logger, ...) NFL_LOG(logger, Info, __VA_ARGS__)
#define NFL_LOG_WARN(logger, ...) NFL_LOG(logger, Warn, __VA_ARGS__)
#define NFL_LOG_ERROR(logger, ...) NFL_LOG(logger, Error, __VA_ARGS__)
