#pragma once

#include "reflector/util/no_copy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
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

constexpr const char* Basename(const char* path) noexcept {
    const char* base = path;
    for (const char* p = path; *p != '\0'; ++p) {
        if (*p == '/') {
            base = p + 1;
        }
    }
    return base;
}

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

    // Ungated: the NFL_LOG macros check the level before they reach here.
    template <typename... Args>
    void Emit(LogLevel level, detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        try {
            // Clang 17 does not support std::chrono::current_zone(). Maybe next time.
            const auto time = std::time({});
            std::tm tm_buf{};
            localtime_r(&time, &tm_buf);
            char time_str[sizeof("yyyy-mm-dd hh:mm:ss")];
            std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

            // Two buffers, so an over-long message loses its own tail rather than the source
            // location after it. std::format plus std::println would allocate twice per record.
            std::array<char, MAX_MESSAGE_SIZE> message_buffer;
            const auto formatted = std::format_to_n(message_buffer.data(), message_buffer.size(),
                std::move(fmt.fmt), std::forward<Args>(args)...);
            const std::string_view message{message_buffer.data(),
                static_cast<size_t>(formatted.out - message_buffer.data())};
            // formatted.size is the length the message needed, not what fit, so this catches a cut.
            const std::string_view elision =
                static_cast<size_t>(formatted.size) > message_buffer.size() ? "[...]" : "";

            // One slot is held back for the newline, so it lands even on a truncated record and the
            // whole line still goes out in a single write.
            std::array<char, MAX_RECORD_SIZE> record;
            const auto emitted = std::format_to_n(record.data(), record.size() - 1, "{} {} [{}] {}{} ({}:{})",
                time_str, level, name_, message, elision,
                detail::Basename(fmt.loc.file_name()), fmt.loc.line());
            const auto length = static_cast<size_t>(emitted.out - record.data());
            record[length] = '\n';
            std::fwrite(record.data(), 1, length + 1, stdout);
        } catch (...) {
            std::fputs("logger: failed to emit message\n", stderr);
        }
    }

private:
    static constexpr size_t MAX_MESSAGE_SIZE = 1024;
    // Plus the timestamp, level, logger name and source location wrapped around it.
    static constexpr size_t MAX_RECORD_SIZE = MAX_MESSAGE_SIZE + 512;

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
