#pragma once

#include "reflector/util/no_copy.h"

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <print>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace reflector {

enum class LogLevel : uint8_t {
    Debug,
    Info,
    Warning,
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

    void SetName(std::string_view name) { name_ = name; }

    static void SetMinLevel(LogLevel level) noexcept { min_level_ = level; }
    [[nodiscard]] static LogLevel MinLevel() noexcept { return min_level_; }

    template <typename... Args>
    void Log(LogLevel level, detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        if (level < min_level_) {
            return;
        }
        try {
            // Clang 17 does not support std::chrono::current_zone(). Maybe next time.
            const auto time = std::time({});
            char time_str[sizeof("yyyy-mm-dd hh:mm:ss")];
            std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
            std::println("{} {} [{}] {} ({}:{})",
                time_str, level, name_,
                std::format(std::move(fmt.fmt), std::forward<Args>(args)...),
                detail::Basename(fmt.loc.file_name()), fmt.loc.line());
        } catch (...) {
            std::fputs("logger: failed to emit message\n", stderr);
        }
    }

    template <typename... Args>
    void Debug(detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        Log(LogLevel::Debug, std::move(fmt), std::forward<Args>(args)...);
    }

    template <typename... Args>
    void Info(detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        Log(LogLevel::Info, std::move(fmt), std::forward<Args>(args)...);
    }

    template <typename... Args>
    void Warning(detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        Log(LogLevel::Warning, std::move(fmt), std::forward<Args>(args)...);
    }

    template <typename... Args>
    void Error(detail::LogFmt<std::type_identity_t<Args>...> fmt, Args&& ...args) noexcept {
        Log(LogLevel::Error, std::move(fmt), std::forward<Args>(args)...);
    }

private:
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
        case Warning: return std::format_to(ctx.out(), "WARNING");
        case Error: return std::format_to(ctx.out(), "ERROR");
        }

        std::unreachable();
    }
};
