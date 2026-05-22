#pragma once

#include <format>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace reflector {

class Error {
public:
    // Allow anything an std::string can be constructed from except const char*.
    // const char* is always treated as format string and will be handled by the next constructor.
    template <typename T>
        requires (std::is_constructible_v<std::string, T> && !std::is_same_v<std::decay_t<T>, const char*>)
    Error(T&& message) : message_{std::forward<T>(message)} {}

    template <typename ...Args>
    Error(std::format_string<Args...> fmt, Args&&... args) : message_{std::format(std::move(fmt), std::forward<Args>(args)...)} {}

    [[nodiscard]] static Error FromErrno();
    [[nodiscard]] static Error FromErrno(int err);

    [[nodiscard]] std::string_view Message() const noexcept { return message_; }

private:
    std::string message_;
};

} // namespace reflector

template <>
struct std::formatter<reflector::Error, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx) {
        auto it = ctx.begin();
        if (it != ctx.end() && *it != '}') {
            throw std::format_error("Invalid format args for Error");
        }

        return it;
    }

    template <typename FmtContext>
    FmtContext::iterator format(const reflector::Error& e, FmtContext& ctx) const {
        return std::format_to(ctx.out(), "{}", e.Message());
    }
};
