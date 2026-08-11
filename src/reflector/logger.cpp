#include "reflector/logger.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <format>
#include <source_location>
#include <string_view>

namespace {

using namespace reflector;

constexpr size_t MAX_MESSAGE_SIZE = 1024;
// Plus the timestamp, level, logger name and source location wrapped around it.
constexpr size_t MAX_RECORD_SIZE = MAX_MESSAGE_SIZE + 512;

constexpr const char* Basename(const char* path) noexcept {
    const char* base = path;
    for (const char* p = path; *p != '\0'; ++p) {
        if (*p == '/') {
            base = p + 1;
        }
    }
    return base;
}

struct SinkState {
    char* out;
    size_t capacity;
    size_t written = 0;
};

// Writes while the buffer has room and keeps counting past it, so an over-long message stays
// measurable. format_to_n does this for a typed call, but type-erased arguments go through
// vformat_to, which has no bounded form.
//
// Shaped like std::back_insert_iterator: the assignment writes and advances, ++ is a no-op. The
// position cannot advance in operator++ instead, because std::format writes through `*it++ = c`
// against a shared position, which would read a slot its own increment had already moved past.
class BoundedSink {
public:
    using difference_type = ptrdiff_t;

    explicit BoundedSink(SinkState& state) noexcept : state_{&state} {}

    BoundedSink& operator=(char c) noexcept {
        if (state_->written < state_->capacity) {
            state_->out[state_->written] = c;
        }
        ++state_->written;
        return *this;
    }

    BoundedSink& operator*() noexcept { return *this; }
    BoundedSink& operator++() noexcept { return *this; }
    BoundedSink operator++(int) noexcept { return *this; }

private:
    SinkState* state_;
};

} // namespace

namespace reflector {

void Logger::EmitRecord(LogLevel level, std::string_view fmt, std::format_args args,
    const std::source_location& loc) noexcept {
    try {
        // Clang 17 does not support std::chrono::current_zone(). Maybe next time.
        const auto time = std::time({});
        std::tm tm_buf{};
        localtime_r(&time, &tm_buf);
        char time_str[sizeof("yyyy-mm-dd hh:mm:ss")];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

        // Two buffers, so an over-long message loses its own tail rather than the source location
        // after it. std::format plus std::println would allocate twice per record.
        std::array<char, MAX_MESSAGE_SIZE> message_buffer;
        SinkState state{message_buffer.data(), message_buffer.size()};
        std::vformat_to(BoundedSink{state}, fmt, args);
        const std::string_view message{message_buffer.data(), std::min(state.written, state.capacity)};
        const std::string_view elision = state.written > state.capacity ? "[...]" : "";

        // One slot is held back for the newline, so it lands even on a truncated record and the
        // whole line still goes out in a single write.
        std::array<char, MAX_RECORD_SIZE> record;
        const auto emitted = std::format_to_n(record.data(), record.size() - 1, "{} {} [{}] {}{} ({}:{})",
            time_str, level, name_, message, elision, Basename(loc.file_name()), loc.line());
        const auto length = static_cast<size_t>(emitted.out - record.data());
        record[length] = '\n';
        std::fwrite(record.data(), 1, length + 1, stdout);
    } catch (...) {
        std::fputs("logger: failed to emit message\n", stderr);
    }
}

} // namespace reflector
