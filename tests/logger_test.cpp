#include "reflector/logger.h"

#include <gtest/gtest.h>

#include "test_helpers.h"
#include "util/allocation_counter.h"

#include "reflector/ip_address.h"
#include "reflector/mac_address.h"

#include <charconv>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace {
using namespace reflector;

} // namespace

namespace reflector {

TEST(LoggerTest, SetMinLevelUpdatesMinLevel) {
    const ScopedMinLogLevel level{LogLevel::Debug};

    Logger::SetMinLevel(LogLevel::Error);
    EXPECT_EQ(Logger::MinLevel(), LogLevel::Error);
}

TEST(LoggerTest, MinLevelSuppressesLowerSeverityMessages) {
    const ScopedMinLogLevel level{LogLevel::Warning};
    Logger logger{"LoggerTest"};

    const std::string output = CaptureStdout([&] {
        logger.Debug("hidden debug message");
        logger.Info("hidden info message");
        logger.Warning("visible warning message");
        logger.Error("visible error message");
    });

    EXPECT_EQ(output.find("hidden debug message"), std::string::npos) << output;
    EXPECT_EQ(output.find("hidden info message"), std::string::npos) << output;
    EXPECT_NE(output.find("visible warning message"), std::string::npos) << output;
    EXPECT_NE(output.find("visible error message"), std::string::npos) << output;
}

TEST(LoggerTest, NameAppearsInOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"NamedLogger"};

    const std::string output = CaptureStdout([&] {
        logger.Info("message from a named logger");
    });

    EXPECT_NE(output.find("[NamedLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from a named logger"), std::string::npos) << output;
}

TEST(LoggerTest, NameSurvivesMoveConstructionAndAssignment) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger constructed_from{"MoveConstructedLogger"};
    Logger move_constructed{std::move(constructed_from)};
    Logger move_assigned_target{"InitialLogger"};
    Logger assigned_from{"MoveAssignedStaticLogger"};
    move_assigned_target = std::move(assigned_from);

    const std::string output = CaptureStdout([&] {
        move_constructed.Info("message from the move constructed logger");
        move_assigned_target.Info("message from the move assigned logger");
    });

    EXPECT_NE(output.find("[MoveConstructedLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("[MoveAssignedStaticLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from the move constructed logger"), std::string::npos) << output;
    EXPECT_NE(output.find("message from the move assigned logger"), std::string::npos) << output;
}

TEST(LoggerTest, DynamicNameSurvivesMoveConstructionAndAssignment) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger constructed_from{std::string{"MoveConstructedDynamicLoggerName"}};
    Logger move_constructed{std::move(constructed_from)};
    Logger move_assigned_target{"InitialLogger"};
    Logger assigned_from{std::string{"MoveAssignedDynamicLoggerName"}};
    move_assigned_target = std::move(assigned_from);

    const std::string output = CaptureStdout([&] {
        move_constructed.Info("message from move constructed dynamic logger");
        move_assigned_target.Info("message from move assigned dynamic logger");
    });

    EXPECT_NE(output.find("[MoveConstructedDynamicLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("[MoveAssignedDynamicLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move constructed dynamic logger"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move assigned dynamic logger"), std::string::npos) << output;
}

TEST(LoggerTest, FormatsLogLevelNames) {
    EXPECT_EQ(std::format("{}", LogLevel::Debug), "DEBUG");
    EXPECT_EQ(std::format("{}", LogLevel::Info), "INFO");
    EXPECT_EQ(std::format("{}", LogLevel::Warning), "WARNING");
    EXPECT_EQ(std::format("{}", LogLevel::Error), "ERROR");
}

TEST(LoggerTest, LogLineIncludesSourceLocation) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"LoggerTest"};

    const std::string output = CaptureStdout([&] {
        logger.Info("a message");
    });

    // The line carries the call site as basename:line; parse the number to prove a line follows.
    const std::string marker = "logger_test.cpp:";
    const auto pos = output.find(marker);
    ASSERT_NE(pos, std::string::npos) << output;

    int line = 0;
    const char* first = output.data() + pos + marker.size();
    const auto result = std::from_chars(first, output.data() + output.size(), line);
    EXPECT_EQ(result.ec, std::errc{}) << output;  // digits follow the colon
    EXPECT_GT(line, 0) << output;
}

TEST(LoggerTest, MarksAnOverlongMessageAndKeepsWhatFollowsIt) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"LoggerTest"};

    // Longer than any record buffer, so the message is cut wherever that boundary sits.
    const std::string argument(8192, 'x');
    const std::string output = CaptureStdout([&] {
        logger.Info("{}", argument);
    });

    // The marker and the source location both land past the cut message, so the tail is what
    // explains a failure here.
    ASSERT_GT(output.size(), 100u);
    const std::string tail = output.substr(output.size() - 100);

    EXPECT_LT(output.size(), argument.size());  // cut, not grown to fit
    EXPECT_NE(output.find("[...]"), std::string::npos) << tail;
    EXPECT_NE(output.find("logger_test.cpp:"), std::string::npos) << tail;
    EXPECT_TRUE(output.ends_with("\n")) << tail;
}

#if defined(REFLECTOR_HAS_ALLOCATION_COUNTER)
// Emitting a record stays off the heap end to end: the message and the record format into stack
// buffers, and the IpAddress/MacAddress formatters write through the same sink rather than building
// strings. An IPv6 address is the demanding case -- its text is far past any small-string capacity.
TEST(LoggerTest, EmittingARecordDoesNotAllocate) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"LoggerTest"};
    const auto address = *IpAddress::FromString("2001:db8:85a3:1234:5678:8a2e:370:7334");
    const auto mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");

    size_t allocated = 0;
    const std::string output = CaptureStdout([&] {
        logger.Info("warm-up: the redirected stream buffers itself on its first write");
        const ScopedAllocationCounter counter;
        logger.Info("group {} via {} port {}", address, mac, 1900);
        allocated = counter.Count();
    });

    EXPECT_EQ(allocated, 0u);
    EXPECT_NE(output.find("[2001:db8:85a3:1234:5678:8a2e:370:7334]"), std::string::npos) << output;
    EXPECT_NE(output.find("AA:BB:CC:DD:EE:FF"), std::string::npos) << output;
}
#endif  // REFLECTOR_HAS_ALLOCATION_COUNTER

TEST(LoggerTest, EndsTheLineWhenEvenTheRecordIsTruncated) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{std::string(8192, 'n')};  // the name alone overruns the record buffer

    const std::string output = CaptureStdout([&] {
        logger.Info("a message");
    });

    // Exactly one newline, at the very end: the reserved slot held, and the record is a single line.
    ASSERT_FALSE(output.empty());
    EXPECT_EQ(output.find('\n'), output.size() - 1);
}

}  // namespace reflector
