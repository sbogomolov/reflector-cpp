#include "reflector/logger.h"

#include <gtest/gtest.h>

#include "test_helpers.h"

#include <charconv>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace {
using namespace reflector;

constexpr char STATIC_ARRAY_NAME[] = "StaticArrayLogger";

static_assert(noexcept(Logger{"LiteralLogger"}));
static_assert(noexcept(Logger{STATIC_ARRAY_NAME}));
static_assert(!noexcept(Logger{std::string_view{"DynamicLogger"}}));
static_assert(noexcept(std::declval<Logger&>().SetName("LiteralLogger")));
static_assert(noexcept(std::declval<Logger&>().SetName(STATIC_ARRAY_NAME)));
static_assert(!noexcept(std::declval<Logger&>().SetName(std::string_view{"DynamicLogger"})));

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

TEST(LoggerTest, StaticLiteralNameAppearsInOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"StaticLiteralLogger"};

    const std::string output = CaptureStdout([&] {
        logger.Info("message from static literal logger");
    });

    EXPECT_NE(output.find("[StaticLiteralLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from static literal logger"), std::string::npos) << output;
}

TEST(LoggerTest, StaticArrayNameAppearsInOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{STATIC_ARRAY_NAME};

    const std::string output = CaptureStdout([&] {
        logger.Info("message from static array logger");
    });

    EXPECT_NE(output.find(STATIC_ARRAY_NAME), std::string::npos) << output;
    EXPECT_NE(output.find("message from static array logger"), std::string::npos) << output;
}

TEST(LoggerTest, DynamicTemporaryNameAppearsInOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{std::string{"DynamicTemporaryLoggerName"}};

    const std::string output = CaptureStdout([&] {
        logger.Info("message from dynamic temporary logger");
    });

    EXPECT_NE(output.find("[DynamicTemporaryLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from dynamic temporary logger"), std::string::npos) << output;
}

TEST(LoggerTest, SetNameWithStaticLiteralUpdatesOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{std::string{"InitialDynamicLoggerName"}};
    logger.SetName("RenamedStaticLiteralLogger");

    const std::string output = CaptureStdout([&] {
        logger.Info("message from renamed static literal logger");
    });

    EXPECT_NE(output.find("[RenamedStaticLiteralLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from renamed static literal logger"), std::string::npos) << output;
}

TEST(LoggerTest, SetNameWithDynamicTemporaryUpdatesOutput) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"InitialStaticLogger"};
    logger.SetName(std::string{"RenamedDynamicLoggerName"});

    const std::string output = CaptureStdout([&] {
        logger.Info("message from renamed dynamic logger");
    });

    EXPECT_NE(output.find("[RenamedDynamicLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from renamed dynamic logger"), std::string::npos) << output;
}

TEST(LoggerTest, StaticNameSurvivesMoveConstructionAndAssignment) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger constructed_from{STATIC_ARRAY_NAME};
    Logger move_constructed{std::move(constructed_from)};
    Logger move_assigned_target{"InitialLogger"};
    Logger assigned_from{"MoveAssignedStaticLogger"};
    move_assigned_target = std::move(assigned_from);

    const std::string output = CaptureStdout([&] {
        move_constructed.Info("message from move constructed static logger");
        move_assigned_target.Info("message from move assigned static logger");
    });

    EXPECT_NE(output.find(STATIC_ARRAY_NAME), std::string::npos) << output;
    EXPECT_NE(output.find("[MoveAssignedStaticLogger]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move constructed static logger"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move assigned static logger"), std::string::npos) << output;
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

}  // namespace reflector
