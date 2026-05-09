#include "reflector/logger.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <string>

using namespace reflector;

namespace {

class ScopedMinLogLevel {
public:
    explicit ScopedMinLogLevel(LogLevel level) noexcept : previous_{Logger::MinLevel()} {
        Logger::SetMinLevel(level);
    }

    ~ScopedMinLogLevel() noexcept {
        Logger::SetMinLevel(previous_);
    }

private:
    LogLevel previous_;
};

} // namespace

TEST(LoggerTest, SetMinLevelUpdatesMinLevel) {
    const ScopedMinLogLevel level{LogLevel::Debug};

    Logger::SetMinLevel(LogLevel::Error);
    EXPECT_EQ(Logger::MinLevel(), LogLevel::Error);
}

TEST(LoggerTest, MinLevelSuppressesLowerSeverityMessages) {
    const ScopedMinLogLevel level{LogLevel::Warning};
    Logger logger{"LoggerTest"};

    testing::internal::CaptureStdout();
    logger.Debug("hidden debug message");
    logger.Info("hidden info message");
    logger.Warning("visible warning message");
    logger.Error("visible error message");
    std::fflush(stdout);
    const std::string output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(output.find("hidden debug message"), std::string::npos) << output;
    EXPECT_EQ(output.find("hidden info message"), std::string::npos) << output;
    EXPECT_NE(output.find("visible warning message"), std::string::npos) << output;
    EXPECT_NE(output.find("visible error message"), std::string::npos) << output;
}
