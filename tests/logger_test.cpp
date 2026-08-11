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
    const ScopedMinLogLevel level{LogLevel::Warn};
    Logger logger{"LoggerTest"};

    const std::string output = CaptureStdout([&] {
        NFL_LOG_DEBUG(logger, "hidden debug message");
        NFL_LOG_INFO(logger, "hidden info message");
        NFL_LOG_WARN(logger, "visible warning message");
        NFL_LOG_ERROR(logger, "visible error message");
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
        NFL_LOG_INFO(logger, "message from a named logger");
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
        NFL_LOG_INFO(move_constructed, "message from the move constructed logger");
        NFL_LOG_INFO(move_assigned_target, "message from the move assigned logger");
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
        NFL_LOG_INFO(move_constructed, "message from move constructed dynamic logger");
        NFL_LOG_INFO(move_assigned_target, "message from move assigned dynamic logger");
    });

    EXPECT_NE(output.find("[MoveConstructedDynamicLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("[MoveAssignedDynamicLoggerName]"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move constructed dynamic logger"), std::string::npos) << output;
    EXPECT_NE(output.find("message from move assigned dynamic logger"), std::string::npos) << output;
}

TEST(LoggerTest, FormatsLogLevelNames) {
    EXPECT_EQ(std::format("{}", LogLevel::Trace), "TRACE");
    EXPECT_EQ(std::format("{}", LogLevel::Debug), "DEBUG");
    EXPECT_EQ(std::format("{}", LogLevel::Info), "INFO");
    EXPECT_EQ(std::format("{}", LogLevel::Warn), "WARN");
    EXPECT_EQ(std::format("{}", LogLevel::Error), "ERROR");
    EXPECT_EQ(std::format("{}", LogLevel::Off), "OFF");
}

// The contract differs by build, so the test does too: a release build has no Trace statement left
// to run, and every other build emits one when the level allows it.
TEST(LoggerTest, ReleaseBuildsCarryNoTraceStatement) {
    const ScopedMinLogLevel level{LogLevel::Trace};
    Logger logger{"TraceLogger"};

    const std::string output = CaptureStdout([&] {
        NFL_LOG_TRACE(logger, "a trace message");
    });

#if defined(NDEBUG)
    EXPECT_EQ(output.find("a trace message"), std::string::npos) << output;
#else
    EXPECT_NE(output.find("a trace message"), std::string::npos) << output;
    EXPECT_NE(output.find("TRACE"), std::string::npos) << output;
#endif
}

TEST(LoggerTest, OffSuppressesEveryLevel) {
    const ScopedMinLogLevel level{LogLevel::Off};
    Logger logger{"OffLogger"};

    const std::string output = CaptureStdout([&] {
        NFL_LOG_TRACE(logger, "trace record");
        NFL_LOG_DEBUG(logger, "debug record");
        NFL_LOG_INFO(logger, "info record");
        NFL_LOG_WARN(logger, "warn record");
        NFL_LOG_ERROR(logger, "error record");
    });

    EXPECT_TRUE(output.empty()) << output;
}

TEST(LoggerTest, LogLineIncludesSourceLocation) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"LoggerTest"};

    const std::string output = CaptureStdout([&] {
        NFL_LOG_INFO(logger, "a message");
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
        NFL_LOG_INFO(logger, "{}", argument);
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
        NFL_LOG_INFO(logger, "warm-up: the redirected stream buffers itself on its first write");
        const ScopedAllocationCounter counter;
        NFL_LOG_INFO(logger, "group {} via {} port {}", address, mac, 1900);
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
        NFL_LOG_INFO(logger, "a message");
    });

    // Exactly one newline, at the very end: the reserved slot held, and the record is a single line.
    ASSERT_FALSE(output.empty());
    EXPECT_EQ(output.find('\n'), output.size() - 1);
}
// Times are MonotonicSecs readings, which are one-based: 1 is the first second of uptime.
TEST(RateGateTest, EmitsFirstThenSuppressesWithinTheWindow) {
    detail::RateGate gate{60};

    EXPECT_EQ(gate.Admit(1), 0U);
    EXPECT_EQ(gate.Admit(2), std::nullopt);
    EXPECT_EQ(gate.Admit(60), std::nullopt);
    // A full 60 seconds after the emission at 1, disclosing the two it swallowed.
    EXPECT_EQ(gate.Admit(61), 2U);
    EXPECT_EQ(gate.Admit(200), 0U);
}

TEST(RateGateTest, RepeatedCallsInTheFirstSecondEmitOnlyOnce) {
    detail::RateGate gate{60};

    EXPECT_EQ(gate.Admit(1), 0U);
    EXPECT_EQ(gate.Admit(1), std::nullopt);
    EXPECT_EQ(gate.Admit(1), std::nullopt);
}

TEST(RateGateTest, AZeroWindowAdmitsEveryCall) {
    detail::RateGate gate{0};

    EXPECT_EQ(gate.Admit(1), 0U);
    EXPECT_EQ(gate.Admit(1), 0U);
    EXPECT_EQ(gate.Admit(2), 0U);
}

// RateGate spends 0 on "never emitted", which only works because a reading can never be 0. The
// first second of uptime is the case that would otherwise collide with it.
TEST(RateGateTest, TheClockIsOneBased) {
    EXPECT_EQ(detail::MonotonicSecsFrom(0), 1U);
    EXPECT_EQ(detail::MonotonicSecsFrom(999'999'999), 1U);
    EXPECT_EQ(detail::MonotonicSecsFrom(1'000'000'000), 2U);
}

TEST(LoggerTest, ASuppressedCountRidesOnTheNextRecord) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"RateLogger"};

    const std::string output = CaptureStdout([&] {
        logger.EmitRated(LogLevel::Warn, 5, "a message");
    });

    EXPECT_NE(output.find("(5 suppressed)"), std::string::npos) << output;
}

TEST(LoggerTest, ADisclosureOutlivesAnOverlongMessage) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"RateLogger"};

    const std::string argument(8192, 'x');
    const std::string output = CaptureStdout([&] {
        logger.EmitRated(LogLevel::Warn, 7, "{}", argument);
    });

    ASSERT_GT(output.size(), 100u);
    const std::string tail = output.substr(output.size() - 100);
    EXPECT_NE(output.find("[...]"), std::string::npos) << tail;
    EXPECT_NE(output.find("(7 suppressed)"), std::string::npos) << tail;
}

// Wants a gate that has never emitted, so it does not survive --gtest_repeat: the static below holds
// its window across iterations. Every lane runs each test once.
TEST(LoggerTest, ARateLimitedCallSiteEmitsOncePerWindow) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"RateLogger"};

    const std::string output = CaptureStdout([&] {
        for (int i = 0; i < 3; ++i) {
            NFL_LOG_WARN_RATE(logger, 60, "flooding {}", i);
        }
    });

    EXPECT_NE(output.find("flooding 0"), std::string::npos) << output;
    EXPECT_EQ(output.find("flooding 1"), std::string::npos) << output;
    EXPECT_EQ(output.find("flooding 2"), std::string::npos) << output;
    // Nothing was suppressed before the one that emitted, so it carries no disclosure.
    EXPECT_EQ(output.find("suppressed"), std::string::npos) << output;
}

// The macro gates on the level before the arguments are formed, so a filtered record costs nothing
// past the comparison. Calling Logger::Emit directly still builds every argument first.
TEST(LoggerTest, AFilteredRecordDoesNotEvaluateItsArguments) {
    const ScopedMinLogLevel level{LogLevel::Info};
    Logger logger{"GateLogger"};
    int evaluated = 0;
    const auto counted = [&evaluated] { return ++evaluated; };

    NFL_LOG_DEBUG(logger, "suppressed {}", counted());
    EXPECT_EQ(evaluated, 0);

    const std::string output = CaptureStdout([&] { NFL_LOG_INFO(logger, "emitted {}", counted()); });

    EXPECT_EQ(evaluated, 1);
    EXPECT_NE(output.find("emitted 1"), std::string::npos) << output;
}

}  // namespace reflector
