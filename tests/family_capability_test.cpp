#include "reflector/family_capability.h"

#include "mocks/fake_interface.h"
#include "reflector/ip_address.h"
#include "reflector/logger.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <format>
#include <string>

namespace {

using namespace reflector;

constexpr FamilyCapability::Policy USES_BOTH_REQUIRES_V4{
    .uses = {true, true}, .required = {true, false}};

} // namespace

namespace reflector {

class FamilyCapabilityTest : public ::testing::Test {
protected:
    FakeInterface iface;  // defaults: loopback sources for both families
    Logger logger{"FamilyCapabilityTest"};
};

TEST_F(FamilyCapabilityTest, CanSendAndsConfigPolicyWithLiveCapability) {
    const FamilyCapability capability{iface, logger,
        {.uses = {true, false}, .required = {true, false}}};

    EXPECT_TRUE(capability.CanSend(IpAddress::Family::V4));
    EXPECT_FALSE(capability.CanSend(IpAddress::Family::V6));  // config never uses v6

    iface.SetV4(std::nullopt);  // capability is read live, no Observe needed
    EXPECT_FALSE(capability.CanSend(IpAddress::Family::V4));
}

TEST_F(FamilyCapabilityTest, ObserveIsQuietWithoutAChange) {
    FamilyCapability capability{iface, logger, USES_BOTH_REQUIRES_V4};

    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    EXPECT_TRUE(output.empty()) << output;
}

TEST_F(FamilyCapabilityTest, LosingARequiredFamilyLogsErrorOnce) {
    FamilyCapability capability{iface, logger, USES_BOTH_REQUIRES_V4};

    iface.SetV4(std::nullopt);
    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    const auto error = std::format("Cannot reflect {} packets", IpAddress::Family::V4);
    EXPECT_NE(output.find(error), std::string::npos) << output;
    EXPECT_EQ(output.find(error), output.rfind(error)) << "the notice must be one-shot: " << output;
}

TEST_F(FamilyCapabilityTest, LosingAMerelyUsedFamilyLogsInfoOnce) {
    FamilyCapability capability{iface, logger, USES_BOTH_REQUIRES_V4};

    iface.SetV6(std::nullopt);
    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    const auto notice = std::format("Stopping {} reflection", IpAddress::Family::V6);
    EXPECT_NE(output.find(notice), std::string::npos) << output;
    EXPECT_EQ(output.find(notice), output.rfind(notice)) << "the notice must be one-shot: " << output;
    EXPECT_EQ(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(FamilyCapabilityTest, RegainingAFamilyLogsInfoOnce) {
    iface.SetV6(std::nullopt);
    FamilyCapability capability{iface, logger, USES_BOTH_REQUIRES_V4};

    iface.SetV6(IpAddress::LoopbackV6());
    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    const auto notice = std::format("Starting {} reflection", IpAddress::Family::V6);
    EXPECT_NE(output.find(notice), std::string::npos) << output;
    EXPECT_EQ(output.find(notice), output.rfind(notice)) << "the notice must be one-shot: " << output;
}

// One Observe() drives both families independently: a required V4 lost and an optional V6
// regained in the same pass each emit their own notice, neither suppressing the other.
TEST_F(FamilyCapabilityTest, ObserveReportsBothFamiliesIndependentlyInOnePass) {
    iface.SetV6(std::nullopt);  // v6 starts down
    FamilyCapability capability{iface, logger,
        {.uses = {true, true}, .required = {true, false}}};

    iface.SetV4(std::nullopt);             // required v4 lost -> Error
    iface.SetV6(IpAddress::LoopbackV6());  // optional v6 regained -> Info
    const std::string output = CaptureStdout([&] { capability.Observe(); });

    EXPECT_NE(output.find(std::format("Cannot reflect {} packets", IpAddress::Family::V4)),
        std::string::npos) << output;
    EXPECT_NE(output.find(std::format("Starting {} reflection", IpAddress::Family::V6)),
        std::string::npos) << output;
}

// Two-interface tracker: a family is sendable only when BOTH interfaces can send it, and losing it
// on EITHER one stops reflection (here the second interface drops v4).
TEST_F(FamilyCapabilityTest, TwoInterfacesCombineWithAnd) {
    FakeInterface second;  // defaults: loopback on both families
    FamilyCapability capability{iface, second, logger, USES_BOTH_REQUIRES_V4};

    EXPECT_TRUE(capability.CanSend(IpAddress::Family::V4));  // both interfaces can send v4

    const std::string output = CaptureStdout([&] {
        second.SetV4(std::nullopt);  // the second interface loses v4
        capability.Observe();
    });

    EXPECT_FALSE(capability.CanSend(IpAddress::Family::V4));  // combined capability is now false
    EXPECT_NE(output.find(std::format("Cannot reflect {} packets", IpAddress::Family::V4)),
        std::string::npos) << output;  // v4 is required -> Error
}

// Two-interface tracker, the Starting/Stopping notice paths: an optional (used-not-required) family
// regained on both interfaces logs Info "Starting", and lost again logs Info "Stopping" (not Error).
TEST_F(FamilyCapabilityTest, TwoInterfaceOptionalFamilyStartsAndStops) {
    FakeInterface second;
    second.SetV6(std::nullopt);  // v6 down on the second interface at construction
    FamilyCapability capability{iface, second, logger, USES_BOTH_REQUIRES_V4};

    const std::string up = CaptureStdout([&] {
        second.SetV6(IpAddress::LoopbackV6());  // v6 now sendable on both -> Starting
        capability.Observe();
    });
    EXPECT_NE(up.find(std::format("Starting {} reflection", IpAddress::Family::V6)),
        std::string::npos) << up;

    const std::string down = CaptureStdout([&] {
        second.SetV6(std::nullopt);  // v6 lost again -> Stopping (Info, v6 is merely used)
        capability.Observe();
    });
    EXPECT_NE(down.find(std::format("Stopping {} reflection", IpAddress::Family::V6)),
        std::string::npos) << down;
    EXPECT_EQ(down.find("ERROR"), std::string::npos) << down;
}

TEST_F(FamilyCapabilityTest, UnusedFamilyChangesAreTrackedSilently) {
    FamilyCapability capability{iface, logger,
        {.uses = {true, false}, .required = {true, false}}};

    iface.SetV6(std::nullopt);
    const std::string lost = CaptureStdout([&] { capability.Observe(); });
    EXPECT_TRUE(lost.empty()) << lost;

    iface.SetV6(IpAddress::LoopbackV6());
    const std::string regained = CaptureStdout([&] { capability.Observe(); });
    EXPECT_TRUE(regained.empty()) << regained;
}

} // namespace reflector
