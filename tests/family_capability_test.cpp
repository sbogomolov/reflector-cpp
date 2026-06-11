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
    const FamilyCapability capability{iface, "target", logger,
        {.uses = {true, false}, .required = {true, false}}};

    EXPECT_TRUE(capability.CanSend(IpAddress::Family::V4));
    EXPECT_FALSE(capability.CanSend(IpAddress::Family::V6));  // config never uses v6

    iface.SetV4(std::nullopt);  // capability is read live, no Observe needed
    EXPECT_FALSE(capability.CanSend(IpAddress::Family::V4));
}

TEST_F(FamilyCapabilityTest, ObserveIsQuietWithoutAChange) {
    FamilyCapability capability{iface, "target", logger, USES_BOTH_REQUIRES_V4};

    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    EXPECT_TRUE(output.empty()) << output;
}

TEST_F(FamilyCapabilityTest, LosingARequiredFamilyLogsErrorOnce) {
    FamilyCapability capability{iface, "target", logger, USES_BOTH_REQUIRES_V4};

    iface.SetV4(std::nullopt);
    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    const auto error = std::format("Cannot reflect {} packets", IpAddress::Family::V4);
    EXPECT_NE(output.find(error), std::string::npos) << output;
    EXPECT_EQ(output.find(error), output.rfind(error)) << "the notice must be one-shot: " << output;
    EXPECT_NE(output.find("target interface"), std::string::npos) << output;
}

TEST_F(FamilyCapabilityTest, LosingAMerelyUsedFamilyLogsInfoOnce) {
    FamilyCapability capability{iface, "source", logger, USES_BOTH_REQUIRES_V4};

    iface.SetV6(std::nullopt);
    const std::string output = CaptureStdout([&] {
        capability.Observe();
        capability.Observe();
    });

    const auto notice = std::format("Stopping {} reflection", IpAddress::Family::V6);
    EXPECT_NE(output.find(notice), std::string::npos) << output;
    EXPECT_EQ(output.find(notice), output.rfind(notice)) << "the notice must be one-shot: " << output;
    EXPECT_NE(output.find("source interface"), std::string::npos) << output;
    EXPECT_EQ(output.find("ERROR"), std::string::npos) << output;
}

TEST_F(FamilyCapabilityTest, RegainingAFamilyLogsInfoOnce) {
    iface.SetV6(std::nullopt);
    FamilyCapability capability{iface, "target", logger, USES_BOTH_REQUIRES_V4};

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
    FamilyCapability capability{iface, "target", logger,
        {.uses = {true, true}, .required = {true, false}}};

    iface.SetV4(std::nullopt);             // required v4 lost -> Error
    iface.SetV6(IpAddress::LoopbackV6());  // optional v6 regained -> Info
    const std::string output = CaptureStdout([&] { capability.Observe(); });

    EXPECT_NE(output.find(std::format("Cannot reflect {} packets", IpAddress::Family::V4)),
        std::string::npos) << output;
    EXPECT_NE(output.find(std::format("Starting {} reflection", IpAddress::Family::V6)),
        std::string::npos) << output;
}

TEST_F(FamilyCapabilityTest, UnusedFamilyChangesAreTrackedSilently) {
    FamilyCapability capability{iface, "target", logger,
        {.uses = {true, false}, .required = {true, false}}};

    iface.SetV6(std::nullopt);
    const std::string lost = CaptureStdout([&] { capability.Observe(); });
    EXPECT_TRUE(lost.empty()) << lost;

    iface.SetV6(IpAddress::LoopbackV6());
    const std::string regained = CaptureStdout([&] { capability.Observe(); });
    EXPECT_TRUE(regained.empty()) << regained;
}

} // namespace reflector
