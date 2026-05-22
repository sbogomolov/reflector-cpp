#include "reflector/address_monitor.h"

#include "reflector/dispatcher.h"
#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif defined(__APPLE__)
#include <net/if.h>
#include <net/route.h>
#endif

namespace {

// The parser writes to an out-parameter, so tests assert on that directly; this sink only exists
// to give the monitor a valid callback at construction.
struct ChangeSink {
    void OnChange(unsigned /*interface_index*/) noexcept {}
};

#if defined(__linux__)

// Appends one netlink address message (nlmsghdr + ifaddrmsg) of the given type carrying
// ifa_index, laid out as the kernel emits it: the ifaddrmsg follows the 4-aligned nlmsghdr,
// which is where the parser's NLMSG_DATA lands. nlmsg_len (24) is already NLMSG_ALIGN'd, so
// concatenated messages pack contiguously.
void AppendAddrMessage(std::vector<std::byte>& out, uint16_t type, uint32_t interface_index) {
    static_assert(sizeof(nlmsghdr) % 4 == 0);
    nlmsghdr header{};
    header.nlmsg_len = static_cast<uint32_t>(sizeof(nlmsghdr) + sizeof(ifaddrmsg));
    header.nlmsg_type = type;
    ifaddrmsg message{};
    message.ifa_index = interface_index;

    const size_t start = out.size();
    out.resize(start + header.nlmsg_len);
    std::memcpy(out.data() + start, &header, sizeof(header));
    std::memcpy(out.data() + start + sizeof(nlmsghdr), &message, sizeof(message));
}

constexpr uint16_t ADDR_MESSAGE = RTM_NEWADDR;
constexpr uint16_t NON_ADDR_MESSAGE = RTM_NEWLINK;

#elif defined(__APPLE__)

// Appends one PF_ROUTE message (ifa_msghdr) of the given type carrying ifam_index. The parser
// reads ifam_msglen/ifam_type from the rt_msghdr-shared prefix and ifam_index from the
// ifa_msghdr layout, so an ifa_msghdr-shaped record exercises both reads.
void AppendAddrMessage(std::vector<std::byte>& out, unsigned char type, uint16_t interface_index) {
    ifa_msghdr message{};
    message.ifam_msglen = static_cast<unsigned short>(sizeof(ifa_msghdr));
    message.ifam_version = RTM_VERSION;
    message.ifam_type = type;
    message.ifam_index = interface_index;

    const size_t start = out.size();
    out.resize(start + sizeof(ifa_msghdr));
    std::memcpy(out.data() + start, &message, sizeof(message));
}

constexpr unsigned char ADDR_MESSAGE = RTM_NEWADDR;
constexpr unsigned char NON_ADDR_MESSAGE = RTM_IFINFO;

#endif

} // namespace

namespace reflector {

class AddressMonitorTest : public ::testing::Test {
protected:
    ChangeSink sink;
    AddressMonitor monitor{
        AddressMonitor::TestingTag{}, CreateDelegate<&ChangeSink::OnChange>(&sink)};

    std::vector<unsigned> Collect(std::span<const std::byte> messages) {
        std::vector<unsigned> changed;
        monitor.CollectChangedInterfaces(messages, changed);
        return changed;
    }
};

TEST_F(AddressMonitorTest, OpensKernelSocket) {
    Dispatcher dispatcher;
    AddressMonitor real{dispatcher, CreateDelegate<&ChangeSink::OnChange>(&sink)};
    EXPECT_TRUE(real.IsValid());
}

TEST_F(AddressMonitorTest, ReportsChangedInterfaceIndex) {
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 7);

    EXPECT_EQ(Collect(messages), (std::vector<unsigned>{7}));
}

TEST_F(AddressMonitorTest, ReportsEachMessageInBatch) {
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 2);
    AppendAddrMessage(messages, ADDR_MESSAGE, 5);
    AppendAddrMessage(messages, ADDR_MESSAGE, 9);

    EXPECT_EQ(Collect(messages), (std::vector<unsigned>{2, 5, 9}));
}

TEST_F(AddressMonitorTest, CoalescesRepeatedInterfaceIndices) {
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 5);
    AppendAddrMessage(messages, ADDR_MESSAGE, 3);

    // Each interface appears once, in first-seen order.
    EXPECT_EQ(Collect(messages), (std::vector<unsigned>{3, 5}));
}

TEST_F(AddressMonitorTest, IgnoresNonAddressMessages) {
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, NON_ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 4);
    AppendAddrMessage(messages, NON_ADDR_MESSAGE, 6);

    EXPECT_EQ(Collect(messages), (std::vector<unsigned>{4}));
}

} // namespace reflector
