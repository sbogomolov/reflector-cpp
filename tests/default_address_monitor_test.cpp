#include "reflector/default_address_monitor.h"

#include "reflector/event_loop_dispatcher.h"
#include "reflector/util/delegate.h"
#include "mocks/fake_dispatcher.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif defined(__APPLE__)
#include <net/if.h>
#include <net/route.h>
#endif

namespace {

// Records the interface indices the monitor reports, so tests assert on its actual on_change output.
struct RecordingChangeSink {
    void OnChange(unsigned interface_index) noexcept { changed.push_back(interface_index); }

    std::vector<unsigned> changed;
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
constexpr uint16_t DELETED_ADDR_MESSAGE = RTM_DELADDR;
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
constexpr unsigned char DELETED_ADDR_MESSAGE = RTM_DELADDR;
constexpr unsigned char NON_ADDR_MESSAGE = RTM_IFINFO;

#endif

} // namespace

namespace reflector {

// Drives DefaultAddressMonitor over a non-blocking socketpair registered with a FakeDispatcher: the
// test writes synthesized kernel notifications to the write end, fires the monitor's read callback,
// and asserts on the indices delivered to the recording sink — exercising the real
// recv->parse->deliver path with no kernel netlink/route socket.
class DefaultAddressMonitorTest : public ::testing::Test {
protected:
    FakeDispatcher dispatcher;
    RecordingChangeSink sink;
    int monitor_fd = -1;  // read end, owned by the monitor
    int write_fd = -1;    // write end, owned by the fixture

    ~DefaultAddressMonitorTest() override {
        if (write_fd >= 0) {
            ::close(write_fd);
        }
    }

    // Builds a monitor adopting one end of a fresh non-blocking socketpair; the other end is kept
    // for feeding notifications. The monitor owns and closes its (read) end. Like production, it
    // does not watch until StartWatching() — call that to begin observing.
    DefaultAddressMonitor MakeMonitor() {
        int fds[2];
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds), 0) << std::strerror(errno);
        EXPECT_EQ(::fcntl(fds[0], F_SETFL, O_NONBLOCK), 0) << std::strerror(errno);
        monitor_fd = fds[0];
        write_fd = fds[1];
        return DefaultAddressMonitor::ForTesting(dispatcher, fds[0]);
    }

    // Starts the monitor, binding the recording sink — the construct-then-Start() flow production
    // uses. Returns Start()'s result so tests can assert on it.
    [[nodiscard]] bool StartWatching(DefaultAddressMonitor& monitor) {
        return monitor.Start(CreateDelegate<&RecordingChangeSink::OnChange>(&sink));
    }

    // Writes one notification datagram to the monitor's socket.
    void Write(const std::vector<std::byte>& messages) {
        ASSERT_EQ(::write(write_fd, messages.data(), messages.size()),
            static_cast<ssize_t>(messages.size())) << std::strerror(errno);
    }

    // Fires the monitor's read callback, as the dispatcher would when the fd becomes readable.
    void FireReadable() { dispatcher.FireReadable(monitor_fd); }
};

TEST_F(DefaultAddressMonitorTest, RegistersFdWithDispatcher) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));

    EXPECT_TRUE(monitor.IsValid());
    EXPECT_TRUE(dispatcher.IsWatching(monitor_fd));
    EXPECT_EQ(dispatcher.RegistrationCount(), 1);
}

TEST_F(DefaultAddressMonitorTest, UnregistersOnDestruction) {
    {
        auto monitor = MakeMonitor();
        ASSERT_TRUE(StartWatching(monitor));
        ASSERT_EQ(dispatcher.RegistrationCount(), 1);
    }

    EXPECT_EQ(dispatcher.RegistrationCount(), 0);
}

TEST_F(DefaultAddressMonitorTest, ReportsNewAddress) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 7);

    Write(messages);
    FireReadable();

    EXPECT_EQ(sink.changed, (std::vector<unsigned>{7}));
}

TEST_F(DefaultAddressMonitorTest, ReportsDeletedAddress) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, DELETED_ADDR_MESSAGE, 4);

    Write(messages);
    FireReadable();

    EXPECT_EQ(sink.changed, (std::vector<unsigned>{4}));
}

TEST_F(DefaultAddressMonitorTest, ReportsEachInBatchCoalescingRepeats) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 5);

    Write(messages);
    FireReadable();

    // Each interface once, in first-seen order.
    EXPECT_EQ(sink.changed, (std::vector<unsigned>{3, 5}));
}

TEST_F(DefaultAddressMonitorTest, CoalescesAcrossReads) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    // Two separate datagrams (two recv reads in one drain) for the same index -> one callback.
    std::vector<std::byte> first;
    AppendAddrMessage(first, ADDR_MESSAGE, 8);
    std::vector<std::byte> second;
    AppendAddrMessage(second, ADDR_MESSAGE, 8);

    Write(first);
    Write(second);
    FireReadable();

    EXPECT_EQ(sink.changed, (std::vector<unsigned>{8}));
}

TEST_F(DefaultAddressMonitorTest, IgnoresNonAddressMessages) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, NON_ADDR_MESSAGE, 3);
    AppendAddrMessage(messages, ADDR_MESSAGE, 4);
    AppendAddrMessage(messages, NON_ADDR_MESSAGE, 6);

    Write(messages);
    FireReadable();

    EXPECT_EQ(sink.changed, (std::vector<unsigned>{4}));
}

TEST_F(DefaultAddressMonitorTest, IgnoresSpuriousWakeWithNoData) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));

    FireReadable();  // nothing was written

    EXPECT_TRUE(sink.changed.empty());
}

TEST_F(DefaultAddressMonitorTest, ToleratesTruncatedTrailingMessage) {
    auto monitor = MakeMonitor();
    ASSERT_TRUE(StartWatching(monitor));
    std::vector<std::byte> messages;
    AppendAddrMessage(messages, ADDR_MESSAGE, 2);
    messages.push_back(std::byte{0x42});  // a stray trailing byte, too short to be a message

    Write(messages);
    FireReadable();

    // The valid leading message is reported; the truncated tail is ignored, not over-read.
    EXPECT_EQ(sink.changed, (std::vector<unsigned>{2}));
}

TEST_F(DefaultAddressMonitorTest, StartRejectsUnboundCallback) {
    auto monitor = MakeMonitor();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(monitor.Start({}));  // a default-constructed (unbound) callback
    });

    EXPECT_FALSE(dispatcher.IsWatching(monitor_fd));
    EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
}

// The one genuinely-real test: opening the kernel notification socket and starting it on a real
// dispatcher succeeds (needs no privilege on Linux/macOS).
TEST(DefaultAddressMonitorRealSocketTest, OpensKernelSocket) {
    EventLoopDispatcher dispatcher;
    RecordingChangeSink sink;
    DefaultAddressMonitor monitor{dispatcher};

    EXPECT_TRUE(monitor.Start(CreateDelegate<&RecordingChangeSink::OnChange>(&sink)));
    EXPECT_TRUE(monitor.IsValid());
}

} // namespace reflector
