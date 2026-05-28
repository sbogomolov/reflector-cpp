#include "reflector/mdns_message.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

using namespace reflector;

namespace {

// A 12-byte DNS header carrying `flags_high` as the high byte of the flags field (byte 2); all
// other header bytes zero. The QR bit lives in this byte, so it's all the classifier reads.
std::array<std::byte, 12> HeaderWithFlagsHigh(uint8_t flags_high) {
    std::array<std::byte, 12> header{};
    header[2] = std::byte{flags_high};
    return header;
}

} // namespace

TEST(MdnsMessageTest, ClassifiesQueryWhenQrBitClear) {
    EXPECT_EQ(ClassifyMdnsMessage(HeaderWithFlagsHigh(0x00)), MdnsMessageKind::Query);
}

TEST(MdnsMessageTest, ClassifiesResponseWhenQrBitSet) {
    // 0x84: QR=1, AA=1 — the usual flags on an mDNS response/announcement.
    EXPECT_EQ(ClassifyMdnsMessage(HeaderWithFlagsHigh(0x84)), MdnsMessageKind::Response);
}

TEST(MdnsMessageTest, ClassifiesByQrBitOnlyIgnoringOtherFlags) {
    // Every flag bit except QR set → still a query.
    EXPECT_EQ(ClassifyMdnsMessage(HeaderWithFlagsHigh(0x7f)), MdnsMessageKind::Query);
    // Only the QR bit set → response.
    EXPECT_EQ(ClassifyMdnsMessage(HeaderWithFlagsHigh(0x80)), MdnsMessageKind::Response);
}

TEST(MdnsMessageTest, AcceptsExactlyTwelveBytes) {
    const std::array<std::byte, 12> minimal{};  // all zero → QR clear → query
    EXPECT_EQ(ClassifyMdnsMessage(minimal), MdnsMessageKind::Query);
}

TEST(MdnsMessageTest, AcceptsPayloadLongerThanHeader) {
    // A 12-byte header (QR=1) followed by a question/record section: length > 12 is accepted, and
    // the kind comes from the header — the trailing bytes are never read.
    std::array<std::byte, 24> message{};
    message[2] = std::byte{0x84};  // QR=1
    EXPECT_EQ(ClassifyMdnsMessage(message), MdnsMessageKind::Response);
}

TEST(MdnsMessageTest, RejectsPayloadShorterThanHeader) {
    const std::array<std::byte, 11> too_short{};
    EXPECT_EQ(ClassifyMdnsMessage(too_short), std::nullopt);
    EXPECT_EQ(ClassifyMdnsMessage(std::span<const std::byte>{}), std::nullopt);
}
