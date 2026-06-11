#include "reflector/util/address_family_pair.h"

#include "reflector/ip_address.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace reflector {

TEST(AddressFamilyPairTest, DefaultConstructsValueInitialized) {
    const AddressFamilyPair<int> pair;
    EXPECT_EQ(pair.V4(), 0);
    EXPECT_EQ(pair.V6(), 0);
}

TEST(AddressFamilyPairTest, TwoArgConstructorAssignsPerFamily) {
    const AddressFamilyPair<int> pair{4, 6};
    EXPECT_EQ(pair.V4(), 4);
    EXPECT_EQ(pair.V6(), 6);
}

TEST(AddressFamilyPairTest, CompileTimeGetSelectsPerFamily) {
    const AddressFamilyPair<int> pair{4, 6};
    EXPECT_EQ(pair.Get<IpAddress::Family::V4>(), 4);
    EXPECT_EQ(pair.Get<IpAddress::Family::V6>(), 6);
}

TEST(AddressFamilyPairTest, RuntimeGetSelectsPerFamily) {
    const AddressFamilyPair<int> pair{4, 6};
    EXPECT_EQ(pair.Get(IpAddress::Family::V4), 4);
    EXPECT_EQ(pair.Get(IpAddress::Family::V6), 6);
}

TEST(AddressFamilyPairTest, MutableAccessorsWriteBack) {
    AddressFamilyPair<int> pair;
    pair.V4() = 1;
    pair.Get<IpAddress::Family::V6>() = 2;
    EXPECT_EQ(pair.V4(), 1);
    EXPECT_EQ(pair.V6(), 2);

    pair.Get(IpAddress::Family::V4) = 7;  // runtime mutable form
    EXPECT_EQ(pair.V4(), 7);

    // The symmetric mutable forms (named V6, compile-time V4, runtime V6).
    pair.V6() = 3;
    pair.Get<IpAddress::Family::V4>() = 8;
    pair.Get(IpAddress::Family::V6) = 9;
    EXPECT_EQ(pair.V4(), 8);
    EXPECT_EQ(pair.V6(), 9);
}

TEST(AddressFamilyPairTest, CopyConstructsFromLvalues) {
    std::string v4 = "four";
    std::string v6 = "six";
    const AddressFamilyPair<std::string> pair{v4, v6};  // lvalues -> forwarding chooses the copy path
    EXPECT_EQ(pair.V4(), "four");
    EXPECT_EQ(pair.V6(), "six");
    EXPECT_EQ(v4, "four");  // sources untouched: copied, not moved
    EXPECT_EQ(v6, "six");
}

TEST(AddressFamilyPairTest, SupportsMoveOnlyTypes) {
    // Compiles only if the elements are move-forwarded — std::unique_ptr is non-copyable, so a
    // copy-forwarding ctor would fail to build. Pins the move path the lvalue test can't.
    const AddressFamilyPair<std::unique_ptr<int>> pair{std::make_unique<int>(4), std::make_unique<int>(6)};
    ASSERT_NE(pair.V4(), nullptr);
    ASSERT_NE(pair.V6(), nullptr);
    EXPECT_EQ(*pair.V4(), 4);
    EXPECT_EQ(*pair.V6(), 6);
}

// Const-correctness: every accessor on a const pair yields a const reference (regression guard
// for the deducing-this return type — a hardcoded `T&` would fail to compile here).
TEST(AddressFamilyPairTest, ConstAccessorsYieldConstReferences) {
    const AddressFamilyPair<int> pair{4, 6};
    static_assert(std::is_same_v<decltype(pair.V4()), const int&>);
    static_assert(std::is_same_v<decltype(pair.V6()), const int&>);
    static_assert(std::is_same_v<decltype(pair.Get<IpAddress::Family::V4>()), const int&>);
    static_assert(std::is_same_v<decltype(pair.Get<IpAddress::Family::V6>()), const int&>);
    static_assert(std::is_same_v<decltype(pair.Get(IpAddress::Family::V4)), const int&>);
    static_assert(std::is_same_v<decltype(pair.Get(IpAddress::Family::V6)), const int&>);

    AddressFamilyPair<int> mutable_pair;
    static_assert(std::is_same_v<decltype(mutable_pair.V4()), int&>);
    static_assert(std::is_same_v<decltype(mutable_pair.V6()), int&>);
    static_assert(std::is_same_v<decltype(mutable_pair.Get<IpAddress::Family::V4>()), int&>);
    static_assert(std::is_same_v<decltype(mutable_pair.Get<IpAddress::Family::V6>()), int&>);
    static_assert(std::is_same_v<decltype(mutable_pair.Get(IpAddress::Family::V4)), int&>);
    static_assert(std::is_same_v<decltype(mutable_pair.Get(IpAddress::Family::V6)), int&>);
    SUCCEED();
}

TEST(AddressFamilyPairTest, HoldsNonTrivialTypes) {
    AddressFamilyPair<std::string> pair{"four", "six"};
    EXPECT_EQ(pair.V4(), "four");
    EXPECT_EQ(pair.Get(IpAddress::Family::V6), "six");

    std::string moved_in = "moved";
    AddressFamilyPair<std::string> from_move{std::move(moved_in), "copied"};
    EXPECT_EQ(from_move.V4(), "moved");
    EXPECT_EQ(from_move.V6(), "copied");
}

} // namespace reflector
