#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <utility>

using namespace reflector;

struct DelegateTestClass {
    int Method(int, float) { return 1; }
    void MethodNoReturn(int& ret, float) { ret = 2; }
    int MethodNoArgs() { return 3; }

    int MethodConst() const { return 4; }
    int MethodVolatile() volatile { return 5; }
    int MethodConstVolatile() const volatile { return 6; }

    int MethodNoexcept() noexcept { return 7; }
    int MethodConstNoexcept() const noexcept { return 8; }
    int MethodVolatileNoexcept() volatile noexcept { return 9; }
    int MethodConstVolatileNoexcept() const volatile noexcept { return 10; }

    static int StaticMethod(int, float) { return 11; }
    static void StaticMethodNoReturn(int& ret, float) { ret = 12; }
    static int StaticMethodNoArgs() { return 13; }

    static int StaticMethodNoexcept() noexcept { return 14; }
};

struct DelegateForwardingTestNonMovable {
    DelegateForwardingTestNonMovable() = default;
    DelegateForwardingTestNonMovable(const DelegateForwardingTestNonMovable&) = delete;
    DelegateForwardingTestNonMovable& operator=(const DelegateForwardingTestNonMovable&) = delete;
    DelegateForwardingTestNonMovable(DelegateForwardingTestNonMovable&&) = delete;
    DelegateForwardingTestNonMovable& operator=(DelegateForwardingTestNonMovable&&) = delete;
};

struct DelegateForwardingTestSink {
    const DelegateForwardingTestNonMovable* stored_ptr = nullptr;

    void ConstLvalueRef(const DelegateForwardingTestNonMovable& value) {
        stored_ptr = &value;
    }

    void LvalueRef(DelegateForwardingTestNonMovable& value) {
        stored_ptr = &value;
    }

    void RvalueRef(DelegateForwardingTestNonMovable&& value) {
        stored_ptr = &value;
    }

    void PointerByValue(const DelegateForwardingTestNonMovable* value) {
        stored_ptr = value;
    }
};

TEST(DelegateTest, InstanceMethods) {
    DelegateTestClass test;

    auto delegate = CreateDelegate<&DelegateTestClass::Method>(&test);
    EXPECT_EQ(delegate(1, 2.3f), 1);

    auto delegate_no_ret = CreateDelegate<&DelegateTestClass::MethodNoReturn>(&test);
    int ret;
    delegate_no_ret(ret, 2.3f);
    EXPECT_EQ(ret, 2);

    auto delegate_no_args = CreateDelegate<&DelegateTestClass::MethodNoArgs>(&test);
    EXPECT_EQ(delegate_no_args(), 3);
}

TEST(DelegateTest, ConstVolatileMethods) {
    DelegateTestClass test;

    auto delegate_c = CreateDelegate<&DelegateTestClass::MethodConst>(&test);
    EXPECT_EQ(delegate_c(), 4);

    auto delegate_v = CreateDelegate<&DelegateTestClass::MethodVolatile>(&test);
    EXPECT_EQ(delegate_v(), 5);

    auto delegate_cv = CreateDelegate<&DelegateTestClass::MethodConstVolatile>(&test);
    EXPECT_EQ(delegate_cv(), 6);
}

TEST(DelegateTest, NoexceptMethods) {
    DelegateTestClass test;

    auto delegate_n = CreateDelegate<&DelegateTestClass::MethodNoexcept>(&test);
    EXPECT_EQ(delegate_n(), 7);

    auto delegate_c_n = CreateDelegate<&DelegateTestClass::MethodConstNoexcept>(&test);
    EXPECT_EQ(delegate_c_n(), 8);

    auto delegate_v_n = CreateDelegate<&DelegateTestClass::MethodVolatileNoexcept>(&test);
    EXPECT_EQ(delegate_v_n(), 9);

    auto delegate_cv_n = CreateDelegate<&DelegateTestClass::MethodConstVolatileNoexcept>(&test);
    EXPECT_EQ(delegate_cv_n(), 10);
}

TEST(DelegateTest, StaticMethods) {
    auto static_delegate = CreateDelegate<&DelegateTestClass::StaticMethod>();
    EXPECT_EQ(static_delegate(1, 2.3f), 11);

    auto static_delegate_no_ret = CreateDelegate<&DelegateTestClass::StaticMethodNoReturn>();
    int ret;
    static_delegate_no_ret(ret, 2.3f);
    EXPECT_EQ(ret, 12);

    auto static_delegate_no_args = CreateDelegate<&DelegateTestClass::StaticMethodNoArgs>();
    EXPECT_EQ(static_delegate_no_args(), 13);
}

TEST(DelegateTest, StaticNoexceptMethods) {
    auto static_delegate_n = CreateDelegate<&DelegateTestClass::StaticMethodNoexcept>();
    EXPECT_EQ(static_delegate_n(), 14);
}

TEST(DelegateTest, ForwardsConstLvalueReference) {
    DelegateForwardingTestSink sink;
    DelegateForwardingTestNonMovable value;

    auto delegate = CreateDelegate<&DelegateForwardingTestSink::ConstLvalueRef>(&sink);
    delegate(value);

    EXPECT_EQ(sink.stored_ptr, &value);
}

TEST(DelegateTest, ForwardsLvalueReference) {
    DelegateForwardingTestSink sink;
    DelegateForwardingTestNonMovable value;

    auto delegate = CreateDelegate<&DelegateForwardingTestSink::LvalueRef>(&sink);
    delegate(value);

    EXPECT_EQ(sink.stored_ptr, &value);
}

TEST(DelegateTest, ForwardsRvalueReference) {
    DelegateForwardingTestSink sink;
    DelegateForwardingTestNonMovable value;

    auto delegate = CreateDelegate<&DelegateForwardingTestSink::RvalueRef>(&sink);
    delegate(std::move(value));

    EXPECT_EQ(sink.stored_ptr, &value);
}

TEST(DelegateTest, PassesPointerByValue) {
    DelegateForwardingTestSink sink;
    DelegateForwardingTestNonMovable value;

    auto delegate = CreateDelegate<&DelegateForwardingTestSink::PointerByValue>(&sink);
    delegate(&value);

    EXPECT_EQ(sink.stored_ptr, &value);
}

TEST(DelegateTest, DefaultConstructedIsInvalid) {
    const Delegate<int(int, float)> empty;
    EXPECT_FALSE(empty.IsValid());

    DelegateTestClass test;
    const auto bound = CreateDelegate<&DelegateTestClass::Method>(&test);
    EXPECT_TRUE(bound.IsValid());
}

TEST(DelegateTest, AssignedAfterDefaultConstructionIsCallable) {
    DelegateTestClass test;

    // The "bind later" case the default constructor exists for: hold an empty delegate, assign a
    // target afterwards, then call it.
    Delegate<int(int, float)> delegate;
    ASSERT_FALSE(delegate.IsValid());

    delegate = CreateDelegate<&DelegateTestClass::Method>(&test);

    EXPECT_TRUE(delegate.IsValid());
    EXPECT_EQ(delegate(1, 2.3f), 1);
}
