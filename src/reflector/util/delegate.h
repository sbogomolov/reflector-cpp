#pragma once

#include <cassert>
#include <type_traits>
#include <utility>

namespace reflector {

template <typename T>
class Delegate;

namespace detail {
    template <typename T, typename R, typename... Args>
    struct MethodHelperBase {
        using ClassT = T;
        using DelegateT = Delegate<R(Args...)>;
    };

    template <typename T>
    struct MethodHelper;

    template <typename T, typename R, typename... Args, bool is_noexcept>
    struct MethodHelper<R (T::*)(Args...) noexcept(is_noexcept)> : MethodHelperBase<T, R, Args...> {};

    template <typename T, typename R, typename... Args, bool is_noexcept>
    struct MethodHelper<R (T::*)(Args...) const noexcept(is_noexcept)> : MethodHelperBase<T, R, Args...> {};

    template <typename T, typename R, typename... Args, bool is_noexcept>
    struct MethodHelper<R (T::*)(Args...) volatile noexcept(is_noexcept)> : MethodHelperBase<T, R, Args...> {};

    template <typename T, typename R, typename... Args, bool is_noexcept>
    struct MethodHelper<R (T::*)(Args...) const volatile noexcept(is_noexcept)> : MethodHelperBase<T, R, Args...> {};

    template <auto method>
    using DelegateForMethod = MethodHelper<decltype(method)>::DelegateT;

    // Satisfied when `method` can be invoked on a `T*`: T is the method's class, or derives from it. The
    // derived case lets &Base::m bind on a Derived instance — taking &Derived::m of an inherited m yields a
    // Base member pointer, so ClassT is Base while T is Derived. MethodStub's static_cast<T*> does the upcast.
    template <auto method, typename T>
    concept IsMethodOfClass = std::is_base_of_v<typename MethodHelper<decltype(method)>::ClassT, T>;

    template <typename R, typename... Args>
    struct FunctionHelperBase {
        using DelegateT = Delegate<R(Args...)>;
    };

    template <typename T>
    struct FunctionHelper;

    template <typename R, typename... Args, bool is_noexcept>
    struct FunctionHelper<R (*)(Args...) noexcept(is_noexcept)> : FunctionHelperBase<R, Args...> {};

    template <auto function>
    using DelegateForFunction = FunctionHelper<decltype(function)>::DelegateT;
} // namespace reflector::detail

template <typename R, typename... Args>
class Delegate<R(Args...)>
{
private:
    // Calls are forwarded into this fixed erased stub. Full forwarding cannot
    // continue past this boundary because Args... are part of StubT; use
    // reference-qualified delegate signatures when zero-copy behavior matters.
    typedef R (*StubT)(void*, Args...);

public:
    template <typename T, auto method>
        requires detail::IsMethodOfClass<method, T>
    [[nodiscard]] static Delegate FromMethod(T* object) noexcept {
        return Delegate{object, &MethodStub<T, method>};
    }

    template <R (*function)(Args...)>
    [[nodiscard]] static Delegate FromStatic() noexcept {
        return Delegate{nullptr, &FunctionStub<function>};
    }

    template <typename... CallArgs>
        requires std::is_invocable_r_v<R, StubT, void*, CallArgs&&...>
    R operator()(CallArgs&& ...args) const {
        assert(stub_ != nullptr);
        return stub_(object_, std::forward<CallArgs>(args)...);
    }

    // Default-constructed delegates are invalid: they bind nothing, and calling operator() on one
    // is undefined — it does not check, to keep the call branch-free on hot paths. Guard with
    // IsValid() when a delegate may not have been assigned a target.
    Delegate() noexcept = default;
    Delegate(void* object, StubT stub) : object_{object}, stub_{stub} {}

    [[nodiscard]] bool IsValid() const noexcept { return stub_ != nullptr; }

    template <typename T, auto method>
    [[nodiscard]] static R MethodStub(void* object, Args... args) {
        return (static_cast<T*>(object)->*method)(std::forward<Args>(args)...);
    }

    template <auto function>
    [[nodiscard]] static R FunctionStub(void* /* not used */, Args... args) {
        return (*function)(std::forward<Args>(args)...);
    }

    void* object_ = nullptr;
    StubT stub_ = nullptr;
};

template <auto method, typename T, typename D = detail::DelegateForMethod<method>>
[[nodiscard]] inline auto CreateDelegate(T* object) noexcept
{
    return D::template FromMethod<T, method>(object);
}

template <auto function, typename D = detail::DelegateForFunction<function>>
[[nodiscard]] inline auto CreateDelegate() noexcept
{
    return D::template FromStatic<function>();
}

} // namespace reflector
