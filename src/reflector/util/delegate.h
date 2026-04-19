#pragma once

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

    template <auto method, typename T>
    concept IsMethodOfClass = std::is_same_v<T, typename MethodHelper<decltype(method)>::ClassT>;

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
        return stub_(object_, std::forward<CallArgs>(args)...);
    }

    Delegate(void* object, StubT stub) : object_{object}, stub_{stub} {}

    template <typename T, auto method>
    [[nodiscard]] static R MethodStub(void* object, Args... args) {
        return (static_cast<T*>(object)->*method)(std::forward<Args>(args)...);
    }

    template <auto function>
    [[nodiscard]] static R FunctionStub(void* /* not used */, Args... args) {
        return (*function)(std::forward<Args>(args)...);
    }

    void* object_;
    StubT stub_;
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
