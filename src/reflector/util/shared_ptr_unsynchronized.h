#pragma once

#include <memory>

#if defined(__GLIBCXX__)
#include <bits/shared_ptr_base.h>
#endif

namespace reflector {

#if defined(__GLIBCXX__)
template <typename T>
using SharedPtrUnsynchronized = std::__shared_ptr<T, __gnu_cxx::_S_single>;

template <typename T>
using WeakPtrUnsynchronized = std::__weak_ptr<T, __gnu_cxx::_S_single>;
#else
template <typename T>
using SharedPtrUnsynchronized = std::shared_ptr<T>;

template <typename T>
using WeakPtrUnsynchronized = std::weak_ptr<T>;
#endif

} // namespace reflector
