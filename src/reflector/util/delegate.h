#pragma once

// Delegate lives in its own repository (https://github.com/sbogomolov/delegate), pulled in via
// FetchContent. This adapter re-exports it under the reflector namespace so the rest of the codebase
// keeps spelling it `Delegate` / `CreateDelegate` unqualified.
#include <delegate/delegate.h>

namespace reflector {

using delegate::CreateDelegate;
using delegate::Delegate;

} // namespace reflector
