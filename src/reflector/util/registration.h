#pragma once

#include "no_copy.h"

#include <utility>

namespace reflector {

// RAII handle for a registration held by an `Owner` (a dispatcher/registry). Resetting or
// destroying it unregisters via `Owner::Unregister(key)`. The `Owner` mints handles through its
// protected `MakeRegistration` (this constructor is private and friended to `Owner`) and declares
// `Unregister` privately, befriending this handle back via `friend Registration;` so `Reset` can
// reach it. Movable, non-copyable; a default/moved-from/reset handle holds a null owner.
template <typename Owner, typename Key>
class Registration : NoCopy {
public:
    Registration() noexcept = default;
    ~Registration() noexcept { Reset(); }

    Registration(Registration&& other) noexcept
            : owner_{std::exchange(other.owner_, nullptr)}, key_{other.key_} {}
    Registration& operator=(Registration&& other) noexcept {
        if (this != &other) {
            Reset();
            owner_ = std::exchange(other.owner_, nullptr);
            key_ = other.key_;
        }
        return *this;
    }

    [[nodiscard]] bool IsValid() const noexcept { return owner_ != nullptr; }

    bool Reset() noexcept {
        if (owner_ == nullptr) {
            return false;
        }
        return std::exchange(owner_, nullptr)->Unregister(key_);
    }

private:
    friend Owner;

    Registration(Owner* owner, Key key) noexcept : owner_{owner}, key_{key} {}

    Owner* owner_ = nullptr;
    Key key_{};
};

} // namespace reflector
