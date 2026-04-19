#include "error.h"

#include <cerrno>
#include <system_error>

namespace reflector {

Error Error::FromErrno() {
    const int err = errno;
    return Error{"({}) {}", err, std::system_category().message(err)};
}

} // namespace reflector
