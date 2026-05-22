#include "error.h"

#include <cerrno>
#include <system_error>

namespace reflector {

Error Error::FromErrno() {
    return FromErrno(errno);
}

Error Error::FromErrno(int err) {
    return Error{"({}) {}", err, std::system_category().message(err)};
}

} // namespace reflector
