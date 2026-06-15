#pragma once

// IWYU pragma: always_keep
//
// Single supported-platform contract for the whole project. Linux is the outlier (netlink,
// AF_PACKET, epoll); macOS and FreeBSD share the BSD path (kqueue, BPF, route sockets,
// getifaddrs). Platform-specific code branches on __linux__ and routes everything else through
// #else, so an unsupported OS would otherwise silently compile the BSD path and fail with
// confusing downstream errors. Every file that makes a platform assumption includes this header
// so the failure is one clear message instead.
#if !defined(__linux__) && !defined(__APPLE__) && !defined(__FreeBSD__)
#error "reflector only supports Linux, macOS, and FreeBSD"
#endif
