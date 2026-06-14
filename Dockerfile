# syntax=docker/dockerfile:1.24

ARG DEBIAN_TRIXIE_SLIM=docker.io/library/debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e

# build-env runs on the BUILD host (so the arm/v7 and arm/v5 images cross-compile on an amd64/arm64
# runner rather than under slow QEMU). For a native target (amd64 on amd64, arm64 on arm64) the
# conditional below is a no-op and /toolchain.cmake is empty, so --toolchain is a no-op in the builder
# stage. For 32-bit arm it installs the matching cross toolchain (armhf for v7, armel for v5) and writes
# a CMake toolchain file selecting it.
FROM --platform=$BUILDPLATFORM ${DEBIAN_TRIXIE_SLIM} AS build-env
ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        git \
        iproute2 \
        ninja-build \
        tzdata \
    && if [ "$TARGETARCH" = arm ]; then \
        case "$TARGETVARIANT" in \
          v7) triple=arm-linux-gnueabihf; pkg=armhf ;; \
          v5) triple=arm-linux-gnueabi;  pkg=armel ;; \
          *)  echo "unsupported arm variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
        esac; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            "crossbuild-essential-${pkg}" "g++-14-${triple}" "gcc-14-${triple}"; \
        { echo 'set(CMAKE_SYSTEM_NAME Linux)'; \
          echo 'set(CMAKE_SYSTEM_PROCESSOR arm)'; \
          echo "set(CMAKE_C_COMPILER ${triple}-gcc-14)"; \
          echo "set(CMAKE_CXX_COMPILER ${triple}-g++-14)"; } > /toolchain.cmake; \
    else \
        : > /toolchain.cmake; \
    fi

WORKDIR /src
COPY CMakeLists.txt ./
COPY src/ ./src/

FROM build-env AS builder
RUN --mount=type=cache,target=/src/build/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build \
        --toolchain /toolchain.cmake \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_TESTING=OFF \
        -D REFLECTOR_SANITIZE=OFF \
        -D REFLECTOR_STATIC=ON \
    && cmake --build build --target reflector_app

# Build the test binary only — do NOT run ctest here. docker build can't grant CAP_NET_ADMIN,
# which the veth-pair RequiresRoot tests need to create interfaces; the suite is run via
# `docker run --cap-add=NET_ADMIN` instead (see docker_test.sh). The ENTRYPOINT fixes the ctest
# prefix so a bare run executes the full suite and any extra args append to it.
FROM build-env AS test-debug
COPY tests/ ./tests/
RUN --mount=type=cache,target=/src/build-test-debug/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build-test-debug \
        -D CMAKE_BUILD_TYPE=Debug \
        -D BUILD_TESTING=ON \
        -D REFLECTOR_SANITIZE=ON \
    && cmake --build build-test-debug --target reflector_test
ENTRYPOINT ["ctest", "--test-dir", "build-test-debug", "-L", "unit"]
CMD ["--output-on-failure"]

FROM build-env AS test-release
COPY tests/ ./tests/
RUN --mount=type=cache,target=/src/build-test-release/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build-test-release \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_TESTING=ON \
        -D REFLECTOR_SANITIZE=OFF \
        -D REFLECTOR_STATIC=ON \
    && cmake --build build-test-release --target reflector_test
ENTRYPOINT ["ctest", "--test-dir", "build-test-release", "-L", "unit"]
CMD ["--output-on-failure"]

# Run the whole unit binary under Valgrind memcheck. Debug + no sanitizers (Valgrind and ASan are
# mutually exclusive; -g yields readable traces) — the instrumentation is orthogonal to the
# test-debug/test-release build variants. Run via `docker run --cap-add=NET_ADMIN` so the RequiresRoot
# tests execute too; a definite/indirect/possible leak or any memcheck error exits 1 (see docker_test.sh
# valgrind). "still reachable" is allowed — file-local static singletons (GetLogger) live to exit by
# design. No --track-fds here: unit tests intentionally open/close/probe fds (one verifies a move closed
# the old one), so fd-leak tracking belongs in Valgrind.E2E against the real daemon, not the test binary.
FROM build-env AS test-valgrind
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends valgrind
COPY tests/ ./tests/
RUN --mount=type=cache,target=/src/build-test-valgrind/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build-test-valgrind \
        -D CMAKE_BUILD_TYPE=Debug \
        -D BUILD_TESTING=ON \
        -D REFLECTOR_SANITIZE=OFF \
    && cmake --build build-test-valgrind --target reflector_test
ENTRYPOINT ["valgrind", \
    "--leak-check=full", \
    "--show-leak-kinds=all", \
    "--errors-for-leak-kinds=definite,indirect,possible", \
    "--num-callers=30", \
    "--error-exitcode=1", \
    "/src/build-test-valgrind/tests/reflector_test"]

# The production Release binary, rebuilt with -ggdb3 for readable traces (debug symbols don't change
# the -O3/LTO codegen, so it's the same shipped machine code), wrapped in Valgrind memcheck. Run by
# `e2e/run.py --valgrind`, which SIGTERMs the daemon for a clean exit so valgrind reports leaks at exit.
# Unlike the unit gate this DOES use --track-fds: a leaked socket in the live daemon is a real bug.
# --error-exitcode=1 fails the run on any leak, leaked fd, or memcheck error.
FROM build-env AS builder-valgrind
RUN --mount=type=cache,target=/src/build-valgrind/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build-valgrind \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_TESTING=OFF \
        -D REFLECTOR_SANITIZE=OFF \
        -D CMAKE_CXX_FLAGS=-ggdb3 \
    && cmake --build build-valgrind --target reflector_app

FROM ${DEBIAN_TRIXIE_SLIM} AS runtime-valgrind
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends valgrind
COPY --from=builder-valgrind /src/build-valgrind/reflector /usr/local/bin/reflector
ENTRYPOINT ["valgrind", \
    "--leak-check=full", \
    "--show-leak-kinds=all", \
    "--errors-for-leak-kinds=definite,indirect,possible", \
    "--track-fds=yes", \
    "--num-callers=30", \
    "--error-exitcode=1", \
    "/usr/local/bin/reflector"]
CMD ["/etc/reflector/config.toml"]

# Production image: one fully static binary on scratch — nothing else to ship or to carry CVEs. zoneinfo
# is copied in so a TZ=<zone> env var yields local-time logs (the static binary still reads the tz
# database at runtime). Keep this LAST so a bare `docker build .` (no --target, as e2e/run.py and
# releases use) defaults to it rather than to a test/valgrind stage.
FROM scratch AS runtime
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /src/build/reflector /usr/local/bin/reflector
ENTRYPOINT ["/usr/local/bin/reflector"]
# No default argument: with none the reflector configures itself from REFLECTOR_* environment
# variables. To use a file instead, mount it and pass its path, e.g. `docker run ... <image> /etc/reflector/config.toml`.
