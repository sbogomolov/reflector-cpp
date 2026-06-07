# syntax=docker/dockerfile:1.24

ARG DEBIAN_TRIXIE_SLIM=docker.io/library/debian:trixie-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8
ARG DISTROLESS_CC_DEBIAN13=gcr.io/distroless/cc-debian13:latest@sha256:8b5d1db6d2253036a53cb8362d3e3fa82a7caf84c247772c46a023166c64e977

FROM ${DEBIAN_TRIXIE_SLIM} AS build-env
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
        ninja-build

WORKDIR /src
COPY CMakeLists.txt ./
COPY src/ ./src/

FROM build-env AS builder
RUN --mount=type=cache,target=/src/build/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_TESTING=OFF \
        -D REFLECTOR_SANITIZE=OFF \
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

FROM ${DISTROLESS_CC_DEBIAN13} AS runtime
COPY --from=builder /src/build/reflector /usr/local/bin/reflector
ENTRYPOINT ["/usr/local/bin/reflector"]
CMD ["/etc/reflector/config.toml"]
