# syntax=docker/dockerfile:1.7

ARG DEBIAN_TRIXIE_SLIM=docker.io/library/debian:trixie-slim@sha256:109e2c65005bf160609e4ba6acf7783752f8502ad218e298253428690b9eaa4b
ARG DISTROLESS_CC_DEBIAN13=gcr.io/distroless/cc-debian13:latest@sha256:56aaf20ab2523a346a67c8e8f8e8dabe447447d0788b82284d14ad79cd5f93cc

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
        -D CMAKE_CXX_COMPILER_LAUNCHER=ccache \
    && cmake --build build --target reflector_app

FROM build-env AS test
COPY tests/ ./tests/
RUN --mount=type=cache,target=/src/build-test/_deps,sharing=locked \
    --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    cmake -G Ninja -B build-test \
        -D CMAKE_BUILD_TYPE=Debug \
        -D BUILD_TESTING=ON \
        -D REFLECTOR_ENABLE_E2E_TESTS=OFF \
        -D REFLECTOR_SANITIZE=OFF \
        -D CMAKE_CXX_COMPILER_LAUNCHER=ccache \
    && cmake --build build-test --target reflector_test \
    && ctest --test-dir build-test -L unit --output-on-failure

FROM ${DISTROLESS_CC_DEBIAN13} AS runtime
COPY --from=builder /src/build/reflector /usr/local/bin/reflector
ENTRYPOINT ["/usr/local/bin/reflector"]
CMD ["/etc/reflector/config.toml"]
