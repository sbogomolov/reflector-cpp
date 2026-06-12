# Builds the reflector with debug symbols and NO sanitizers (ASan and valgrind are mutually
# exclusive), then packages it under valgrind. Used by soak.py to leak-check the daemon under a
# sustained mDNS/SSDP flood. Build from the repo root: docker build -f e2e/valgrind/Dockerfile .
ARG DEBIAN=docker.io/library/debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e

FROM ${DEBIAN} AS build
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake git ninja-build \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY src/ ./src/
RUN cmake -G Ninja -B build \
        -D CMAKE_BUILD_TYPE=Debug \
        -D BUILD_TESTING=OFF \
        -D REFLECTOR_SANITIZE=OFF \
    && cmake --build build --target reflector_app

FROM ${DEBIAN} AS valgrind
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        valgrind ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/reflector /usr/local/bin/reflector
# --track-fds catches a leaked reservation socket; --leak-check=full at clean SIGTERM exit catches a
# leaked Session/registration. --error-exitcode=0 so a finding doesn't crash the container before we
# read the report.
ENTRYPOINT ["valgrind", \
    "--leak-check=full", \
    "--show-leak-kinds=all", \
    "--track-fds=yes", \
    "--num-callers=30", \
    "--error-exitcode=0", \
    "/usr/local/bin/reflector"]
CMD ["/etc/reflector/config.toml"]
