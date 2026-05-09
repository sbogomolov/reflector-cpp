# syntax=docker/dockerfile:1.7

FROM debian:trixie-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY src/ ./src/

RUN cmake -G Ninja -B build \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_TESTING=OFF \
        -D REFLECTOR_SANITIZE=OFF \
    && cmake --build build --target reflector_app

FROM gcr.io/distroless/cc-debian13
COPY --from=builder /src/build/reflector /usr/local/bin/reflector
ENTRYPOINT ["/usr/local/bin/reflector"]
CMD ["/etc/reflector/config.toml"]
