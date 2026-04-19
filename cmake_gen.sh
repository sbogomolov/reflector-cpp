#!/bin/sh

build_type="${1:-Debug}"

case "$build_type" in
    Debug|Release) ;;
    *)
        echo "Unknown build type: $build_type" >&2
        echo "Usage: $0 [Debug|Release]" >&2
        exit 1
        ;;
esac

cmake -G Ninja -B build -D CMAKE_BUILD_TYPE="$build_type"
