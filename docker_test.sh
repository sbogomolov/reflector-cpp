#!/usr/bin/env bash
# Build the Dockerfile test image and run the unit suite in a container with CAP_NET_ADMIN,
# so the veth-pair RequiresRoot tests (which create interfaces) actually run instead of
# skipping. docker build can't grant the capability, so the image is build-only and the
# suite runs here via `docker run`.
#
#   ./docker_test.sh                      # Debug (ASan/UBSan)
#   ./docker_test.sh release              # Release
#   ./docker_test.sh debug -R RawSocket   # extra args are forwarded to ctest
set -euo pipefail

variant="${1:-debug}"
if [[ $# -gt 0 ]]; then
    shift
fi

case "${variant}" in
    debug | release) ;;
    *)
        echo "usage: $0 [debug|release] [ctest args...]" >&2
        exit 2
        ;;
esac

cd "$(dirname "$0")"

target="test-${variant}"
image="reflector:${target}"

docker build --target "${target}" -t "${image}" .
docker run --rm --cap-add=NET_ADMIN "${image}" "$@"
