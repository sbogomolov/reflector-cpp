#!/bin/sh
set -eu

# Single source of truth for the project version: extracts it from the project() command in
# CMakeLists.txt. docker_build.sh (image tag), release.sh (git tag), and the tag-version CI guard
# all read it from here, so the image, the git tag, and the GitHub release share one value.
root="$(dirname "$0")"
version=$(sed -n 's/.*project([[:space:]]*reflector[[:space:]]*VERSION[[:space:]]*\([0-9.]*\).*/\1/p' "$root/CMakeLists.txt")
if [ -z "$version" ]; then
    echo "Cannot determine VERSION from CMakeLists.txt" >&2
    exit 1
fi
printf '%s\n' "$version"
