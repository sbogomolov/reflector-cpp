#!/bin/sh
set -eu

# Cut a release. From a clean main in sync with origin/main, this confirms the version, then tags
# v<version> (from CMakeLists.txt via version.sh) and pushes it. Pushing the tag triggers
# .github/workflows/release.yml, which gates on CI being green for the commit, builds the per-arch
# binaries, publishes the multi-arch image to GHCR, and creates the GitHub release.
# The version in CMakeLists.txt is the single source of truth; the pushed tag is re-checked against
# it by the "Tag version check" workflow.

cd "$(dirname "$0")"

version=$(./version.sh)
tag="v${version}"

if [ -n "$(git status --porcelain)" ]; then
    echo "Working tree is not clean; commit or stash before releasing." >&2
    exit 1
fi

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" != "main" ]; then
    echo "Releases are cut from main; current branch is \"$branch\"." >&2
    exit 1
fi

git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    echo "Local main is not in sync with origin/main; push or pull first." >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1 \
        || git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
    echo "Tag ${tag} already exists; bump the version in CMakeLists.txt first." >&2
    exit 1
fi

# Confirm before the irreversible tag push. A non-interactive run (no stdin) reads EOF and aborts.
printf 'Release %s at %s? [y/N] ' "$tag" "$(git rev-parse --short HEAD)"
if ! read -r answer; then answer=""; fi
case "$answer" in
    y | Y | yes | Yes | YES) ;;
    *) echo "Aborted." >&2; exit 1 ;;
esac

echo "Tagging and pushing ${tag}..."
git tag -a "${tag}" -m "Release ${tag}"
git push origin "${tag}"

slug=$(git config --get remote.origin.url | sed -e 's#^.*github\.com[:/]##' -e 's#\.git$##')
echo "Pushed ${tag}. The release workflow takes over from here -- it gates on CI, builds the"
echo "binaries, publishes the image to GHCR, and creates the GitHub release:"
echo "  https://github.com/${slug}/actions/workflows/release.yml"
