#!/bin/sh
set -eu

# Fully automated release. From a clean main in sync with origin/main, this:
#   1. verifies CI is green on the release commit (gh),
#   2. prints the detected version and asks for confirmation,
#   3. tags v<version> (from CMakeLists.txt via version.sh) and pushes the tag,
#   4. creates the GitHub release (gh),
#   5. publishes the Docker images (docker_build.sh --push).
# The version in CMakeLists.txt is the single source of truth; the pushed tag is re-checked against
# it by the "Tag version check" workflow.

cd "$(dirname "$0")"

command -v gh >/dev/null 2>&1 || { echo "gh (GitHub CLI) is required; install it and run 'gh auth login'." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required to publish images." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated; run 'gh auth login'." >&2; exit 1; }

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

# 1. CI must be green on the exact commit being released. Every check run on the commit must have
# completed successfully (skipped/neutral count as non-blocking); anything still running blocks too.
sha=$(git rev-parse HEAD)
echo "Checking CI status for ${sha}..."
checks=$(gh api --paginate "repos/{owner}/{repo}/commits/${sha}/check-runs" \
    --jq '.check_runs[] | "\(.status)\t\(.conclusion)\t\(.name)"')
if [ -z "$checks" ]; then
    echo "No CI checks found for ${sha}; refusing to release." >&2
    exit 1
fi
not_passing=$(printf '%s\n' "$checks" | awk -F'\t' '$1 != "completed" || ($2 != "success" && $2 != "skipped" && $2 != "neutral")')
if [ -n "$not_passing" ]; then
    echo "CI has not passed for ${sha}:" >&2
    printf '%s\n' "$not_passing" | awk -F'\t' '{printf "  %s (%s/%s)\n", $3, $1, $2}' >&2
    exit 1
fi
echo "CI passed ($(printf '%s\n' "$checks" | wc -l | tr -d ' ') checks)."

# 2. Confirm the version before anything irreversible (tag push). A non-interactive run (no stdin)
# reads EOF and aborts.
printf 'Release %s at %s? [y/N] ' "$tag" "$(git rev-parse --short HEAD)"
if ! read -r answer; then answer=""; fi
case "$answer" in
    y | Y | yes | Yes | YES) ;;
    *) echo "Aborted." >&2; exit 1 ;;
esac

# 3. Tag and push.
echo "Tagging and pushing ${tag}..."
git tag -a "${tag}" -m "Release ${tag}"
git push origin "${tag}"

# 4. GitHub release, with notes generated from the commits since the previous tag.
echo "Creating GitHub release ${tag}..."
gh release create "${tag}" --title "${tag}" --generate-notes

# 5. Publish the images (tagged with the same version via version.sh).
echo "Publishing Docker images..."
./docker_build.sh --push

echo "Release ${tag} complete."
