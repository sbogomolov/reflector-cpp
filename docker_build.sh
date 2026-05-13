#!/bin/sh
set -eu

default_platforms="linux/amd64,linux/arm64"
default_push_image="ghcr.io/sbogomolov/reflector"
image="reflector"
image_set=false
platforms="$default_platforms"
platforms_set=false
push=false

usage() {
    cat <<EOF
Usage:
  ./docker_build.sh [--platforms PLATFORM]
  ./docker_build.sh --push [--image IMAGE] [--platforms PLATFORMS]

Options:
  --push                  Publish an image manifest to the registry.
  --image IMAGE           Registry image name for --push.
                           Default: ${default_push_image}
  --platforms PLATFORMS   Comma-separated platforms.
                           Without --push: single platform only (Docker cannot
                           --load multi-arch images locally).
                           With --push: default ${default_platforms}.
  -h, --help              Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --push)
            push=true
            shift
            ;;
        --image)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "--image requires a value" >&2
                usage >&2
                exit 2
            fi
            image="$2"
            image_set=true
            shift 2
            ;;
        --image=*)
            image="${1#--image=}"
            if [ -z "$image" ]; then
                echo "--image requires a value" >&2
                usage >&2
                exit 2
            fi
            image_set=true
            shift
            ;;
        --platforms)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "--platforms requires a value" >&2
                usage >&2
                exit 2
            fi
            platforms="$2"
            platforms_set=true
            shift 2
            ;;
        --platforms=*)
            platforms="${1#--platforms=}"
            if [ -z "$platforms" ]; then
                echo "--platforms requires a value" >&2
                usage >&2
                exit 2
            fi
            platforms_set=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$push" = false ] && [ "$image_set" = true ]; then
    echo "--image is only valid with --push" >&2
    usage >&2
    exit 2
fi

if [ "$push" = false ] && [ "$platforms_set" = true ]; then
    case "$platforms" in
        *,*)
            echo "multi-platform requires --push (Docker cannot --load multi-arch images)" >&2
            exit 2
            ;;
    esac
fi

if [ "$push" = true ] && [ "$image_set" = false ]; then
    image="$default_push_image"
fi

version=$(sed -n 's/.*project([[:space:]]*reflector[[:space:]]*VERSION[[:space:]]*\([0-9.]*\).*/\1/p' CMakeLists.txt)
if [ -z "$version" ]; then
    echo "Cannot determine VERSION from CMakeLists.txt" >&2
    exit 1
fi

if [ "$push" = true ]; then
    docker buildx build \
        --platform "$platforms" \
        --push \
        -t "${image}:${version}" \
        -t "${image}:latest" \
        .

    printf '\nPublished %s:%s (also tagged latest).\n' "$image" "$version"
    printf 'Platforms: %s\n' "$platforms"
elif [ "$platforms_set" = true ]; then
    docker buildx build \
        --load \
        --platform "$platforms" \
        -t "${image}:${version}" \
        -t "${image}:latest" \
        .

    printf '\nBuilt %s:%s for %s (also tagged latest).\n' "$image" "$version" "$platforms"
else
    docker buildx build \
        --load \
        -t "${image}:${version}" \
        -t "${image}:latest" \
        .

    printf '\nBuilt %s:%s (also tagged latest).\n' "$image" "$version"
fi

cat <<EOF

Run:
  docker run --rm \\
      --network host \\
      -v /path/to/your/config.toml:/etc/reflector/config.toml:ro \\
      ${image}:${version}

--network host is recommended so the reflector sees the real source/target interfaces.

If you run with --cap-drop=ALL (or Kubernetes restricted PSS), also add:
  --cap-add NET_RAW --cap-add NET_BIND_SERVICE
EOF
