#!/bin/sh
set -eu

version=$(sed -n 's/.*project([[:space:]]*reflector[[:space:]]*VERSION[[:space:]]*\([0-9.]*\).*/\1/p' CMakeLists.txt)
if [ -z "$version" ]; then
    echo "Cannot determine VERSION from CMakeLists.txt" >&2
    exit 1
fi

docker build -t "reflector:${version}" -t "reflector:latest" .

cat <<EOF

Built reflector:${version} (also tagged latest).

Run:
  docker run --rm \\
      --network host \\
      -v /path/to/your/config.toml:/etc/reflector/config.toml:ro \\
      reflector:${version}

--network host is recommended so the reflector sees the real source/target interfaces.

If you run with --cap-drop=ALL (or Kubernetes restricted PSS), also add:
  --cap-add NET_RAW --cap-add NET_BIND_SERVICE
EOF
