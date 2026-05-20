# CLAUDE.md

## Invariants

- Single-threaded main loop. No worker threads, no locks, no condition variables.
- Signal handlers run async → state they share with the main loop must be `volatile sig_atomic_t` or a lock-free `std::atomic`. Prefer `_r` glibc variants (`localtime_r`) over the non-reentrant ones.

## Code style

- Prefer RAII over manual cleanup.
- Pin Docker base images as `image:tag@sha256:digest` (don't drop the tag).

## Build

```sh
./cmake_gen.sh           # Debug, ASan + UBSan on
./cmake_gen.sh Release   # LTO on if supported
cmake --build build
```

## Tests

Default: run unit tests against a Debug build with ASan/UBSan on. Before trusting a result, confirm `grep REFLECTOR_SANITIZE build/CMakeCache.txt` shows `ON` — CMake caches the value at first configure and a stale `OFF` survives later reconfigures, silently disabling instrumentation.

```sh
ctest --test-dir build -L unit --output-on-failure
docker build --target test-debug .                    # docker test (Debug)
docker build --target test-release .                  # docker test (Release)
python3 e2e/run.py                                    # docker e2e
```

Docker / e2e via ctest is opt-in:

```sh
cmake -S . -B build -DREFLECTOR_ENABLE_DOCKER_TESTS=ON -DREFLECTOR_ENABLE_E2E_TESTS=ON
ctest --test-dir build -L docker          # all docker-dependent
ctest --test-dir build -L e2e             # e2e only
```
