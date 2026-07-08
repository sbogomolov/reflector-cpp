# CLAUDE.md

## Invariants

- Single-threaded main loop. No worker threads, no locks, no condition variables.
- Signal handlers run async → state they share with the main loop must be `volatile sig_atomic_t` or a lock-free `std::atomic`. Prefer `_r` glibc variants (`localtime_r`) over the non-reentrant ones.

## Code style

- Prefer RAII over manual cleanup.
- Anonymous namespaces at file scope only, above `namespace reflector` (with `using namespace reflector;` inside when needed) — never nested inside it.
- Pin Docker base images as `image:tag@sha256:digest` (don't drop the tag).
- `auto`/`auto&`/`auto*` for locals and loop vars where the initializer makes the type clear; CTAD for aggregates (`std::array parts{a, b}`). Explicit type only when it genuinely clarifies (non-obvious conversion, pinning an interface).
- Order struct members so padding lands at the end — place a trailing `bool` after a member with tail padding so it tucks in. A throwaway `static_assert(sizeof(X) == 0)` prints the actual size.
- Log level by failure, not blame: failure of an intended operation → `Error`, even if externally caused; deliberate skips (traffic not handled by design) → `Debug`. If Error volume becomes a problem, rate-limit — don't downgrade.

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
./docker_test.sh                                      # docker test (Debug, ASan/UBSan)
./docker_test.sh release                              # docker test (Release)
./docker_test.sh valgrind                             # docker test (unit binary under Valgrind memcheck)
python3 e2e/run.py                                    # docker e2e
python3 e2e/run.py --valgrind                         # docker e2e under Valgrind memcheck
```

Docker / e2e / valgrind via ctest is opt-in:

```sh
cmake -S . -B build -DREFLECTOR_ENABLE_DOCKER_TESTS=ON -DREFLECTOR_ENABLE_E2E_TESTS=ON -DREFLECTOR_ENABLE_VALGRIND_UNIT_TESTS=ON -DREFLECTOR_ENABLE_VALGRIND_E2E_TESTS=ON
ctest --test-dir build -L docker          # all docker-dependent
ctest --test-dir build -L e2e             # e2e only
ctest --test-dir build -L valgrind        # valgrind only (unit + e2e under memcheck)
```
