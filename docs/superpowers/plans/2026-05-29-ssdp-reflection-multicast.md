# SSDP Reflection (PR3, Step 1: Multicast) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SSDP (UPnP/DLNA) multicast reflection between two interfaces as a third network-level reflector alongside WoL and mDNS — relaying M-SEARCH source→target and NOTIFY advertisements target→source on 239.255.255.250 / ff02::c / ff05::c port 1900.

**Architecture:** Mirrors the completed mDNS reflector. A new `SsdpReflector` derives from the existing `Reflector` base and plugs into `Application`'s `ConfigureReflectors<R>` template with no wiring changes. The one structural divergence from mDNS: SSDP has a *set* of multicast groups per IPv6 family (ff02::c link-local + ff05::c site-local), so the reflector's per-family setup loops over `IpAddress::SsdpGroupsFor(family)`. Classification is by SSDP start-line token ("M-SEARCH " / "NOTIFY ") rather than a bit. Re-emit TTL is 2 (UDA 2.0 default), not mDNS's 255.

**Tech Stack:** C++23 (GCC 14 / AppleClang 16), CMake + Ninja, GoogleTest, Docker-backed e2e (Python). Single-threaded event loop; AF_PACKET (Linux) / BPF (macOS) capture.

**Spec:** `docs/superpowers/specs/2026-05-29-ssdp-reflection-design.md` (step 1 of the 3-step SSDP roadmap; unicast-response proxy and DIAL are steps 2–3, out of scope here).

**Methodology:** Per-commit — discuss/agree, wait for explicit "go", implement, then STOP and show the diff for review; commit only after explicit per-batch permission. Each data-path commit runs the full test gate (native `ctest -L unit` + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`) before review. Confirm `grep REFLECTOR_SANITIZE build/CMakeCache.txt` shows `ON` before trusting native results.

---

### Task 1: SSDP multicast group constants

**Files:**
- Modify: `src/reflector/ip_address.h` — add `#include <vector>` (alongside the existing `<span>`/`<string>` includes near line 10-11); add four `static` declarations after the `MdnsGroupFor` declaration (line 34).
- Modify: `src/reflector/ip_address.cpp` — add four definitions after `MdnsGroupFor` (line 62).
- Test: `tests/ip_address_test.cpp` — add tests after `MdnsGroupForSelectsFamilyAppropriateAddress` (line 85).

- [ ] **Step 1: Add the failing tests for the SSDP group constants**

  Insert into `tests/ip_address_test.cpp` immediately after the `MdnsGroupForSelectsFamilyAppropriateAddress` test (after line 85). The `<vector>` include is needed for `SsdpGroupsFor`'s return type; add it to the test's include block too (it sorts after `<sys/socket.h>`... actually alphabetically `<vector>` follows `<sys/socket.h>`, so append it after line 12).

  Add to the include block (after `#include <sys/socket.h>`):
  ```cpp
  #include <vector>
  ```

  Add the tests:
  ```cpp
  TEST(IpAddressTest, SsdpGroupV4ReturnsSsdpMulticastAddress) {
      const auto addr = IpAddress::SsdpGroupV4();

      EXPECT_TRUE(addr.IsV4());
      EXPECT_EQ(addr, IpAddress::FromV4Bytes(239, 255, 255, 250));
      EXPECT_EQ(addr.ToString(), "239.255.255.250");
  }

  TEST(IpAddressTest, SsdpGroupV6LinkLocalReturnsLinkScopedSsdpAddress) {
      const auto addr = IpAddress::SsdpGroupV6LinkLocal();

      EXPECT_TRUE(addr.IsV6());
      EXPECT_EQ(addr, IpAddress::FromString("ff02::c"));
      EXPECT_EQ(addr.ToString(), "ff02::c");
      EXPECT_EQ(std::to_integer<uint8_t>(addr.Bytes()[1]), 0x02);   // link-local scope
      EXPECT_EQ(std::to_integer<uint8_t>(addr.Bytes()[15]), 0x0c);  // SSDP group id
  }

  TEST(IpAddressTest, SsdpGroupV6SiteLocalReturnsSiteScopedSsdpAddress) {
      const auto addr = IpAddress::SsdpGroupV6SiteLocal();

      EXPECT_TRUE(addr.IsV6());
      EXPECT_EQ(addr, IpAddress::FromString("ff05::c"));
      EXPECT_EQ(addr.ToString(), "ff05::c");
      EXPECT_EQ(std::to_integer<uint8_t>(addr.Bytes()[1]), 0x05);   // site-local scope
      EXPECT_EQ(std::to_integer<uint8_t>(addr.Bytes()[15]), 0x0c);  // SSDP group id
  }

  TEST(IpAddressTest, SsdpGroupsForReturnsSingleV4Group) {
      const std::vector<IpAddress> groups = IpAddress::SsdpGroupsFor(IpAddress::Family::V4);

      ASSERT_EQ(groups.size(), 1u);
      EXPECT_EQ(groups[0], IpAddress::SsdpGroupV4());
  }

  TEST(IpAddressTest, SsdpGroupsForReturnsLinkThenSiteLocalV6Groups) {
      const std::vector<IpAddress> groups = IpAddress::SsdpGroupsFor(IpAddress::Family::V6);

      ASSERT_EQ(groups.size(), 2u);
      EXPECT_EQ(groups[0], IpAddress::SsdpGroupV6LinkLocal());   // link-local first
      EXPECT_EQ(groups[1], IpAddress::SsdpGroupV6SiteLocal());   // then site-local
  }
  ```

- [ ] **Step 2: Run the tests and see them fail to compile**

  ```sh
  cmake --build build && ctest --test-dir build -L unit -R IpAddressTest --output-on-failure
  ```

  Expected: the build fails because `IpAddress` has no member `SsdpGroupV4`, `SsdpGroupV6LinkLocal`, `SsdpGroupV6SiteLocal`, or `SsdpGroupsFor` (compiler errors such as `error: no member named 'SsdpGroupV4' in 'reflector::IpAddress'`). No test binary is produced, so the run reports a build failure rather than a test pass.

- [ ] **Step 3: Declare the SSDP group methods in the header**

  In `src/reflector/ip_address.h`, add the `<vector>` include. The standard headers are grouped first and the `<sys/socket.h>` path header sits last (line 12), so insert `<vector>` between `<string>` (line 11) and `<sys/socket.h>` to preserve that convention:
  ```cpp
  #include <string>
  #include <vector>
  #include <sys/socket.h>
  ```

  Then add the declarations immediately after the `MdnsGroupFor` declaration (after line 34), before `LoopbackV4`:
  ```cpp
      [[nodiscard]] static IpAddress SsdpGroupV4() noexcept;           // 239.255.255.250
      [[nodiscard]] static IpAddress SsdpGroupV6LinkLocal() noexcept;  // ff02::c
      [[nodiscard]] static IpAddress SsdpGroupV6SiteLocal() noexcept;  // ff05::c
      // The SSDP multicast groups for the family, in the order they should be joined: the single
      // IPv4 group, or the IPv6 link-local then site-local groups, all served on UDP 1900.
      [[nodiscard]] static std::vector<IpAddress> SsdpGroupsFor(Family family);
  ```

- [ ] **Step 4: Define the SSDP group methods**

  In `src/reflector/ip_address.cpp`, add the definitions immediately after `MdnsGroupFor` (after line 62), before `LoopbackV4`:
  ```cpp
  IpAddress IpAddress::SsdpGroupV4() noexcept {
      return FromV4Bytes(239, 255, 255, 250);
  }

  IpAddress IpAddress::SsdpGroupV6LinkLocal() noexcept {
      ByteArray bytes{};
      bytes[0] = std::byte{0xff};
      bytes[1] = std::byte{0x02};
      bytes[15] = std::byte{0x0c};
      return IpAddress{Family::V6, bytes};
  }

  IpAddress IpAddress::SsdpGroupV6SiteLocal() noexcept {
      ByteArray bytes{};
      bytes[0] = std::byte{0xff};
      bytes[1] = std::byte{0x05};
      bytes[15] = std::byte{0x0c};
      return IpAddress{Family::V6, bytes};
  }

  std::vector<IpAddress> IpAddress::SsdpGroupsFor(Family family) {
      if (family == Family::V4) {
          return {SsdpGroupV4()};
      }
      return {SsdpGroupV6LinkLocal(), SsdpGroupV6SiteLocal()};
  }
  ```

  `<vector>` is already visible through `ip_address.h`, so no new include is needed in the `.cpp`.

- [ ] **Step 5: Run the tests and see them pass**

  ```sh
  cmake --build build && ctest --test-dir build -L unit -R IpAddressTest --output-on-failure
  ```

  Expected: the build succeeds and every `IpAddressTest` case passes, including the five new `Ssdp*` tests, e.g. `[  PASSED  ]` for `SsdpGroupV4ReturnsSsdpMulticastAddress`, `SsdpGroupV6LinkLocalReturnsLinkScopedSsdpAddress`, `SsdpGroupV6SiteLocalReturnsSiteScopedSsdpAddress`, `SsdpGroupsForReturnsSingleV4Group`, and `SsdpGroupsForReturnsLinkThenSiteLocalV6Groups`. The final line reads `100% tests passed`.

- [ ] **Step 6: Confirm sanitizers, run the full test gate, then stop for review**

  First confirm instrumentation is on (CMake caches the first-configure value, so a stale `OFF` silently disables it):
  ```sh
  grep REFLECTOR_SANITIZE build/CMakeCache.txt
  ```
  Expected: `REFLECTOR_SANITIZE:BOOL=ON`. If it shows `OFF`, re-run `./cmake_gen.sh` before proceeding.

  Then run the full test gate:
  ```sh
  ctest --test-dir build -L unit --output-on-failure
  ./docker_test.sh
  ./docker_test.sh release
  python3 e2e/run.py
  ```
  Expected: all four green (native unit suite `100% tests passed`; both docker runs pass; e2e exits 0).

  Then STOP and show the diff for review (`git diff src/reflector/ip_address.h src/reflector/ip_address.cpp tests/ip_address_test.cpp`); commit only after explicit per-batch permission. Do not run `git commit` autonomously.

### Task 2: SSDP message classifier

**Files:**
- Create: `src/reflector/ssdp_message.h`
- Create: `src/reflector/ssdp_message.cpp`
- Modify: `src/reflector/CMakeLists.txt` — add `ssdp_message.cpp` to the `add_library(reflector STATIC ...)` list (after line 12, `mdns_message.cpp`)
- Modify: `tests/CMakeLists.txt` — add `ssdp_message_test.cpp` to the `add_executable(reflector_test ...)` list (after line 14, `mdns_message_test.cpp`)
- Test: `tests/ssdp_message_test.cpp`

This mirrors `mdns_message` exactly: a single free function `ClassifySsdpMessage` returning `std::optional<SsdpMessageKind>`, `[[nodiscard]]` + `noexcept`, no parsing beyond the leading token, header-only declaration with the same include set. The only structural difference from mDNS is that classification keys on a leading ASCII request-line token (SSDP is HTTPU/text) instead of a binary header bit.

---

- [ ] **Step 1: Write the failing test `tests/ssdp_message_test.cpp`**

  Mirror `tests/mdns_message_test.cpp`: project include first, then `<gtest/gtest.h>`, then sorted system includes, `using namespace reflector;`, an anonymous-namespace payload helper, then the cases. The helper builds a `std::span<const std::byte>` over a string literal's bytes (excluding the trailing NUL).

  ```cpp
  #include "reflector/ssdp_message.h"

  #include <gtest/gtest.h>

  #include <cstddef>
  #include <optional>
  #include <span>
  #include <string_view>

  using namespace reflector;

  namespace {

  // A span over the bytes of an ASCII payload, excluding the literal's trailing NUL. The classifier
  // reads only the leading request-line token, but the helper carries whole multi-line messages so
  // the realistic-payload cases exercise it with true SSDP traffic.
  std::span<const std::byte> Bytes(std::string_view text) {
      return std::as_bytes(std::span<const char>{text.data(), text.size()});
  }

  } // namespace

  TEST(SsdpMessageTest, ClassifiesMSearchAsSearch) {
      EXPECT_EQ(ClassifySsdpMessage(Bytes("M-SEARCH ")), SsdpMessageKind::Search);
  }

  TEST(SsdpMessageTest, ClassifiesNotifyAsAdvertisement) {
      EXPECT_EQ(ClassifySsdpMessage(Bytes("NOTIFY ")), SsdpMessageKind::Advertisement);
  }

  TEST(SsdpMessageTest, ClassifiesRealisticMSearchAsSearch) {
      EXPECT_EQ(ClassifySsdpMessage(Bytes(
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 2\r\n"
                    "ST: ssdp:all\r\n"
                    "\r\n")),
                SsdpMessageKind::Search);
  }

  TEST(SsdpMessageTest, ClassifiesRealisticNotifyAsAdvertisement) {
      EXPECT_EQ(ClassifySsdpMessage(Bytes(
                    "NOTIFY * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    "LOCATION: http://192.0.2.1:80/desc.xml\r\n"
                    "NT: upnp:rootdevice\r\n"
                    "NTS: ssdp:alive\r\n"
                    "USN: uuid:device-uuid::upnp:rootdevice\r\n"
                    "\r\n")),
                SsdpMessageKind::Advertisement);
  }

  TEST(SsdpMessageTest, RejectsHttpResponse) {
      EXPECT_EQ(ClassifySsdpMessage(Bytes("HTTP/1.1 200 OK\r\n")), std::nullopt);
  }

  TEST(SsdpMessageTest, RejectsTooShortPayload) {
      // Shorter than the "NOTIFY " token (the shortest accepted prefix), so no token can match.
      EXPECT_EQ(ClassifySsdpMessage(Bytes("M-SEAR")), std::nullopt);
      EXPECT_EQ(ClassifySsdpMessage(std::span<const std::byte>{}), std::nullopt);
  }

  TEST(SsdpMessageTest, RejectsLowercaseToken) {
      // Classification is case-sensitive: the verbs are uppercase on the wire (RFC-style HTTPU).
      EXPECT_EQ(ClassifySsdpMessage(Bytes("m-search ")), std::nullopt);
      EXPECT_EQ(ClassifySsdpMessage(Bytes("notify ")), std::nullopt);
  }

  TEST(SsdpMessageTest, RejectsPartialOrUnseparatedToken) {
      // The verb must be followed by its space separator; a bare or run-on token is not a match.
      EXPECT_EQ(ClassifySsdpMessage(Bytes("M-SEARCH")), std::nullopt);
      EXPECT_EQ(ClassifySsdpMessage(Bytes("NOTIFYING ")), std::nullopt);
      EXPECT_EQ(ClassifySsdpMessage(Bytes("junk")), std::nullopt);
  }
  ```

- [ ] **Step 2: Wire the test into CMake so it compiles (and fails to link)**

  Add the test source after the `mdns_message_test.cpp` line in `tests/CMakeLists.txt` (current line 14):

  ```cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/mdns_message_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/mdns_reflector_test.cpp
  ```

- [ ] **Step 3: Run the build and see the test fail (header missing)**

  ```sh
  cmake --build build
  ```

  Expected: compilation fails because `reflector/ssdp_message.h` does not exist:

  ```
  fatal error: 'reflector/ssdp_message.h' file not found
  #include "reflector/ssdp_message.h"
           ^~~~~~~~~~~~~~~~~~~~~~~~~~~
  ```

- [ ] **Step 4: Create the header `src/reflector/ssdp_message.h`**

  Mirror `mdns_message.h` byte-for-byte in structure: same include set, same `namespace reflector`, an `enum class ... : uint8_t`, then the single `[[nodiscard]] ... noexcept` free function. The doc comment carries the WHY (the two-way split is the reflector's directional gate, just as in mDNS).

  ```cpp
  #pragma once

  #include <cstddef>
  #include <cstdint>
  #include <optional>
  #include <span>

  namespace reflector {

  // An SSDP message (HTTPU over UDP, UPnP Device Architecture §1) is either an M-SEARCH discovery
  // request or a NOTIFY advertisement, told apart by the leading request-line method token. This
  // two-way split is exactly the reflector's directional gate: searches are relayed source->target,
  // advertisements target->source.
  enum class SsdpMessageKind : uint8_t {
      Search,
      Advertisement,
  };

  // Classifies an SSDP message by its leading ASCII method token, case-sensitive: a payload starting
  // with "M-SEARCH " is a Search, one starting with "NOTIFY " is an Advertisement. Anything else —
  // an "HTTP/..." search response, a too-short payload, or junk — yields nullopt. Reads only the
  // leading token; no header parsing.
  [[nodiscard]] std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept;

  } // namespace reflector
  ```

- [ ] **Step 5: Create the implementation `src/reflector/ssdp_message.cpp`**

  Mirror `mdns_message.cpp`: own header first, then system include, anonymous namespace for the constants/helper, then the function. The token-prefix check compares the payload's leading bytes against an ASCII literal without allocating or copying.

  ```cpp
  #include "ssdp_message.h"

  #include <cstddef>
  #include <span>
  #include <string_view>

  namespace reflector {

  namespace {

  // SSDP method tokens including their trailing space separator, so a prefix match cannot accept a
  // run-on verb like "NOTIFYING " (UPnP Device Architecture §1.1, §1.3 — HTTPU request lines).
  constexpr std::string_view SEARCH_TOKEN = "M-SEARCH ";
  constexpr std::string_view NOTIFY_TOKEN = "NOTIFY ";

  bool StartsWith(std::span<const std::byte> payload, std::string_view token) noexcept {
      if (payload.size() < token.size()) {
          return false;
      }
      for (size_t i = 0; i < token.size(); ++i) {
          if (payload[i] != std::byte{static_cast<unsigned char>(token[i])}) {
              return false;
          }
      }
      return true;
  }

  } // namespace

  std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept {
      if (StartsWith(payload, SEARCH_TOKEN)) {
          return SsdpMessageKind::Search;
      }
      if (StartsWith(payload, NOTIFY_TOKEN)) {
          return SsdpMessageKind::Advertisement;
      }
      return std::nullopt;
  }

  } // namespace reflector
  ```

- [ ] **Step 6: Wire the implementation into the library**

  Add the source after the `mdns_message.cpp` line in `src/reflector/CMakeLists.txt` (current line 12):

  ```cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/mdns_message.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/mdns_reflector.cpp
  ```

- [ ] **Step 7: Rebuild and run the SSDP message tests; see them pass**

  ```sh
  cmake --build build
  ctest --test-dir build -L unit -R SsdpMessageTest --output-on-failure
  ```

  Expected: all eight cases pass:

  ```
  100% tests passed, 0 tests failed out of 8
  ```

  (Each case is discovered with the `unit.` prefix per `tests/CMakeLists.txt`, e.g. `unit.SsdpMessageTest.ClassifiesMSearchAsSearch`.)

- [ ] **Step 8: Gate, review, and commit**

  Confirm the build is still instrumented before trusting the result:

  ```sh
  grep REFLECTOR_SANITIZE build/CMakeCache.txt   # expect ...:BOOL=ON
  ```

  Then run the full test gate:

  ```sh
  ctest --test-dir build -L unit --output-on-failure
  ./docker_test.sh
  ./docker_test.sh release
  python3 e2e/run.py
  ```

  After the gate is green, STOP and show the diff for review (`git diff` plus the new untracked files via `git status` / `git add -N` then `git diff`). Commit only after explicit per-batch permission — do not commit autonomously.

### Task 3: Config [[ssdp]] section

**Files:**
- Modify: `src/reflector/config.h` — add `SsdpConfig` struct after `MdnsConfig` (after line 75); add `SsdpConfigs()` accessor (after line 82); add `ssdp_configs_` member (after line 95); update `ReflectorCount()` (lines 90-92); add `std::formatter<SsdpConfig>` after the `MdnsConfig` formatter (after line 188); add `ssdp` loop to `std::formatter<Config>` (after line 226).
- Modify: `src/reflector/config.cpp` — add `ReadSsdpConfig`/`ReadSsdpConfigs` after `ReadMdnsConfigs` (after line 291); add `SsdpConfig::Verify()` after `MdnsConfig::Verify()` (after line 340); wire the `ssdp` section into `Config::FromString` dispatch (after line 392).
- Test: `tests/config_test.cpp` — add `// --- SSDP ---` cases at end of file (after line 1068).

---

- [ ] **Step 1: Write the failing tests for `[[ssdp]]` parsing and dedup**

  Append to `tests/config_test.cpp` (after line 1068, the end of the mDNS block). These mirror the mDNS cases exactly: minimal parse, mac+address_family parse, wol+ssdp together, ssdp-only validity, missing source_if/target_if, same interfaces, ports rejected, unknown option, invalid mac, invalid address_family, duplicate name, duplicate rule, and disjoint-family acceptance.

  ```cpp
  // --- SSDP ---

  TEST(ConfigTest, ParsesMinimalSsdpConfig) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  )";

      const auto config = Config::FromString(toml);
      ASSERT_TRUE(config.has_value()) << config.error().Message();
      ASSERT_EQ(config->SsdpConfigs().size(), 1);

      const auto& ssdp = config->SsdpConfigs().front();
      EXPECT_EQ(ssdp.name, "bridge");
      EXPECT_FALSE(ssdp.mac.has_value());
      EXPECT_EQ(ssdp.source_if, "lan");
      EXPECT_EQ(ssdp.target_if, "iot");
      EXPECT_EQ(ssdp.address_family, AddressFamily::Default);
  }

  TEST(ConfigTest, ParsesSsdpWithMacAndAddressFamily) {
      std::string toml = R"(
  [[ssdp]]
  name = "tv"
  mac = "00:11:22:33:44:55"
  source_if = "lan"
  target_if = "iot"
  address_family = "dual"
  )";

      const auto config = Config::FromString(toml);
      ASSERT_TRUE(config.has_value()) << config.error().Message();
      ASSERT_EQ(config->SsdpConfigs().size(), 1);

      const auto& ssdp = config->SsdpConfigs().front();
      ASSERT_TRUE(ssdp.mac.has_value());
      EXPECT_EQ(*ssdp.mac, *MacAddress::FromString("00:11:22:33:44:55"));
      EXPECT_EQ(ssdp.address_family, AddressFamily::Dual);
  }

  TEST(ConfigTest, ParsesWolAndSsdpTogether) {
      std::string toml = R"(
  [[wol]]
  name = "wake"
  source_if = "eth0"
  target_if = "eth1"

  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  )";

      const auto config = Config::FromString(toml);
      ASSERT_TRUE(config.has_value()) << config.error().Message();
      EXPECT_EQ(config->WolConfigs().size(), 1);
      EXPECT_EQ(config->SsdpConfigs().size(), 1);
  }

  TEST(ConfigTest, SsdpOnlyConfigIsValid) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  )";

      const auto config = Config::FromString(toml);
      ASSERT_TRUE(config.has_value()) << config.error().Message();
      EXPECT_TRUE(config->WolConfigs().empty());
      EXPECT_EQ(config->SsdpConfigs().size(), 1);
  }

  TEST(ConfigTest, RejectsSsdpMissingSourceIf) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  target_if = "iot"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpMissingTargetIf) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpSameInterfaces) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "lan"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpPortsOption) {
      // SSDP uses the fixed port 1900; ports is not a valid ssdp option.
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  ports = [1900]
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsUnknownSsdpOption) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  extra = "x"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpInvalidMac) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  mac = "not-a-mac"
  source_if = "lan"
  target_if = "iot"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpInvalidAddressFamily) {
      std::string toml = R"(
  [[ssdp]]
  name = "bridge"
  source_if = "lan"
  target_if = "iot"
  address_family = "ipx"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpDuplicateName) {
      std::string toml = R"(
  [[ssdp]]
  name = "dup"
  source_if = "lan"
  target_if = "iot"

  [[ssdp]]
  name = "dup"
  source_if = "lan2"
  target_if = "iot2"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  TEST(ConfigTest, RejectsSsdpDuplicateRule) {
      // Same source_if/target_if, both unfiltered (any MAC) with overlapping families.
      std::string toml = R"(
  [[ssdp]]
  name = "a"
  source_if = "lan"
  target_if = "iot"

  [[ssdp]]
  name = "b"
  source_if = "lan"
  target_if = "iot"
  )";
      EXPECT_FALSE(Config::FromString(toml).has_value());
  }

  // An ipv4-only and an ipv6-only rule never handle the same packet, so an otherwise
  // identical pair is not a duplicate.
  TEST(ConfigTest, AcceptsSsdpIdenticalRuleWithDisjointAddressFamilies) {
      std::string toml = R"(
  [[ssdp]]
  name = "a"
  source_if = "lan"
  target_if = "iot"
  address_family = "ipv4"

  [[ssdp]]
  name = "b"
  source_if = "lan"
  target_if = "iot"
  address_family = "ipv6"
  )";

      const auto config = Config::FromString(toml);
      ASSERT_TRUE(config.has_value()) << config.error().Message();
      EXPECT_EQ(config->SsdpConfigs().size(), 2);
  }
  ```

- [ ] **Step 2: Run the tests and watch them fail to compile**

  ```sh
  ctest --test-dir build -L unit --output-on-failure
  ```

  Expected: the build fails. The compiler reports that `Config` has no member `SsdpConfigs`, and `SsdpConfig` is undeclared — e.g.

  ```
  error: no member named 'SsdpConfigs' in 'reflector::Config'
  ```

- [ ] **Step 3: Add the `SsdpConfig` struct in `config.h`**

  Insert immediately after the closing `};` of `MdnsConfig` (after line 75, before `class Config`). It is identical in shape to `MdnsConfig` (no `ports`), with an SSDP-specific doc comment.

  ```cpp
  // An SSDP reflector entry: reflects Simple Service Discovery Protocol multicast between
  // source_if and target_if on UDP 1900. M-SEARCH requests flow source->target and NOTIFY
  // advertisements target->source; `mac`, when set, restricts the target->source direction to
  // frames whose L2 source MAC matches it (advertise only that device).
  struct SsdpConfig {
      std::string name;
      std::optional<MacAddress> mac;
      std::string source_if;
      std::string target_if;
      AddressFamily address_family = AddressFamily::Default;

      [[nodiscard]] constexpr bool UsesIPv4() const noexcept { return reflector::UsesIPv4(address_family); }
      [[nodiscard]] constexpr bool UsesIPv6() const noexcept { return reflector::UsesIPv6(address_family); }
      [[nodiscard]] constexpr bool RequiresIPv4() const noexcept { return reflector::RequiresIPv4(address_family); }
      [[nodiscard]] constexpr bool RequiresIPv6() const noexcept { return reflector::RequiresIPv6(address_family); }

      [[nodiscard]] std::optional<Error> Verify() const;
  };
  ```

- [ ] **Step 4: Add the accessor, member, and `ReflectorCount()` update in `config.h`**

  Add the accessor after `MdnsConfigs()` (line 82):

  ```cpp
      [[nodiscard]] const std::vector<SsdpConfig>& SsdpConfigs() const noexcept { return ssdp_configs_; }
  ```

  Replace the `ReflectorCount()` body (lines 90-92):

  ```cpp
      [[nodiscard]] size_t ReflectorCount() const noexcept {
          return wol_configs_.size() + mdns_configs_.size() + ssdp_configs_.size();
      }
  ```

  Add the member after `mdns_configs_` (line 95):

  ```cpp
      std::vector<SsdpConfig> ssdp_configs_;
  ```

- [ ] **Step 5: Add the `std::formatter<SsdpConfig>` in `config.h`**

  Insert after the `std::formatter<reflector::MdnsConfig, char>` specialization (after line 188, before `std::formatter<reflector::Config, char>`). This mirrors the `MdnsConfig` formatter exactly (no `ports`).

  ```cpp
  template <>
  struct std::formatter<reflector::SsdpConfig, char>
  {
      template <class ParseContext>
      constexpr ParseContext::iterator parse(ParseContext& ctx) {
          auto it = ctx.begin();
          if (it != ctx.end() && *it != '}') {
              throw std::format_error("Invalid format args for SsdpConfig");
          }

          return it;
      }

      template <typename FmtContext>
      FmtContext::iterator format(const reflector::SsdpConfig& c, FmtContext& ctx) const {
          std::format_to(ctx.out(), "{{name: \"{}\", mac: ", c.name);
          if (c.mac.has_value()) {
              std::format_to(ctx.out(), "\"{}\"", *c.mac);
          } else {
              std::format_to(ctx.out(), "any");
          }
          return std::format_to(ctx.out(), ", source_if: \"{}\", target_if: \"{}\", address_family: {}}}",
              c.source_if, c.target_if, c.address_family);
      }
  };
  ```

- [ ] **Step 6: Add the `ssdp` loop to `std::formatter<Config>` in `config.h`**

  In `std::formatter<reflector::Config, char>::format`, after the `mdns` loop's trailing `}` (after line 226) and before the final `return std::format_to(ctx.out(), "]}}");` (line 228), insert the `ssdp` section. Then update that final return to close the `mdns` array first.

  Replace lines 217-228 (from `std::format_to(ctx.out(), "], mdns: [");` through the final `return`) with:

  ```cpp
          std::format_to(ctx.out(), "], mdns: [");
          first = true;
          for (const auto& mdns_config : c.MdnsConfigs()) {
              if (first) {
                  first = false;
              } else {
                  std::format_to(ctx.out(), ", ");
              }
              std::format_to(ctx.out(), "{}", mdns_config);
          }

          std::format_to(ctx.out(), "], ssdp: [");
          first = true;
          for (const auto& ssdp_config : c.SsdpConfigs()) {
              if (first) {
                  first = false;
              } else {
                  std::format_to(ctx.out(), ", ");
              }
              std::format_to(ctx.out(), "{}", ssdp_config);
          }

          return std::format_to(ctx.out(), "]}}");
  ```

- [ ] **Step 7: Add `ReadSsdpConfig` / `ReadSsdpConfigs` in `config.cpp`**

  Insert in the anonymous namespace immediately after `ReadMdnsConfigs` (after line 291, before the `} // namespace` on line 293). This is the parallel loop to `ReadMdnsConfig`/`ReadMdnsConfigs`, sharing `ReadStringField`, `AddressFamilyFromString`, `MacSelectionsOverlap`, and `AddressFamiliesOverlap`. No `ports` field; the dedup is identical to mdns.

  ```cpp
  std::expected<SsdpConfig, Error> ReadSsdpConfig(const toml::table& entry_table) {
      SsdpConfig ssdp_config{};
      for (const auto& [field_key, field_node] : entry_table) {
          const auto field_name = ToStringView(field_key);
          if (field_name == "name") {
              auto field_value = ReadStringField(field_node, "ssdp", field_name);
              if (!field_value.has_value()) {
                  return std::unexpected(std::move(field_value).error());
              }
              ssdp_config.name = *field_value;
          } else if (field_name == "mac") {
              auto field_value = ReadStringField(field_node, "ssdp", field_name);
              if (!field_value.has_value()) {
                  return std::unexpected(std::move(field_value).error());
              }
              auto mac = MacAddress::FromString(*field_value);
              if (!mac.has_value()) {
                  return std::unexpected(Error{"ssdp mac is not a valid MAC address: \"{}\": {}", *field_value, mac.error()});
              }
              ssdp_config.mac = *mac;
          } else if (field_name == "source_if") {
              auto field_value = ReadStringField(field_node, "ssdp", field_name);
              if (!field_value.has_value()) {
                  return std::unexpected(std::move(field_value).error());
              }
              ssdp_config.source_if = *field_value;
          } else if (field_name == "target_if") {
              auto field_value = ReadStringField(field_node, "ssdp", field_name);
              if (!field_value.has_value()) {
                  return std::unexpected(std::move(field_value).error());
              }
              ssdp_config.target_if = *field_value;
          } else if (field_name == "address_family") {
              const auto field_value = field_node.value<std::string_view>();
              if (!field_value.has_value()) {
                  return std::unexpected(Error{"ssdp address_family must be a string"});
              }
              auto address_family = AddressFamilyFromString("ssdp", *field_value);
              if (!address_family.has_value()) {
                  return std::unexpected(std::move(address_family).error());
              }
              ssdp_config.address_family = *address_family;
          } else {
              return std::unexpected(Error{"unexpected ssdp option: {}", field_name});
          }
      }
      return ssdp_config;
  }

  std::expected<std::vector<SsdpConfig>, Error> ReadSsdpConfigs(const toml::node& ssdp_node) {
      const auto* ssdp_array = ssdp_node.as_array();
      if (!ssdp_array) {
          return std::unexpected(Error{"ssdp node is not an array"});
      }

      std::vector<SsdpConfig> ssdp_configs;
      ssdp_configs.reserve(ssdp_array->size());
      for (const auto& entry_node : *ssdp_array) {
          const auto* entry_table = entry_node.as_table();
          if (!entry_table) {
              return std::unexpected(Error{"ssdp entry is not a table"});
          }

          auto ssdp_config = ReadSsdpConfig(*entry_table);
          if (!ssdp_config.has_value()) {
              return std::unexpected(std::move(ssdp_config).error());
          }
          if (auto error = ssdp_config->Verify()) {
              return std::unexpected(*std::move(error));
          }
          for (const auto& existing : ssdp_configs) {
              if (existing.name == ssdp_config->name) {
                  return std::unexpected(Error{"duplicate ssdp name: \"{}\"", ssdp_config->name});
              }
              if (MacSelectionsOverlap(existing.mac, ssdp_config->mac)
                      && existing.source_if == ssdp_config->source_if
                      && existing.target_if == ssdp_config->target_if
                      && AddressFamiliesOverlap(existing.address_family, ssdp_config->address_family)) {
                  return std::unexpected(Error{
                      "duplicate ssdp rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                      existing.name, ssdp_config->name});
              }
          }
          ssdp_configs.push_back(std::move(*ssdp_config));
      }

      return ssdp_configs;
  }
  ```

- [ ] **Step 8: Add `SsdpConfig::Verify()` in `config.cpp`**

  Insert in `namespace reflector` immediately after `MdnsConfig::Verify()` (after line 340, before `Config::FromFile`). Identical to `MdnsConfig::Verify()` with `ssdp` in the messages.

  ```cpp
  std::optional<Error> SsdpConfig::Verify() const {
      if (name.empty()) {
          return Error{"ssdp name is not configured"};
      }
      if (source_if.empty()) {
          return Error{"ssdp source_if is not configured"};
      }
      if (target_if.empty()) {
          return Error{"ssdp target_if is not configured"};
      }
      if (source_if == target_if) {
          return Error{"ssdp source_if and target_if must be different: \"{}\"", source_if};
      }
      return std::nullopt;
  }
  ```

- [ ] **Step 9: Wire the `ssdp` section into `Config::FromString` dispatch**

  In `Config::FromString`, add the `ssdp` branch to the section dispatch chain after the `mdns` branch (after line 392, the line `config.mdns_configs_ = std::move(*mdns_configs);` and its closing `}`), before the `log_level` branch (`} else if (section_name == "log_level") {`).

  Replace the existing `mdns` branch closing / `log_level` opening:

  ```cpp
          } else if (section_name == "mdns") {
  ```
  ... through ...
  ```cpp
              config.mdns_configs_ = std::move(*mdns_configs);
          } else if (section_name == "log_level") {
  ```

  with:

  ```cpp
          } else if (section_name == "mdns") {
              auto mdns_configs = ReadMdnsConfigs(value);
              if (!mdns_configs.has_value()) {
                  return std::unexpected(Error{"cannot read mdns configuration: {}", mdns_configs.error().Message()});
              }
              config.mdns_configs_ = std::move(*mdns_configs);
          } else if (section_name == "ssdp") {
              auto ssdp_configs = ReadSsdpConfigs(value);
              if (!ssdp_configs.has_value()) {
                  return std::unexpected(Error{"cannot read ssdp configuration: {}", ssdp_configs.error().Message()});
              }
              config.ssdp_configs_ = std::move(*ssdp_configs);
          } else if (section_name == "log_level") {
  ```

  The `ReflectorCount() == 0` check (lines 408-410) already covers `ssdp_configs_` via the `ReflectorCount()` update from Step 4 — no further change there.

- [ ] **Step 10: Rebuild and watch the SSDP tests pass**

  ```sh
  ctest --test-dir build -L unit --output-on-failure
  ```

  Expected: all tests pass, including the new SSDP cases. Confirm the relevant lines in the output, e.g.

  ```
  [       OK ] ConfigTest.ParsesMinimalSsdpConfig
  [       OK ] ConfigTest.ParsesSsdpWithMacAndAddressFamily
  [       OK ] ConfigTest.RejectsSsdpDuplicateRule
  [       OK ] ConfigTest.AcceptsSsdpIdenticalRuleWithDisjointAddressFamilies
  ...
  100% tests passed
  ```

  Before trusting the result, confirm the build is instrumented:

  ```sh
  grep REFLECTOR_SANITIZE build/CMakeCache.txt
  ```

  Expected: `REFLECTOR_SANITIZE:BOOL=ON`.

- [ ] **Step 11: Add the `TestConfigBuilder::Add(SsdpConfig)` overload**

  Task 5 (Application) builds SSDP configs through `TestConfigBuilder` in `tests/test_helpers.h`, which currently has only `Add(WolConfig)` and `Add(MdnsConfig)` (lines 44–50). Add the SSDP overload — it pushes into the `ssdp_configs_` member added in Step 4, and `TestConfigBuilder` is already a `friend class` of `Config`. Insert immediately after the `Add(MdnsConfig)` overload (after line 50):

  ```cpp
      TestConfigBuilder& Add(SsdpConfig ssdp) {
          config_.ssdp_configs_.push_back(std::move(ssdp));
          return *this;
      }
  ```

  No new include is needed: `test_helpers.h` already includes `reflector/config.h`, which now declares `SsdpConfig`. Build the tests to confirm it compiles:

  ```sh
  cmake --build build
  ```

  Expected: the test binary builds clean (this overload has no test of its own; Task 5 exercises it).

- [ ] **Step 12: Gate, review, and commit on permission**

  Run the full test gate (`ctest -L unit` native + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`), then STOP and show the diff for review; commit only after explicit per-batch permission. Do not run `git commit` as an autonomous step.

### Task 4: SsdpReflector

**Files:**
- Create: `src/reflector/ssdp_reflector.h`
- Create: `src/reflector/ssdp_reflector.cpp`
- Modify: `src/reflector/CMakeLists.txt` (the `add_library(reflector STATIC ...)` source list, lines 1-17 — add `ssdp_reflector.cpp` alongside the existing `wol_reflector.cpp` entry)
- Modify: `tests/CMakeLists.txt` (the `add_executable(reflector_test ...)` source list, lines 1-21 — add `ssdp_reflector_test.cpp` alongside `wol_reflector_test.cpp`)
- Test: `tests/ssdp_reflector_test.cpp`

This task depends on `ssdp_message` (`ClassifySsdpMessage`, `SsdpMessageKind`), `SsdpConfig` (in `config.h`), and the `IpAddress::Ssdp*` group methods landed in their own earlier tasks. It mirrors `MdnsReflector` exactly, with one structural difference: the per-family setup loops over every group in `IpAddress::SsdpGroupsFor(family)` (V4 has one group, V6 has two: `ff02::c` and `ff05::c`), joining and registering both directions per group. Re-emit TTL is `2`, not mDNS's `255`.

- [ ] **Step K: Write the failing test file `tests/ssdp_reflector_test.cpp`**

  This is the full test; it won't compile until `ssdp_reflector.{h,cpp}` exist (next step is to see it fail at the build). Payloads are real ASCII `M-SEARCH`/`NOTIFY` request lines so classification runs through `ClassifySsdpMessage`. Registration counts: IPv4 = 2 (one group, two directions), IPv6 = 4 (two groups, two directions), Dual = 6.

  ```cpp
  #include "reflector/ssdp_reflector.h"
  #include "reflector/ip_address.h"
  #include "reflector/mac_address.h"
  #include "mocks/fake_link_socket.h"
  #include "mocks/fake_packet_dispatcher.h"
  #include "test_helpers.h"

  #include <gtest/gtest.h>

  #include <algorithm>
  #include <cstddef>
  #include <cstdint>
  #include <format>
  #include <span>
  #include <string>
  #include <string_view>
  #include <vector>

  namespace reflector {

  namespace {
  constexpr uint16_t SSDP_PORT = 1900;

  std::vector<std::byte> AsciiBytes(std::string_view text) {
      std::vector<std::byte> payload(text.size());
      for (size_t i = 0; i < text.size(); ++i) {
          payload[i] = static_cast<std::byte>(text[i]);
      }
      return payload;
  }

  bool Contains(const std::vector<IpAddress>& groups, const IpAddress& group) {
      return std::find(groups.begin(), groups.end(), group) != groups.end();
  }
  } // namespace

  class SsdpReflectorTestBase {
  protected:
      static SsdpConfig MakeConfig(AddressFamily address_family = AddressFamily::Default) {
          return SsdpConfig{
              .name = "bridge",
              .mac = std::nullopt,
              .source_if = "lan",
              .target_if = "iot",
              .address_family = address_family,
          };
      }

      // A minimal but well-formed M-SEARCH request line; only the leading token is classified.
      static std::vector<std::byte> MakeSearch() {
          return AsciiBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n");
      }

      static std::vector<std::byte> MakeAdvertisement() {
          return AsciiBytes("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNTS: ssdp:alive\r\n\r\n");
      }

      // Builds a packet destined for `group` on SSDP_PORT, with a captured TTL of 1 so the
      // re-emit's override to TTL 2 is observable.
      static Packet MakePacket(std::span<const std::byte> payload, const IpAddress& group,
          MacAddress source_mac = {}) {
          return Packet{
              .header = PacketHeader{
                  .source_ip = LoopbackFor(group.AddressFamily()),
                  .dest_ip = group,
                  .source_port = SSDP_PORT,
                  .dest_port = SSDP_PORT,
                  .ttl = 1,  // re-emit must override this with the SSDP TTL (2)
                  .source_mac = source_mac,
              },
              .payload = payload,
          };
      }
  };

  // Behaviors that depend on the address family run for both V4 and V6.
  class SsdpReflectorPerFamilyTest : public ::testing::TestWithParam<IpAddress::Family>,
                                     public SsdpReflectorTestBase {
  protected:
      FakePacketDispatcher packet_dispatcher;
      FakeLinkSocket source;
      FakeLinkSocket target;

      size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }

      // A single-family config for GetParam(), with only that family sendable on both sockets.
      SsdpReflector BuildReflector() {
          const bool v4 = GetParam() == IpAddress::Family::V4;
          source.can_send_v4 = target.can_send_v4 = v4;
          source.can_send_v6 = target.can_send_v6 = !v4;
          return SsdpReflector{packet_dispatcher, source, target,
              MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
      }
  };

  INSTANTIATE_TEST_SUITE_P(
      Families,
      SsdpReflectorPerFamilyTest,
      ::testing::Values(IpAddress::Family::V4, IpAddress::Family::V6),
      [](const ::testing::TestParamInfo<IpAddress::Family>& param_info) { return std::format("{}", param_info.param); });

  TEST_P(SsdpReflectorPerFamilyTest, RegistersBothDirectionsPerGroup) {
      const auto reflector = BuildReflector();

      EXPECT_TRUE(reflector.IsValid());
      // Two directions per group: one group for V4, two for V6.
      const size_t groups = IpAddress::SsdpGroupsFor(GetParam()).size();
      EXPECT_EQ(RegistrationCount(), 2 * groups);
  }

  TEST_P(SsdpReflectorPerFamilyTest, JoinsEveryGroupOnBothSockets) {
      const auto reflector = BuildReflector();
      ASSERT_TRUE(reflector.IsValid());

      const auto groups = IpAddress::SsdpGroupsFor(GetParam());
      EXPECT_EQ(source.joined_groups, groups);
      EXPECT_EQ(target.joined_groups, groups);
  }

  TEST_P(SsdpReflectorPerFamilyTest, RelaysSearchFromSourceToTargetOnEveryGroup) {
      auto reflector = BuildReflector();
      ASSERT_TRUE(reflector.IsValid());

      const auto search = MakeSearch();
      const auto groups = IpAddress::SsdpGroupsFor(GetParam());
      for (const auto& group : groups) {
          packet_dispatcher.Deliver(source, MakePacket(search, group));
      }

      ASSERT_EQ(target.sent.size(), groups.size());
      for (size_t i = 0; i < groups.size(); ++i) {
          const auto& sent = target.sent[i];
          EXPECT_EQ(sent.dst_ip, groups[i]);
          EXPECT_EQ(sent.dst_port, SSDP_PORT);
          EXPECT_EQ(sent.src_port, SSDP_PORT);
          EXPECT_EQ(sent.ttl, 2);  // re-emitted with the SSDP hop limit, not the captured TTL
          EXPECT_EQ(sent.payload, search);
      }
      EXPECT_TRUE(source.sent.empty());  // not echoed back to the source
  }

  TEST_P(SsdpReflectorPerFamilyTest, DropsAdvertisementFromSourceToTarget) {
      auto reflector = BuildReflector();
      ASSERT_TRUE(reflector.IsValid());

      // A NOTIFY arriving on source is not relayed to target — only M-SEARCH flows that way.
      const auto group = IpAddress::SsdpGroupsFor(GetParam()).front();
      packet_dispatcher.Deliver(source, MakePacket(MakeAdvertisement(), group));

      EXPECT_TRUE(target.sent.empty());
  }

  TEST_P(SsdpReflectorPerFamilyTest, RelaysAdvertisementFromTargetToSource) {
      auto reflector = BuildReflector();
      ASSERT_TRUE(reflector.IsValid());

      const auto advertisement = MakeAdvertisement();
      const auto group = IpAddress::SsdpGroupsFor(GetParam()).front();
      packet_dispatcher.Deliver(target, MakePacket(advertisement, group));

      ASSERT_EQ(source.sent.size(), 1u);
      const auto& sent = source.sent.front();
      EXPECT_EQ(sent.dst_ip, group);
      EXPECT_EQ(sent.dst_port, SSDP_PORT);
      EXPECT_EQ(sent.src_port, SSDP_PORT);
      EXPECT_EQ(sent.ttl, 2);
      EXPECT_EQ(sent.payload, advertisement);
      EXPECT_TRUE(target.sent.empty());
  }

  TEST_P(SsdpReflectorPerFamilyTest, DropsSearchFromTargetToSource) {
      auto reflector = BuildReflector();
      ASSERT_TRUE(reflector.IsValid());

      // An M-SEARCH arriving on target is not relayed to source — that would let target devices
      // discover the source network.
      const auto group = IpAddress::SsdpGroupsFor(GetParam()).front();
      packet_dispatcher.Deliver(target, MakePacket(MakeSearch(), group));

      EXPECT_TRUE(source.sent.empty());
  }

  TEST_P(SsdpReflectorPerFamilyTest, RequiredFamilyUnavailableOnSourceMakesInvalid) {
      const auto family = GetParam();
      const bool v4 = family == IpAddress::Family::V4;
      source.can_send_v4 = !v4 ? true : false;
      source.can_send_v6 = !v4 ? false : true;  // the required family is missing on source
      target.can_send_v4 = target.can_send_v6 = true;

      const std::string output = CaptureStdout([&] {
          const SsdpReflector reflector{packet_dispatcher, source, target,
              MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
          EXPECT_FALSE(reflector.IsValid());
          EXPECT_EQ(RegistrationCount(), 0);
      });
      EXPECT_NE(output.find(std::format("{}", family)), std::string::npos) << output;
  }

  TEST_P(SsdpReflectorPerFamilyTest, RequiredFamilyUnavailableOnTargetMakesInvalid) {
      const auto family = GetParam();
      const bool v4 = family == IpAddress::Family::V4;
      source.can_send_v4 = source.can_send_v6 = true;
      target.can_send_v4 = !v4 ? true : false;
      target.can_send_v6 = !v4 ? false : true;  // the required family is missing on target

      const SsdpReflector reflector{packet_dispatcher, source, target,
          MakeConfig(v4 ? AddressFamily::IPv4 : AddressFamily::IPv6)};
      EXPECT_FALSE(reflector.IsValid());
  }

  // Family-independent behavior, exercised once.
  class SsdpReflectorTest : public ::testing::Test, public SsdpReflectorTestBase {
  protected:
      FakePacketDispatcher packet_dispatcher;
      FakeLinkSocket source;  // both families sendable by default
      FakeLinkSocket target;

      size_t RegistrationCount() const { return packet_dispatcher.RegistrationCount(); }
  };

  TEST_F(SsdpReflectorTest, RejectsInvalidConfig) {
      auto config = MakeConfig();
      config.target_if = config.source_if;  // source_if == target_if fails Verify

      const std::string output = CaptureStdout([&] {
          const SsdpReflector reflector{packet_dispatcher, source, target, config};
          EXPECT_FALSE(reflector.IsValid());
          EXPECT_EQ(RegistrationCount(), 0);
      });
      EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, CreatedLogUsesConfigName) {
      const ScopedMinLogLevel level{LogLevel::Info};
      const std::string output = CaptureStdout([&] {
          const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig()};
          EXPECT_TRUE(reflector.IsValid());
      });
      EXPECT_NE(output.find("bridge"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, DualReflectsBothFamiliesAndJoinsAllGroups) {
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};

      EXPECT_TRUE(reflector.IsValid());
      // V4 (1 group) + V6 (2 groups) = 3 groups, both directions each.
      EXPECT_EQ(RegistrationCount(), 6);
      EXPECT_EQ(source.joined_groups.size(), 3u);
      EXPECT_EQ(target.joined_groups.size(), 3u);
      // Both V6 groups are joined on each socket.
      EXPECT_TRUE(Contains(source.joined_groups, IpAddress::SsdpGroupV6LinkLocal()));
      EXPECT_TRUE(Contains(source.joined_groups, IpAddress::SsdpGroupV6SiteLocal()));
      EXPECT_TRUE(Contains(target.joined_groups, IpAddress::SsdpGroupV6LinkLocal()));
      EXPECT_TRUE(Contains(target.joined_groups, IpAddress::SsdpGroupV6SiteLocal()));
  }

  TEST_F(SsdpReflectorTest, DualInvalidWhenSourceCannotSendAFamily) {
      source.can_send_v6 = false;  // Dual requires v6 on both
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
      EXPECT_FALSE(reflector.IsValid());
  }

  TEST_F(SsdpReflectorTest, DualInvalidWhenTargetCannotSendAFamily) {
      target.can_send_v6 = false;
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
      EXPECT_FALSE(reflector.IsValid());
  }

  // Default uses both families but requires only IPv4; with IPv6 unavailable on one side it stays
  // valid over IPv4 alone (the v6 groups are neither joined nor registered).
  TEST_F(SsdpReflectorTest, DefaultReflectsAvailableFamilyOnly) {
      target.can_send_v6 = false;
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Default)};

      EXPECT_TRUE(reflector.IsValid());
      EXPECT_EQ(RegistrationCount(), 2);  // v4 only, one group
      EXPECT_EQ(source.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
      EXPECT_EQ(target.joined_groups, std::vector<IpAddress>{IpAddress::SsdpGroupV4()});
  }

  TEST_F(SsdpReflectorTest, MacFilterRelaysOnlyTheConfiguredDevice) {
      auto config = MakeConfig(AddressFamily::IPv4);
      config.mac = *MacAddress::FromString("aa:bb:cc:dd:ee:ff");
      const SsdpReflector reflector{packet_dispatcher, source, target, config};
      ASSERT_TRUE(reflector.IsValid());

      const auto advertisement = MakeAdvertisement();
      const auto group = IpAddress::SsdpGroupV4();
      // An advertisement from a different device is filtered out (the dispatcher's source_mac filter).
      packet_dispatcher.Deliver(target,
          MakePacket(advertisement, group, *MacAddress::FromString("00:00:00:00:00:01")));
      EXPECT_TRUE(source.sent.empty());

      // The configured device's advertisement is relayed.
      packet_dispatcher.Deliver(target,
          MakePacket(advertisement, group, *MacAddress::FromString("aa:bb:cc:dd:ee:ff")));
      EXPECT_EQ(source.sent.size(), 1u);
  }

  TEST_F(SsdpReflectorTest, NoMacFilterRelaysAnyDevice) {
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
      ASSERT_TRUE(reflector.IsValid());

      packet_dispatcher.Deliver(target,
          MakePacket(MakeAdvertisement(), IpAddress::SsdpGroupV4(), *MacAddress::FromString("12:34:56:78:9a:bc")));
      EXPECT_EQ(source.sent.size(), 1u);
  }

  TEST_F(SsdpReflectorTest, LogsAndDropsNonSsdpPacket) {
      const ScopedMinLogLevel level{LogLevel::Info};
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
      ASSERT_TRUE(reflector.IsValid());

      // An HTTP response line is neither M-SEARCH nor NOTIFY: classified as nullopt, surfaced.
      const auto junk = AsciiBytes("HTTP/1.1 200 OK\r\n\r\n");
      const std::string output = CaptureStdout([&] {
          packet_dispatcher.Deliver(source, MakePacket(junk, IpAddress::SsdpGroupV4()));
      });

      EXPECT_TRUE(target.sent.empty());
      EXPECT_NE(output.find("non-SSDP"), std::string::npos) << output;  // anomaly surfaced at INFO
  }

  TEST_F(SsdpReflectorTest, DropsWrongDirectionSilently) {
      const ScopedMinLogLevel level{LogLevel::Info};
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
      ASSERT_TRUE(reflector.IsValid());

      // A NOTIFY arriving on source is normal bidirectional SSDP, not an anomaly: dropped without
      // the non-SSDP log.
      const std::string output = CaptureStdout([&] {
          packet_dispatcher.Deliver(source, MakePacket(MakeAdvertisement(), IpAddress::SsdpGroupV4()));
      });

      EXPECT_TRUE(target.sent.empty());
      EXPECT_EQ(output.find("non-SSDP"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, LogsErrorWhenSendFails) {
      const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
      ASSERT_TRUE(reflector.IsValid());
      target.fail_send = true;

      const std::string output = CaptureStdout([&] {
          packet_dispatcher.Deliver(source, MakePacket(MakeSearch(), IpAddress::SsdpGroupV4()));
      });

      EXPECT_TRUE(target.sent.empty());
      EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, JoinFailureMakesInvalid) {
      source.fail_join = true;

      const std::string output = CaptureStdout([&] {
          const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
          EXPECT_FALSE(reflector.IsValid());
          EXPECT_EQ(RegistrationCount(), 0);
      });
      EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, RegistrationFailureRollsBackAndInvalidates) {
      packet_dispatcher.fail_register_on_call = 2;  // the second registration fails

      const std::string output = CaptureStdout([&] {
          const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::IPv4)};
          EXPECT_FALSE(reflector.IsValid());
      });

      EXPECT_EQ(RegistrationCount(), 0);  // the first registration was rolled back
      EXPECT_NE(output.find("ERROR"), std::string::npos) << output;
  }

  TEST_F(SsdpReflectorTest, DestructorUnregisters) {
      {
          const SsdpReflector reflector{packet_dispatcher, source, target, MakeConfig(AddressFamily::Dual)};
          ASSERT_TRUE(reflector.IsValid());
          ASSERT_EQ(RegistrationCount(), 6);
      }

      EXPECT_EQ(RegistrationCount(), 0);
  }

  } // namespace reflector
  ```

  Add the test to `tests/CMakeLists.txt` now, so it builds. Insert this line after the `wol_reflector_test.cpp` line is not where it belongs alphabetically; mirror the mdns grouping — place it right after the `mdns_reflector_test.cpp` entry (line 15):

  ```cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_reflector_test.cpp
  ```

- [ ] **Step K+1: Run the test build and see it fail (no `ssdp_reflector.h` yet)**

  Command:
  ```sh
  cmake --build build --target reflector_test 2>&1 | tail -n 20
  ```
  Expected output: a hard compile error, the header is missing —
  ```
  fatal error: 'reflector/ssdp_reflector.h' file not found
  ```
  (The build fails to produce `reflector_test`; this is the red state.)

- [ ] **Step K+2: Create the header `src/reflector/ssdp_reflector.h`**

  Mirrors `MdnsReflector` but documents the per-family multi-group loop and the SSDP TTL. `SetUpFamily` iterates groups internally, so its signature is unchanged from mdns; an inner `SetUpGroup` does the per-group join + register.

  ```cpp
  #pragma once

  #include "config.h"
  #include "ip_address.h"
  #include "link_socket.h"
  #include "packet.h"
  #include "packet_dispatcher.h"
  #include "reflector.h"
  #include "ssdp_message.h"

  #include <cstdint>

  namespace reflector {

  // Reflects SSDP (UPnP discovery) between two interfaces. Captures on both source_if and target_if
  // (joining the SSDP groups on each), then relays directionally: M-SEARCH source->target,
  // advertisements (NOTIFY) target->source. The target->source direction can be restricted to one
  // device by its frame source MAC (config.mac). Unlike mDNS's single group per family, SSDP uses
  // several groups for IPv6 (link-local ff02::c and site-local ff05::c) and one for IPv4
  // (239.255.255.250); a handled family joins and registers every group in IpAddress::SsdpGroupsFor.
  // Both sockets must outlive this reflector.
  class SsdpReflector : public Reflector {
  public:
      SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
          LinkSocket& target_socket, const SsdpConfig& config);

  private:
      static constexpr uint16_t SSDP_PORT = 1900;
      static constexpr uint8_t SSDP_TTL = 2;

      [[nodiscard]] bool ValidateConfig(const SsdpConfig& config);
      void Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
          LinkSocket& target_socket, const SsdpConfig& config);
      // Joins each of the family's SSDP groups on both sockets and registers both directions per
      // group. Returns false (after logging) if any join or registration fails.
      [[nodiscard]] bool SetUpFamily(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
          LinkSocket& target_socket, IpAddress::Family family, const SsdpConfig& config);
      // Joins one group on both sockets and registers both directions for it.
      [[nodiscard]] bool SetUpGroup(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
          LinkSocket& target_socket, const IpAddress& group, const SsdpConfig& config);

      void OnSourcePacket(const Packet& packet) noexcept;  // source->target: relay M-SEARCH
      void OnTargetPacket(const Packet& packet) noexcept;  // target->source: relay advertisements
      // True if `packet` is an SSDP message of `kind` (and should be relayed). A payload that isn't
      // an SSDP message at all is logged and dropped (it shouldn't appear on the group); a message
      // of the other kind is dropped silently (normal bidirectional traffic).
      [[nodiscard]] bool ShouldRelay(const Packet& packet, SsdpMessageKind kind) noexcept;
      void Relay(LinkSocket& egress, const Packet& packet) noexcept;

      LinkSocket& source_socket_;
      LinkSocket& target_socket_;
  };

  } // namespace reflector
  ```

- [ ] **Step K+3: Create the implementation `src/reflector/ssdp_reflector.cpp`**

  Structure mirrors `mdns_reflector.cpp`. The only divergence: `SetUpFamily` loops over `IpAddress::SsdpGroupsFor(family)` and calls `SetUpGroup` for each; `Relay` uses `SSDP_TTL` (2); `ShouldRelay` calls `ClassifySsdpMessage` and logs "non-SSDP".

  ```cpp
  #include "ssdp_reflector.h"

  #include "ssdp_message.h"
  #include "util/delegate.h"

  #include <format>
  #include <string>
  #include <utility>

  namespace reflector {

  namespace {

  std::string LoggerName(const SsdpConfig& config) {
      return std::format("SsdpReflector:{}:{}->{}", config.name, config.source_if, config.target_if);
  }

  } // namespace

  SsdpReflector::SsdpReflector(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
      LinkSocket& target_socket, const SsdpConfig& config)
          : Reflector{LoggerName(config)}
          , source_socket_{source_socket}
          , target_socket_{target_socket} {
      if (!ValidateConfig(config)) {
          return;
      }

      Initialize(packet_dispatcher, source_socket, target_socket, config);
  }

  bool SsdpReflector::ValidateConfig(const SsdpConfig& config) {
      if (const auto error = config.Verify()) {
          logger_.Error("Cannot create ssdp reflector \"{}\": invalid config: {}", config.name, *error);
          return false;
      }
      return true;
  }

  void SsdpReflector::Initialize(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
      LinkSocket& target_socket, const SsdpConfig& config) {
      // SSDP is bidirectional, so a handled family must be sendable on BOTH interfaces: the target
      // re-emits relayed searches, the source re-emits relayed advertisements.
      const auto reflectable = [&](IpAddress::Family family) {
          return source_socket.CanSend(family) && target_socket.CanSend(family);
      };

      if (config.RequiresIPv4() && !reflectable(IpAddress::Family::V4)) {
          logger_.Error("Cannot create ssdp reflector \"{}\": IPv4 requires a source address on both \"{}\" and \"{}\"",
              config.name, config.source_if, config.target_if);
          return;
      }
      if (config.RequiresIPv6() && !reflectable(IpAddress::Family::V6)) {
          logger_.Error("Cannot create ssdp reflector \"{}\": IPv6 requires a source address on both \"{}\" and \"{}\"",
              config.name, config.source_if, config.target_if);
          return;
      }

      for (const auto family : {IpAddress::Family::V4, IpAddress::Family::V6}) {
          const bool uses = family == IpAddress::Family::V4 ? config.UsesIPv4() : config.UsesIPv6();
          if (!uses || !reflectable(family)) {
              continue;  // a family the config merely "uses" but can't reflect is silently skipped
          }
          if (!SetUpFamily(packet_dispatcher, source_socket, target_socket, family, config)) {
              registrations_.clear();
              return;
          }
      }

      logger_.Info("Created ssdp reflector (IPv4: {}, IPv6: {})",
          config.UsesIPv4() && reflectable(IpAddress::Family::V4) ? "enabled" : "disabled",
          config.UsesIPv6() && reflectable(IpAddress::Family::V6) ? "enabled" : "disabled");
  }

  bool SsdpReflector::SetUpFamily(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
      LinkSocket& target_socket, IpAddress::Family family, const SsdpConfig& config) {
      // SSDP spreads across several groups for IPv6 (link-local + site-local); each is set up
      // independently, so a single failure aborts the whole family.
      for (const auto& group : IpAddress::SsdpGroupsFor(family)) {
          if (!SetUpGroup(packet_dispatcher, source_socket, target_socket, group, config)) {
              return false;
          }
      }
      return true;
  }

  bool SsdpReflector::SetUpGroup(PacketDispatcher& packet_dispatcher, LinkSocket& source_socket,
      LinkSocket& target_socket, const IpAddress& group, const SsdpConfig& config) {
      // Program gate 2 so each interface actually receives the group's multicast.
      if (!source_socket.JoinMulticastGroup(group) || !target_socket.JoinMulticastGroup(group)) {
          logger_.Error("Cannot create ssdp reflector \"{}\": cannot join {} on both interfaces",
              config.name, group);
          return false;
      }

      // source -> target: relay searches, unfiltered (any client on source may ask).
      auto source_registration = packet_dispatcher.Register(source_socket,
          PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT},
          CreateDelegate<&SsdpReflector::OnSourcePacket>(this));
      if (!source_registration.IsValid()) {
          logger_.Error("Cannot create ssdp reflector \"{}\": registration failed for {} (source)", config.name, group);
          return false;
      }
      registrations_.push_back(std::move(source_registration));

      // target -> source: relay advertisements, optionally only from the configured device's MAC.
      auto target_registration = packet_dispatcher.Register(target_socket,
          PacketFilter{.dest_ip = group, .dest_port = SSDP_PORT, .source_mac = config.mac},
          CreateDelegate<&SsdpReflector::OnTargetPacket>(this));
      if (!target_registration.IsValid()) {
          logger_.Error("Cannot create ssdp reflector \"{}\": registration failed for {} (target)", config.name, group);
          return false;
      }
      registrations_.push_back(std::move(target_registration));

      return true;
  }

  void SsdpReflector::OnSourcePacket(const Packet& packet) noexcept {
      if (ShouldRelay(packet, SsdpMessageKind::Search)) {  // only searches flow source -> target
          Relay(target_socket_, packet);
      }
  }

  void SsdpReflector::OnTargetPacket(const Packet& packet) noexcept {
      // Only advertisements flow target -> source; the source-MAC filter is applied by the dispatcher.
      if (ShouldRelay(packet, SsdpMessageKind::Advertisement)) {
          Relay(source_socket_, packet);
      }
  }

  bool SsdpReflector::ShouldRelay(const Packet& packet, SsdpMessageKind kind) noexcept {
      const auto message_kind = ClassifySsdpMessage(packet.payload);
      if (!message_kind.has_value()) {
          // The group + port 1900 should carry only SSDP, so a payload whose leading token is
          // neither M-SEARCH nor NOTIFY is anomalous and worth surfacing — the dedicated group means
          // this won't spam a healthy network. A message of the other kind, by contrast, is normal
          // and dropped silently.
          logger_.Info("Ignoring non-SSDP packet on {} from {}: {}-byte payload not an SSDP request",
              packet.header.dest_ip, packet.header.source_ip, packet.payload.size());
          return false;
      }
      return *message_kind == kind;
  }

  void SsdpReflector::Relay(LinkSocket& egress, const Packet& packet) noexcept {
      // Re-emit to the same group it was sent to (the filter guarantees dest_ip is that group), from
      // the SSDP port, with the conventional TTL of 2.
      const auto& group = packet.header.dest_ip;
      if (!egress.SendUdpDatagram(group, SSDP_PORT, SSDP_PORT, packet.payload, SSDP_TTL)) {
          logger_.Error("Cannot reflect ssdp packet from {} to {}", packet.header.source_ip, group);
          return;
      }
      logger_.Debug("Reflected ssdp packet from {} to {}", packet.header.source_ip, group);
  }

  } // namespace reflector
  ```

  Add the source to `src/reflector/CMakeLists.txt`, mirroring the mdns grouping — insert right after the `mdns_reflector.cpp` line (line 13):

  ```cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_reflector.cpp
  ```

- [ ] **Step K+4: Build and run the SSDP reflector tests — see them pass (green)**

  Command:
  ```sh
  cmake --build build --target reflector_test \
    && ctest --test-dir build -L unit -R 'SsdpReflector' --output-on-failure
  ```
  Expected output: all `SsdpReflector*` cases pass — both parameterized families and the family-independent fixture. Count is `2 families × 8 P-tests + 14 F-tests = 30` test cases:
  ```
  100% tests passed, 0 tests failed out of 30
  ```
  (If `SsdpGroupsFor`/`ClassifySsdpMessage`/`SsdpConfig` from the prerequisite tasks aren't yet merged, the build error names the missing symbol — finish those tasks first.)

- [ ] **Step K+5: Confirm sanitizer instrumentation is live, then run the full unit suite**

  Per project policy, verify ASan/UBSan is actually on (a stale cache can silently disable it), then run the whole unit label so the new translation units are exercised under the sanitizers alongside everything else.

  Commands:
  ```sh
  grep REFLECTOR_SANITIZE build/CMakeCache.txt
  ctest --test-dir build -L unit --output-on-failure
  ```
  Expected output:
  ```
  REFLECTOR_SANITIZE:BOOL=ON
  ...
  100% tests passed, 0 tests failed out of <N>
  ```

- [ ] **Step K+6: Gate, review, and commit on permission (project methodology)**

  This project does not auto-commit. Run the full test gate, then STOP and show the diff for review; commit only after explicit per-batch permission.

  Commands (the gate):
  ```sh
  ctest --test-dir build -L unit --output-on-failure
  ./docker_test.sh
  ./docker_test.sh release
  python3 e2e/run.py
  ```
  Then show the diff for review:
  ```sh
  git status
  git --no-pager diff -- src/reflector/ssdp_reflector.h src/reflector/ssdp_reflector.cpp \
    src/reflector/CMakeLists.txt tests/ssdp_reflector_test.cpp tests/CMakeLists.txt
  ```
  Do not run `git commit` as an autonomous step. After the gate is green and the diff is reviewed, commit only once explicit per-batch permission is given.

### Task 5: Application wiring

**Files:**
- Modify: `src/reflector/application.cpp` — add `#include "ssdp_reflector.h"` (next to the existing `#include "mdns_reflector.h"` at line 5); extend the `Configure` `&&` chain (lines 87-96).
- Test: `tests/application_test.cpp` — add a `MakeSsdpConfig` helper (next to `MakeMdnsConfig`, lines 77-86) and the SSDP wiring/failure cases.

> **Registration-count note (load-bearing — read before writing the asserts).** `dispatcher_->RegistrationCount()` in `application_test.cpp` is the *FakeDispatcher*'s count: `FakeDispatcher::Register` stores **one callback per fd** (`callbacks_.contains(fd)` rejects a second registration on the same fd). `DefaultPacketDispatcher::Register` calls `dispatcher_->Register(fd, ...)` **only on the first subscriber for that fd** (`if (!capture_sources_.contains(fd))`). So however many times `SsdpReflector` calls `packet_dispatcher.Register` — 2 groups × 2 directions = 4 packet-dispatcher registrations per family — the *dispatcher* watches each distinct fd exactly **once**. An SSDP reflector on `src`/`dst` therefore yields `RegistrationCount() == 2` (the two fds), identical to the mDNS case at lines 211-226, NOT 4. The "4" in the spec is the count of `PacketDispatcher` callbacks, which the FakeDispatcher does not expose. To prove the multi-group join actually happened, assert on `Socket("src")->joined_groups` / `joined_groups.size()` instead — `FakeLinkSocket::JoinMulticastGroup` records every group (fake_link_socket.h:57-63).

---

- [ ] **Step 1: Add the failing `WiresSsdpReflectorOnBothInterfaces` test (and `MakeSsdpConfig` helper)**

Add this helper immediately after `MakeMdnsConfig` (after line 86 in `tests/application_test.cpp`):

```cpp
    static SsdpConfig MakeSsdpConfig(std::string_view name, std::string_view source_if,
        std::string_view target_if, AddressFamily family = AddressFamily::IPv4) {
        return SsdpConfig{
            .name = std::string{name},
            .mac = std::nullopt,
            .source_if = std::string{source_if},
            .target_if = std::string{target_if},
            .address_family = family,
        };
    }
```

Add this test after `WiresMdnsReflectorOnBothInterfaces` (after line 226). It uses the default (dual-stack) family so SSDP joins both V6 groups plus the V4 group across both sockets, exercising the multi-group loop, while the fd-watch count stays at 2:

```cpp
TEST_F(ApplicationTest, WiresSsdpReflectorOnBothInterfaces) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("dial", "src", "dst", AddressFamily::Default))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 1);
    // SSDP captures on both interfaces, so each socket's fd is watched exactly once — the
    // FakeDispatcher counts callbacks per fd, not per PacketDispatcher registration, so the
    // four per-family group registrations collapse to two watched fds.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("src")->fd));
    EXPECT_TRUE(dispatcher_->IsWatching(Socket("dst")->fd));
    // Dual-stack joins one V4 group plus two V6 groups (link- and site-local) on each socket.
    EXPECT_EQ(Socket("src")->joined_groups.size(), 3u);
    EXPECT_EQ(Socket("dst")->joined_groups.size(), 3u);
}
```

The `TestConfigBuilder` needs an `Add(SsdpConfig)` overload (added in the config task); until both that overload and the application wiring exist this fails to compile, which is the intended red state.

- [ ] **Step 2: Run the new test, see it fail (red)**

```sh
ctest --test-dir build -L unit -R ApplicationTest --output-on-failure
```

Expected (compile failure, since `Configure` does not yet wire SSDP and the reflector is unwired): the build fails or `WiresSsdpReflectorOnBothInterfaces` fails with `ReflectorCount(app)` 0 / `joined_groups.size()` 0. Confirm the failure names `WiresSsdpReflectorOnBothInterfaces`.

- [ ] **Step 3: Wire SSDP into `application.cpp` (minimal green)**

Add the include after the mDNS include in `src/reflector/application.cpp` (line 5):

```cpp
#include "mdns_reflector.h"
#include "raw_socket.h"
#include "ssdp_reflector.h"
```

(Keep the existing project-includes block alphabetically ordered: `mdns_reflector.h`, `raw_socket.h`, `ssdp_reflector.h`, then `util/delegate.h`, `wol_reflector.h`.)

Extend the `Configure` `&&` chain (lines 88-89) to:

```cpp
    if (ConfigureReflectors<WolReflector>(config.WolConfigs(), "wol")
        && ConfigureReflectors<MdnsReflector>(config.MdnsConfigs(), "mdns")
        && ConfigureReflectors<SsdpReflector>(config.SsdpConfigs(), "ssdp")) {
        return true;
    }
```

The template, rollback (`reflectors_.clear()`), and `Run`'s `assert(!reflectors_.empty())` are unchanged — `SsdpReflector` shares the `(packet_dispatcher, source, target, config)` ctor shape and the `IsValid()` contract, so `ConfigureReflectors` covers it with no new code.

- [ ] **Step 4: Run the test, see it pass (green)**

```sh
ctest --test-dir build -L unit -R ApplicationTest --output-on-failure
```

Expected: `WiresSsdpReflectorOnBothInterfaces` passes, all other `ApplicationTest` cases still pass.

- [ ] **Step 5: Add `SharesSocketsAcrossAllProtocols` (red, then already green)**

Add after `SharesSocketsBetweenWolAndMdns` (after line 243). WoL + mDNS + SSDP all on `src`/`dst`; all three protocols reuse the same two sockets, and the two fds are watched once each:

```cpp
TEST_F(ApplicationTest, SharesSocketsAcrossAllProtocols) {
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src", "dst", {9}))
        .Add(MakeMdnsConfig("cast", "src", "dst"))
        .Add(MakeSsdpConfig("dial", "src", "dst"))
        .Build();

    ASSERT_TRUE(app.Configure(config));

    // All three protocols reuse the same per-interface sockets.
    EXPECT_EQ(factory_calls_, 2);
    EXPECT_EQ(SocketCount(app), 2);
    EXPECT_EQ(ReflectorCount(app), 3);
    // WoL watches "src"; mDNS and SSDP additionally watch "dst" — two distinct fds total,
    // each watched once however many reflectors register on it.
    EXPECT_EQ(dispatcher_->RegistrationCount(), 2);
}
```

Run it:

```sh
ctest --test-dir build -L unit -R ApplicationTest --output-on-failure
```

Expected: passes (the Step 3 wiring already covers it). If it fails, the wiring is wrong — fix before continuing.

- [ ] **Step 6: Add the SSDP source/target-invalid failure cases**

Add after `FailsWhenMdnsTargetSocketInvalid` (after line 274). These mirror the mDNS invalid-socket cases (lines 245-274) and assert the log names the `ssdp` protocol and the offending interface:

```cpp
TEST_F(ApplicationTest, FailsWhenSsdpSourceSocketInvalid) {
    ConfigureSocket("bad-src", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("dial", "bad-src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("ssdp"), std::string::npos) << output;     // the log names the protocol
    EXPECT_NE(output.find("bad-src"), std::string::npos) << output;  // and the source interface
}

TEST_F(ApplicationTest, FailsWhenSsdpTargetSocketInvalid) {
    ConfigureSocket("bad-dst", {.valid = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("dial", "src", "bad-dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0);
    EXPECT_NE(output.find("bad-dst"), std::string::npos) << output;  // the log names the target interface
}
```

- [ ] **Step 7: Add the SSDP setup-failure case**

Add after the cases from Step 6. Mirrors `FailsWhenMdnsReflectorSetupFails` (lines 276-290): SSDP reflects in both directions, so an IPv4 config whose target can't originate IPv4 fails to initialize even though both socket checks pass:

```cpp
TEST_F(ApplicationTest, FailsWhenSsdpReflectorSetupFails) {
    // SSDP needs the family sendable on both interfaces; the IPv4 config can't be reflected when
    // the target can't originate IPv4, so the reflector fails to initialize.
    ConfigureSocket("dst", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeSsdpConfig("dial", "src", "dst"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output;
}
```

- [ ] **Step 8: Add the cross-protocol rollback case**

Add after the Step 7 case. Mirrors `ClearsWolReflectorWhenLaterMdnsFails` (lines 292-309) but across all three protocols: WoL and mDNS wire first, then SSDP fails, and the transactional `Configure` rolls everything back. A source that can't originate IPv4 breaks both mDNS and SSDP; ordering WoL first proves the earlier successful wiring is discarded:

```cpp
TEST_F(ApplicationTest, ClearsEarlierReflectorsWhenLaterSsdpFails) {
    // WoL and mDNS are configured before SSDP; both wire successfully before the SSDP entry fails.
    // Configure is transactional: those earlier successes are rolled back, leaving nothing wired.
    // A source that can't originate IPv4 breaks the bidirectional protocols (mDNS, SSDP) but the
    // mDNS entry here uses "dst-ok" so it succeeds, isolating the failure to SSDP.
    ConfigureSocket("src-bad", {.can_send_v4 = false});
    auto app = MakeApp();
    const Config config = TestConfigBuilder{}
        .Add(MakeWolConfig("tv", "src-ok", "dst-ok", {9}))
        .Add(MakeMdnsConfig("cast", "src-ok", "dst-ok"))
        .Add(MakeSsdpConfig("dial", "src-bad", "dst-ok"))
        .Build();

    const std::string output = CaptureStdout([&] {
        EXPECT_FALSE(app.Configure(config));
    });

    EXPECT_EQ(ReflectorCount(app), 0) << output; // the WoL and mDNS reflectors wired earlier are rolled back
    EXPECT_NE(output.find("ssdp"), std::string::npos) << output;
}
```

- [ ] **Step 9: Run the full `ApplicationTest` suite, see all green**

```sh
ctest --test-dir build -L unit -R ApplicationTest --output-on-failure
```

Expected: every `ApplicationTest` case passes, including the six new SSDP cases (`WiresSsdpReflectorOnBothInterfaces`, `SharesSocketsAcrossAllProtocols`, `FailsWhenSsdpSourceSocketInvalid`, `FailsWhenSsdpTargetSocketInvalid`, `FailsWhenSsdpReflectorSetupFails`, `ClearsEarlierReflectorsWhenLaterSsdpFails`). Confirm `grep REFLECTOR_SANITIZE build/CMakeCache.txt` shows `ON` so these ran under ASan/UBSan.

- [ ] **Step 10: Gate, review, and commit on permission**

This change is on the data-path wiring, so run the full test gate:

```sh
ctest --test-dir build -L unit --output-on-failure
./docker_test.sh
./docker_test.sh release
python3 e2e/run.py
```

Then STOP and show the diff for review; commit only after explicit per-batch permission. Do not run `git commit` autonomously.

### Task 6: e2e SSDP cases

**Files:**
- Modify: `e2e/config.toml` (append after the `[[mdns]]` block at lines 16-19)
- Modify: `e2e/run.py` (add SSDP constants after the mDNS constants block at lines 33-47; add `TestCase`s to `TEST_CASES` after the mDNS cases, before the closing `]` at line 223)
- Test: `e2e/run.py` itself is the test harness; the new `TestCase`s are the tests, exercised via `python3 e2e/run.py`. `e2e/probe.py` needs no change (verified below).

- [ ] **Step 1: Confirm probe.py already supports the SSDP requirements (no change needed)**

  No edit. Read-only verification that the multicast send + `--join-group` + `--expect-payload-hex` paths added for mDNS cover SSDP unchanged:
  - `send`: `is_ipv4_multicast` (probe.py:49-51) accepts `239.255.255.250` (first octet 239 is in `224..239`), so the IPv4 multicast egress branch (probe.py:77-82) sets `IP_MULTICAST_TTL` and scopes `IP_MULTICAST_IF` to `--interface`. For `ff02::c`, `is_ipv6` (probe.py:45-46) routes to the IPv6 branch (probe.py:66-74), which sets `IPV6_MULTICAST_IF`/`IPV6_MULTICAST_HOPS` and packs the scope id into the address tuple — correct for a link-local group.
  - `receive`: `--join-group`/`--interface` (probe.py:163-164) drive `join_group` (probe.py:53-60) with `IP_ADD_MEMBERSHIP` (v4) / `IPV6_JOIN_GROUP` (v6); `--expect-payload-hex` (probe.py:168) compares the received bytes verbatim against the expected payload (probe.py:91-96, 132-136). SSDP relays the payload verbatim, so this matches.

  Run to confirm the probe accepts the SSDP argument shapes without touching the network:

  ```
  python3 e2e/probe.py send --payload-hex 4d2d534541524348 --port 1900 --address 239.255.255.250 --interface lo --help >/dev/null && echo "send-args OK"
  python3 e2e/probe.py receive --port 1900 --timeout 0.1 --expect-payload-hex 4e4f54494659 --join-group 239.255.255.250 --interface lo --help >/dev/null && echo "receive-args OK"
  ```

  Expected output:
  ```
  send-args OK
  receive-args OK
  ```

  (If, contrary to this analysis, a change were required it would be a new flag on `send`/`receive`; none is — `probe.py` stays untouched.)

- [ ] **Step 2: Add the `[[ssdp]]` section to the e2e config**

  Append to `e2e/config.toml` after the existing `[[mdns]]` block (after line 19). Mirror the `[[mdns]]` block exactly (name + source_if + target_if; no ports, no mac — the e2e exercises the any-MAC path the same way the mDNS block does):

  ```toml
  [[ssdp]]
  name = "e2e-ssdp"
  source_if = "wol_src"
  target_if = "wol_dst"
  ```

  Run to confirm the file parses and the new table is present:

  ```
  python3 -c "import tomllib,pathlib; d=tomllib.loads(pathlib.Path('e2e/config.toml').read_text()); print([s['name'] for s in d['ssdp']])"
  ```

  Expected output:
  ```
  ['e2e-ssdp']
  ```

- [ ] **Step 3: Add the SSDP constants to run.py**

  Insert into `e2e/run.py` immediately after the mDNS constants block (after line 47, before the blank lines preceding `class CommandError`). The payloads are real ASCII SSDP messages with CRLF line endings, encoded as hex so they flow through `--payload-hex`/`--expect-payload-hex` unchanged. The comments explain only the non-obvious facts: why these exact leading tokens matter to `ClassifySsdpMessage`, and that `HTTP/` is deliberately neither kind.

  ```python
  SSDP_GROUP_V4 = "239.255.255.250"
  SSDP_GROUP_V6 = "ff02::c"
  SSDP_PORT = 1900
  # SSDP messages are HTTPU text with CRLF line endings, relayed verbatim. ClassifySsdpMessage keys
  # only on the leading ASCII token: "M-SEARCH " -> Search, "NOTIFY " -> Advertisement, anything else
  # (here "HTTP/1.1") -> neither, so the HTTP response is dropped even when sent on the group.
  SSDP_MSEARCH_HEX = (
      b'M-SEARCH * HTTP/1.1\r\n'
      b'HOST: 239.255.255.250:1900\r\n'
      b'MAN: "ssdp:discover"\r\n'
      b'MX: 1\r\n'
      b'ST: ssdp:all\r\n'
      b'\r\n'
  ).hex()
  SSDP_NOTIFY_HEX = (
      b'NOTIFY * HTTP/1.1\r\n'
      b'HOST: 239.255.255.250:1900\r\n'
      b'CACHE-CONTROL: max-age=1800\r\n'
      b'LOCATION: http://192.0.2.1:80/desc.xml\r\n'
      b'NT: upnp:rootdevice\r\n'
      b'NTS: ssdp:alive\r\n'
      b'\r\n'
  ).hex()
  SSDP_HTTP_RESPONSE_HEX = (
      b'HTTP/1.1 200 OK\r\n'
      b'CACHE-CONTROL: max-age=1800\r\n'
      b'LOCATION: http://192.0.2.1:80/desc.xml\r\n'
      b'ST: upnp:rootdevice\r\n'
      b'\r\n'
  ).hex()
  ```

  Run to confirm the leading tokens classify as intended (mirrors `ClassifySsdpMessage`'s case-sensitive prefix check):

  ```
  python3 -c "import binascii,sys; sys.path.insert(0,'e2e'); import run; m=binascii.unhexlify(run.SSDP_MSEARCH_HEX); n=binascii.unhexlify(run.SSDP_NOTIFY_HEX); h=binascii.unhexlify(run.SSDP_HTTP_RESPONSE_HEX); print(m.startswith(b'M-SEARCH '), n.startswith(b'NOTIFY '), h.startswith(b'HTTP/'))"
  ```

  Expected output:
  ```
  True True True
  ```

- [ ] **Step 4: Add the SSDP `TestCase`s to `TEST_CASES`**

  Insert into `e2e/run.py` at the end of the `TEST_CASES` list, after the last mDNS case (after line 222 `),`, before the closing `]` on line 223). These mirror the mDNS cases exactly: forward = source->target (M-SEARCH), reverse = target->source (NOTIFY). The IPv6 twins set `family=6` and the v6 group. The two "wrong direction" cases and the HTTP-response case use `expect_mac=None` with no `expect_payload_hex`, which makes `start_receiver` pass `--expect-none` (run.py:391-394).

  ```python
      # SSDP relays M-SEARCH source->target and NOTIFY (advertisements) target->source, verbatim, to
      # the 239.255.255.250 / ff02::c group on port 1900. Reflected cases: the message travels its
      # allowed direction and arrives byte-for-byte.
      TestCase(
          name="reflects_ssdp_msearch",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=5.0,
          send_payload_hex=SSDP_MSEARCH_HEX,
          expect_payload_hex=SSDP_MSEARCH_HEX,
          group=SSDP_GROUP_V4,
      ),
      TestCase(
          name="reflects_ssdp_msearch_ipv6",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=5.0,
          send_payload_hex=SSDP_MSEARCH_HEX,
          expect_payload_hex=SSDP_MSEARCH_HEX,
          group=SSDP_GROUP_V6,
          family=6,
      ),
      TestCase(
          name="reflects_ssdp_notify",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=5.0,
          send_payload_hex=SSDP_NOTIFY_HEX,
          expect_payload_hex=SSDP_NOTIFY_HEX,
          group=SSDP_GROUP_V4,
          direction="reverse",
      ),
      TestCase(
          name="reflects_ssdp_notify_ipv6",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=5.0,
          send_payload_hex=SSDP_NOTIFY_HEX,
          expect_payload_hex=SSDP_NOTIFY_HEX,
          group=SSDP_GROUP_V6,
          direction="reverse",
          family=6,
      ),
      # Dropped cases: a message travelling the wrong direction is not relayed. An M-SEARCH arriving on
      # the target (advertisement direction) or a NOTIFY arriving on the source (search direction) is
      # ignored, and an HTTP/1.1 response on the group classifies as neither kind.
      TestCase(
          name="ignores_ssdp_msearch_in_notify_direction",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=1.5,
          send_payload_hex=SSDP_MSEARCH_HEX,
          group=SSDP_GROUP_V4,
          direction="reverse",
      ),
      TestCase(
          name="ignores_ssdp_notify_in_msearch_direction",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=1.5,
          send_payload_hex=SSDP_NOTIFY_HEX,
          group=SSDP_GROUP_V4,
      ),
      TestCase(
          name="ignores_ssdp_http_response_on_group",
          send_port=SSDP_PORT,
          receive_port=SSDP_PORT,
          expect_mac=None,
          timeout_seconds=1.5,
          send_payload_hex=SSDP_HTTP_RESPONSE_HEX,
          group=SSDP_GROUP_V4,
      ),
  ```

  Run to confirm the seven cases load and the runner's `--case` choices now list them (this exercises `select_cases` and `parse_args` without Docker):

  ```
  python3 e2e/run.py --case bogus 2>&1 | tr ',' '\n' | grep ssdp
  ```

  Expected output (argparse rejects the unknown `--case` value with `error: argument --case: invalid choice: 'bogus' (choose from ...)` and prints the full choices list to stderr; the `grep` confirms all seven SSDP names appear among those choices):
  ```
   reflects_ssdp_msearch
   reflects_ssdp_msearch_ipv6
   reflects_ssdp_notify
   reflects_ssdp_notify_ipv6
   ignores_ssdp_msearch_in_notify_direction
   ignores_ssdp_notify_in_msearch_direction
   ignores_ssdp_http_response_on_group
  ```

- [ ] **Step 5: Run the SSDP e2e cases end to end against the built image**

  This requires the SSDP code-path tasks (config parsing, `SsdpReflector`, application wiring) to be merged first, since the e2e drives the real reflector binary. Run only the new cases against a freshly built image:

  ```
  python3 e2e/run.py \
      --case reflects_ssdp_msearch \
      --case reflects_ssdp_msearch_ipv6 \
      --case reflects_ssdp_notify \
      --case reflects_ssdp_notify_ipv6 \
      --case ignores_ssdp_msearch_in_notify_direction \
      --case ignores_ssdp_notify_in_msearch_direction \
      --case ignores_ssdp_http_response_on_group
  ```

  Expected output (tail):
  ```
  PASS reflects_ssdp_msearch
  PASS reflects_ssdp_msearch_ipv6
  PASS reflects_ssdp_notify
  PASS reflects_ssdp_notify_ipv6
  PASS ignores_ssdp_msearch_in_notify_direction
  PASS ignores_ssdp_notify_in_msearch_direction
  PASS ignores_ssdp_http_response_on_group

  PASS 7 e2e case(s)
  ```

- [ ] **Step 6: Full test gate, then stop for review and commit on permission**

  This project does not auto-commit. Run the full test gate, then STOP and show the diff for review; commit only after explicit per-batch permission. Do not run `git commit` as an autonomous step.

  ```
  ctest --test-dir build -L unit --output-on-failure
  ./docker_test.sh
  ./docker_test.sh release
  python3 e2e/run.py
  ```

  All four must pass (unit suite green; both Docker suites green; `python3 e2e/run.py` ends with `PASS N e2e case(s)` covering the WoL, mDNS, and the seven new SSDP cases). Then show `git diff` for `e2e/config.toml` and `e2e/run.py` and wait for explicit per-batch permission before committing.

### Task 7: Docs (README + sample config)

**Files:**
- Modify: `README.md` (intro bullet list around lines 8-11; Configuration intro line 113-114; new subsection after the mDNS subsection which ends at line 155, before `## Tests` at line 157)
- Modify: `config.toml` (append after the `[[mdns]]` block at lines 10-14)

This is a pure-docs task: no code, no failing test, no build gate. The two edits are mechanical string replacements; the only check is a visual diff review. The single commit at the end follows the project methodology.

- [ ] **Step 1: Add the SSDP bullet to the README intro protocol list**

  The intro lists the two supported protocols as a bullet list (README.md lines 8-11). Extend the lead-in count and add a third bullet, mirroring the phrasing of the mDNS bullet.

  Replace (old_string):
  ```markdown
  multicasts — for example, a router bridging a wired LAN to a Wi-Fi network. Two protocols are
  supported today:

  - **Wake-on-LAN** — magic packets sent on one interface are re-emitted on another, so a sender can
    wake a host on a different segment.
  - **multicast DNS (mDNS)** — service discovery traffic is relayed between two interfaces, so clients
    on one segment can discover responders on the other.
  ```
  With (new_string):
  ```markdown
  multicasts — for example, a router bridging a wired LAN to a Wi-Fi network. Three protocols are
  supported today:

  - **Wake-on-LAN** — magic packets sent on one interface are re-emitted on another, so a sender can
    wake a host on a different segment.
  - **multicast DNS (mDNS)** — service discovery traffic is relayed between two interfaces, so clients
    on one segment can discover responders on the other.
  - **Simple Service Discovery Protocol (SSDP)** — UPnP/DLNA discovery traffic is relayed between two
    interfaces, so clients on one segment can find UPnP devices announcing on the other.
  ```

- [ ] **Step 2: Update the Configuration intro to list `[[ssdp]]`**

  The Configuration section opener (README.md lines 113-114) names the entry tables. Add `[[ssdp]]` to the list, mirroring the existing `[[wol]]` / `[[mdns]]` phrasing.

  Replace (old_string):
  ```markdown
  `config.toml` contains optional top-level settings plus at least one reflector entry — a `[[wol]]`
  or `[[mdns]]` table. `log_level` is the only top-level setting:
  ```
  With (new_string):
  ```markdown
  `config.toml` contains optional top-level settings plus at least one reflector entry — a `[[wol]]`,
  `[[mdns]]`, or `[[ssdp]]` table. `log_level` is the only top-level setting:
  ```

- [ ] **Step 3: Add the SSDP subsection after the mDNS subsection**

  The mDNS subsection ends at README.md line 155 (the dedup paragraph), immediately followed by `## Tests` at line 157. Insert the new `### Simple Service Discovery (`[[ssdp]]`)` subsection between them by anchoring on the final mDNS paragraph plus the `## Tests` heading. The prose mirrors the mDNS subsection: a TOML field block, the directional relay description (M-SEARCH source→target / NOTIFY target→source), the groups and port, the `mac` filter on target→source, the address-family note, the dedup rules (no ports), and an honest step-1 scope note about passive NOTIFY discovery vs. active M-SEARCH responses awaiting a unicast-proxy step.

  Replace (old_string):
  ```markdown
  Every mDNS entry name must be unique. Beyond the name, two entries are rejected as duplicates only when they share `source_if`, `target_if`, overlapping MAC selection, and overlapping address-family handling (the same overlap rules as WoL, but without ports — mDNS is always on UDP 5353).

  ## Tests
  ```
  With (new_string):
  ```markdown
  Every mDNS entry name must be unique. Beyond the name, two entries are rejected as duplicates only when they share `source_if`, `target_if`, overlapping MAC selection, and overlapping address-family handling (the same overlap rules as WoL, but without ports — mDNS is always on UDP 5353).

  ### Simple Service Discovery (`[[ssdp]]`)

  ```toml
  [[ssdp]]
  name      = "dlna"               # human-readable label, used in logs
  source_if = "en0"                # interface clients query from (must differ from target_if)
  target_if = "lo0"                # interface the UPnP devices live on
  mac       = "B0:37:95:C5:60:BE"  # optional; restricts the target→source direction to this device
  address_family = "default"       # optional; default | dual | ipv4 | ipv6
  ```

  Reflects SSDP (UDP 1900) between `source_if` and `target_if`, joining the SSDP groups on both. Relaying is directional by the HTTPU request line: `M-SEARCH` discovery requests flow source→target and `NOTIFY` advertisements flow target→source, so clients on `source_if` discover UPnP devices on `target_if` without exposing the `source_if` devices in return. Unlike mDNS, SSDP uses more than one group: the IPv4 group is `239.255.255.250`, and IPv6 uses both the link-local `ff02::c` and the site-local `ff05::c`. Each handled family is reflected on every one of its groups, and reflected datagrams are re-emitted to the same group on port 1900 with a hop limit of 2. No IP addresses appear in the config.

  When `mac` is set, it filters the target→source direction to frames whose L2 source MAC matches it, exposing only that one device on `target_if`; `M-SEARCH` requests source→target are never MAC-filtered. With `mac` omitted, all SSDP traffic is reflected in both directions.

  `address_family` behaves as for mDNS: a handled family must have a source address on **both** interfaces, since the target re-emits relayed searches and the source re-emits relayed advertisements.

  Every SSDP entry name must be unique. Beyond the name, two entries are rejected as duplicates only when they share `source_if`, `target_if`, overlapping MAC selection, and overlapping address-family handling (the same overlap rules as mDNS, without ports — SSDP is always on UDP 1900).

  This step-1 multicast reflection relays the multicast halves of SSDP: passive `NOTIFY` advertisements from `target_if` devices reach `source_if` clients, so devices that announce themselves are discovered. Active `M-SEARCH` discovery, however, expects **unicast** replies sent straight back to the searcher, and those unicast responses are not multicast and so are not reflected here — a `source_if` client that searches will not yet receive answers from `target_if` devices. Bridging the unicast `M-SEARCH` reply path is a later unicast-proxy step.

  ## Tests
  ```

- [ ] **Step 4: Add an `[[ssdp]]` example to the sample config**

  `config.toml` ends with the `[[mdns]]` block (lines 10-14). Append a parallel `[[ssdp]]` block, mirroring the `mac` comment used in the `[[mdns]]` block.

  Replace (old_string):
  ```toml
  [[mdns]]
  name = "cast"
  source_if = "en0"
  target_if = "lo0"
  mac = "B0:37:95:C5:60:BE"  # optional; restricts the target->source direction to this device
  ```
  With (new_string):
  ```toml
  [[mdns]]
  name = "cast"
  source_if = "en0"
  target_if = "lo0"
  mac = "B0:37:95:C5:60:BE"  # optional; restricts the target->source direction to this device

  [[ssdp]]
  name = "dlna"
  source_if = "en0"
  target_if = "lo0"
  mac = "B0:37:95:C5:60:BE"  # optional; restricts the target->source direction to this device
  ```

- [ ] **Step 5: Gate, review, and commit (on permission)**

  Docs-only change: no build or test gate is meaningful here, but per project methodology run the full test gate anyway if any code from sibling SSDP tasks landed in the same batch, then STOP and show the diff for review; commit only after explicit per-batch permission. Run the full test gate (`ctest -L unit` native + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`), then STOP and show the diff for review; commit only after explicit per-batch permission. Do not run `git commit` as an autonomous step.

  Review command + expected output:
  ```sh
  git --no-pager diff -- README.md config.toml
  ```
  Expect exactly the four hunks above: the intro bullet list gaining the SSDP bullet and switching "Two" → "Three", the Configuration opener listing `[[ssdp]]`, the new `### Simple Service Discovery (`[[ssdp]]`)` subsection inserted before `## Tests`, and the `[[ssdp]]` block appended to `config.toml`. No other files change.

---

Notes on what I grounded:
- README intro is a bullet list ("Two protocols are supported today:" at line 6-7 with two `- **...**` bullets), not prose — Step 1 edits that list and the count word.
- The Configuration opener wording is exactly `at least one reflector entry — a \`[[wol]]\` / or \`[[mdns]]\` table.` (lines 113-114); Step 2 matches it verbatim.
- The mDNS subsection uses an em-dash/arrow style (`target→source`, `source→target`), a fenced ```toml``` field block with right-aligned trailing comments, and a final unique-name + dedup paragraph; the SSDP subsection mirrors all of that.
- `config.toml` uses ASCII `->` in its inline comment (`target->source`), not the README's `→`; Step 4 preserves the ASCII form to match the existing sample.
- Files read to mirror style: `/Users/sergii/code/reflector/README.md`, `/Users/sergii/code/reflector/config.toml`.
