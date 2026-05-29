# Unified `[name]` Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three per-protocol config sections (`[[wol]]`/`[[mdns]]`/`[[ssdp]]`) with a single named-entry format where each `[name]` entry enables any combination of the three protocols and shares one `mac`.

**Architecture:** A parsing-layer change only. A new `ReadEntry` parses one `[name]` table and appends to the existing `wol_configs_`/`mdns_configs_`/`ssdp_configs_` vectors via per-protocol `Append*` helpers that reuse the existing `Verify()` + dedup logic. The `WolConfig`/`MdnsConfig`/`SsdpConfig` structs, formatters, dedup helpers, `TestConfigBuilder`, and the entire reflector/`Application`/`ConfigureReflectors` machinery are untouched.

**Tech Stack:** C++23, toml++, GoogleTest, Docker e2e (Python).

**Spec:** `docs/superpowers/specs/2026-05-29-unified-config-design.md`.

**Methodology:** Per-commit — discuss/agree, wait for explicit "go", implement, then STOP and show the diff; commit only on explicit per-batch permission. Each commit runs the full gate (native `ctest -L unit` + `./docker_test.sh` + `./docker_test.sh release` + `python3 e2e/run.py`). Confirm `grep REFLECTOR_SANITIZE build/CMakeCache.txt` is `ON`.

---

## File structure

- `src/reflector/config.cpp` — **remove** `ReadWolConfig`/`ReadWolConfigs`/`ReadMdnsConfig`/`ReadMdnsConfigs`/`ReadSsdpConfig`/`ReadSsdpConfigs`; **add** `ReadEntry` + `AppendWol`/`AppendMdns`/`AppendSsdp`; **rewrite** the `FromString` top-level loop. Keep `ReadStringField`, `ReadPorts`, `AddressFamilyFromString`, `LogLevelFromString`, `MacSelectionsOverlap`, `PortsOverlap`, `AddressFamiliesOverlap`, and all three `Verify()`.
- `src/reflector/config.h` — **unchanged** (structs, accessors, formatters, `ReflectorCount`, `TestConfigBuilder` friend all stay).
- `tests/config_test.cpp` — rewrite the parse cases for the new format.
- `e2e/config.toml`, `config.toml`, `README.md` — rewrite to the unified format (Task 2).

---

### Task 1: Unified entry parsing

**Files:**
- Modify: `src/reflector/config.cpp` (parsing only)
- Test: `tests/config_test.cpp` (rewrite parse cases)

- [ ] **Step 1: Replace the config_test.cpp parse cases with the new format**

Replace every `Config::FromString` parse test (the `[[wol]]`/`[[mdns]]`/`[[ssdp]]` cases) with the cases below. Keep the includes and any non-parse helpers. Each case is `TEST(ConfigTest, <Name>)` wrapping the shown TOML and assertions.

```cpp
TEST(ConfigTest, ParsesSingleProtocolEntry) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    EXPECT_TRUE(config->MdnsConfigs().empty());
    EXPECT_TRUE(config->SsdpConfigs().empty());
    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.name, "tv");
    EXPECT_EQ(wol.source_if, "lan");
    EXPECT_EQ(wol.target_if, "iot");
    EXPECT_FALSE(wol.mac.has_value());
    EXPECT_EQ(wol.ports, (std::vector<uint16_t>{7, 9}));  // default
    EXPECT_EQ(wol.address_family, AddressFamily::Default);
}

TEST(ConfigTest, ExpandsAllThreeProtocolsFromOneEntry) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
mac = "00:11:22:33:44:55"
wol = true
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    ASSERT_EQ(config->WolConfigs().size(), 1);
    ASSERT_EQ(config->MdnsConfigs().size(), 1);
    ASSERT_EQ(config->SsdpConfigs().size(), 1);
    // The one mac flows to all three (device-centric).
    const auto mac = *MacAddress::FromString("00:11:22:33:44:55");
    EXPECT_EQ(config->WolConfigs().front().mac, mac);
    EXPECT_EQ(config->MdnsConfigs().front().mac, mac);
    EXPECT_EQ(config->SsdpConfigs().front().mac, mac);
    EXPECT_EQ(config->WolConfigs().front().name, "tv");
    EXPECT_EQ(config->MdnsConfigs().front().name, "tv");
    EXPECT_EQ(config->SsdpConfigs().front().name, "tv");
}

TEST(ConfigTest, NetworkEntryHasNoMac) {
    const auto config = Config::FromString(R"(
[net]
source_if = "lan"
target_if = "iot"
mdns = true
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_FALSE(config->MdnsConfigs().front().mac.has_value());
    EXPECT_FALSE(config->SsdpConfigs().front().mac.has_value());
}

TEST(ConfigTest, AppliesWolPortsAndAddressFamily) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
wol_ports = [7, 9, 4000]
address_family = "ipv4"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    const auto& wol = config->WolConfigs().front();
    EXPECT_EQ(wol.ports, (std::vector<uint16_t>{7, 9, 4000}));
    EXPECT_EQ(wol.address_family, AddressFamily::IPv4);
}

TEST(ConfigTest, AddressFamilyAppliesToEveryEnabledProtocol) {
    const auto config = Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
mdns = true
address_family = "dual"
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().front().address_family, AddressFamily::Dual);
    EXPECT_EQ(config->MdnsConfigs().front().address_family, AddressFamily::Dual);
}

TEST(ConfigTest, ParsesLogLevelAlongsideEntries) {
    const auto config = Config::FromString(R"(
log_level = "debug"

[tv]
source_if = "lan"
target_if = "iot"
wol = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->MinLogLevel(), LogLevel::Debug);
    EXPECT_EQ(config->WolConfigs().size(), 1);
}

TEST(ConfigTest, RejectsEntryEnablingNoProtocol) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
)").has_value());
}

TEST(ConfigTest, RejectsWolPortsWithoutWol) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
mdns = true
wol_ports = [7, 9]
)").has_value());
}

TEST(ConfigTest, RejectsMissingSourceIf) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
target_if = "iot"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsSameInterfaces) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "lan"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsUnknownEntryField) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
extra = "x"
)").has_value());
}

TEST(ConfigTest, RejectsUnknownTopLevelScalar) {
    EXPECT_FALSE(Config::FromString(R"(
log_levle = "debug"

[tv]
source_if = "lan"
target_if = "iot"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsInvalidMac) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
mac = "not-a-mac"
wol = true
)").has_value());
}

TEST(ConfigTest, RejectsInvalidAddressFamily) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = true
address_family = "ipx"
)").has_value());
}

TEST(ConfigTest, RejectsNonBooleanProtocolFlag) {
    EXPECT_FALSE(Config::FromString(R"(
[tv]
source_if = "lan"
target_if = "iot"
wol = "yes"
)").has_value());
}

TEST(ConfigTest, RejectsEmptyConfig) {
    EXPECT_FALSE(Config::FromString("").has_value());
}

TEST(ConfigTest, RejectsConfigWithOnlyLogLevel) {
    EXPECT_FALSE(Config::FromString(R"(log_level = "info")").has_value());
}

TEST(ConfigTest, RejectsDuplicateMdnsRuleAcrossEntries) {
    // Two entries, same source/target, both unfiltered mdns with overlapping families.
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
mdns = true

[b]
source_if = "lan"
target_if = "iot"
mdns = true
)").has_value());
}

TEST(ConfigTest, RejectsDuplicateWolRuleAcrossEntries) {
    // Same source/target, overlapping ports, both any-MAC.
    EXPECT_FALSE(Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
wol = true

[b]
source_if = "lan"
target_if = "iot"
wol = true
)").has_value());
}

TEST(ConfigTest, AcceptsOverlappingDifferentProtocolsAcrossEntries) {
    // Entry "a" does wol on lan->iot; entry "b" does mdns on lan->iot. Different protocol
    // vectors, so no dedup collision.
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
wol = true

[b]
source_if = "lan"
target_if = "iot"
mdns = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->WolConfigs().size(), 1);
    EXPECT_EQ(config->MdnsConfigs().size(), 1);
}

TEST(ConfigTest, AcceptsDisjointEntries) {
    const auto config = Config::FromString(R"(
[a]
source_if = "lan"
target_if = "iot"
ssdp = true

[b]
source_if = "lan"
target_if = "guest"
ssdp = true
)");
    ASSERT_TRUE(config.has_value()) << config.error().Message();
    EXPECT_EQ(config->SsdpConfigs().size(), 2);
}
```

- [ ] **Step 2: Build and watch the rewritten tests fail**

Run: `cmake --build build`
Expected: `config_test.cpp` still compiles (it only uses `Config::FromString` + the public accessors, which are unchanged), but the tests fail at runtime — the old parser rejects `[tv]` tables as "unexpected configuration section", so the `ASSERT_TRUE(config.has_value())` cases fail. Confirm with:
Run: `ctest --test-dir build -L unit -R ConfigTest --output-on-failure`
Expected: the new positive cases FAIL (config has no value); negative cases may spuriously pass.

- [ ] **Step 3: Add the `AppendWol`/`AppendMdns`/`AppendSsdp` dedup helpers**

In `src/reflector/config.cpp`, inside the anonymous namespace, **after** `AddressFamiliesOverlap` (line ~105) and before the (to-be-removed) `ReadWolConfig`, add. These lift the existing `Verify()` + dedup loops out of the old `ReadXConfigs` so `ReadEntry` can reuse them:

```cpp
std::optional<Error> AppendWol(std::vector<WolConfig>& configs, WolConfig config) {
    if (auto error = config.Verify()) {
        return error;
    }
    for (const auto& existing : configs) {
        if (existing.name == config.name) {
            return Error{"duplicate wol name: \"{}\"", config.name};
        }
        if (MacSelectionsOverlap(existing.mac, config.mac)
                && existing.source_if == config.source_if
                && existing.target_if == config.target_if
                && PortsOverlap(existing.ports, config.ports)
                && AddressFamiliesOverlap(existing.address_family, config.address_family)) {
            return Error{
                "duplicate wol rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, ports, and address family",
                existing.name, config.name};
        }
    }
    configs.push_back(std::move(config));
    return std::nullopt;
}

std::optional<Error> AppendMdns(std::vector<MdnsConfig>& configs, MdnsConfig config) {
    if (auto error = config.Verify()) {
        return error;
    }
    for (const auto& existing : configs) {
        if (existing.name == config.name) {
            return Error{"duplicate mdns name: \"{}\"", config.name};
        }
        if (MacSelectionsOverlap(existing.mac, config.mac)
                && existing.source_if == config.source_if
                && existing.target_if == config.target_if
                && AddressFamiliesOverlap(existing.address_family, config.address_family)) {
            return Error{
                "duplicate mdns rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                existing.name, config.name};
        }
    }
    configs.push_back(std::move(config));
    return std::nullopt;
}

std::optional<Error> AppendSsdp(std::vector<SsdpConfig>& configs, SsdpConfig config) {
    if (auto error = config.Verify()) {
        return error;
    }
    for (const auto& existing : configs) {
        if (existing.name == config.name) {
            return Error{"duplicate ssdp name: \"{}\"", config.name};
        }
        if (MacSelectionsOverlap(existing.mac, config.mac)
                && existing.source_if == config.source_if
                && existing.target_if == config.target_if
                && AddressFamiliesOverlap(existing.address_family, config.address_family)) {
            return Error{
                "duplicate ssdp rule: \"{}\" and \"{}\" have overlapping mac selection, source_if, target_if, and address family",
                existing.name, config.name};
        }
    }
    configs.push_back(std::move(config));
    return std::nullopt;
}
```

- [ ] **Step 4: Add `ReadEntry`**

In `src/reflector/config.cpp`, add after the `Append*` helpers (still in the anonymous namespace). It reads a bool field via `field_node.value<bool>()`:

```cpp
// Reads one [name] entry and appends a reflector config for each protocol it enables.
std::optional<Error> ReadEntry(std::string_view name, const toml::table& table,
        std::vector<WolConfig>& wol_configs, std::vector<MdnsConfig>& mdns_configs,
        std::vector<SsdpConfig>& ssdp_configs) {
    std::string source_if;
    std::string target_if;
    std::optional<MacAddress> mac;
    std::optional<std::vector<uint16_t>> wol_ports;
    bool wol = false;
    bool mdns = false;
    bool ssdp = false;
    AddressFamily address_family = AddressFamily::Default;

    for (const auto& [field_key, field_node] : table) {
        const auto field_name = ToStringView(field_key);
        if (field_name == "source_if") {
            auto value = ReadStringField(field_node, "entry", field_name);
            if (!value.has_value()) {
                return std::move(value).error();
            }
            source_if = *value;
        } else if (field_name == "target_if") {
            auto value = ReadStringField(field_node, "entry", field_name);
            if (!value.has_value()) {
                return std::move(value).error();
            }
            target_if = *value;
        } else if (field_name == "mac") {
            auto value = ReadStringField(field_node, "entry", field_name);
            if (!value.has_value()) {
                return std::move(value).error();
            }
            auto parsed = MacAddress::FromString(*value);
            if (!parsed.has_value()) {
                return Error{"entry \"{}\" mac is not a valid MAC address: \"{}\": {}", name, *value, parsed.error()};
            }
            mac = *parsed;
        } else if (field_name == "wol_ports") {
            auto ports = ReadPorts(field_node);
            if (!ports.has_value()) {
                return std::move(ports).error();
            }
            wol_ports = std::move(*ports);
        } else if (field_name == "wol" || field_name == "mdns" || field_name == "ssdp") {
            const auto flag = field_node.value<bool>();
            if (!flag.has_value()) {
                return Error{"entry \"{}\" {} must be a boolean", name, field_name};
            }
            if (field_name == "wol") {
                wol = *flag;
            } else if (field_name == "mdns") {
                mdns = *flag;
            } else {
                ssdp = *flag;
            }
        } else if (field_name == "address_family") {
            const auto value = field_node.value<std::string_view>();
            if (!value.has_value()) {
                return Error{"entry \"{}\" address_family must be a string", name};
            }
            auto parsed = AddressFamilyFromString("entry", *value);
            if (!parsed.has_value()) {
                return std::move(parsed).error();
            }
            address_family = *parsed;
        } else {
            return Error{"unexpected option in entry \"{}\": {}", name, field_name};
        }
    }

    if (!wol && !mdns && !ssdp) {
        return Error{"entry \"{}\" enables no protocol (set wol, mdns, or ssdp)", name};
    }
    if (wol_ports.has_value() && !wol) {
        return Error{"entry \"{}\" sets wol_ports but does not enable wol", name};
    }

    if (wol) {
        WolConfig config{
            .name = std::string{name},
            .mac = mac,
            .source_if = source_if,
            .target_if = target_if,
            .address_family = address_family,
        };
        if (wol_ports.has_value()) {
            config.ports = *wol_ports;
        }
        if (auto error = AppendWol(wol_configs, std::move(config))) {
            return error;
        }
    }
    if (mdns) {
        if (auto error = AppendMdns(mdns_configs, MdnsConfig{
                .name = std::string{name}, .mac = mac, .source_if = source_if,
                .target_if = target_if, .address_family = address_family})) {
            return error;
        }
    }
    if (ssdp) {
        if (auto error = AppendSsdp(ssdp_configs, SsdpConfig{
                .name = std::string{name}, .mac = mac, .source_if = source_if,
                .target_if = target_if, .address_family = address_family})) {
            return error;
        }
    }
    return std::nullopt;
}
```

- [ ] **Step 5: Remove the six obsolete `ReadXConfig`/`ReadXConfigs` functions**

Delete `ReadWolConfig`, `ReadWolConfigs`, `ReadMdnsConfig`, `ReadMdnsConfigs`, `ReadSsdpConfig`, `ReadSsdpConfigs` from `src/reflector/config.cpp`. (Keep `ReadStringField`, `ReadPorts`, `AddressFamilyFromString`, `LogLevelFromString`, `MacSelectionsOverlap`, `PortsOverlap`, `AddressFamiliesOverlap`, and the three `Verify()` member definitions.)

- [ ] **Step 6: Rewrite the `FromString` top-level loop**

In `src/reflector/config.cpp`, replace the `for (const auto& [key, value] : root_table) { ... }` body (the `wol`/`mdns`/`ssdp`/`log_level`/else dispatch) with:

```cpp
    for (const auto& [key, value] : root_table) {
        const auto key_name = ToStringView(key);
        if (const auto* entry_table = value.as_table()) {
            if (auto error = ReadEntry(key_name, *entry_table,
                    config.wol_configs_, config.mdns_configs_, config.ssdp_configs_)) {
                return std::unexpected(*std::move(error));
            }
        } else if (key_name == "log_level") {
            const auto field_value = value.value<std::string_view>();
            if (!field_value.has_value()) {
                return std::unexpected(Error{"log_level must be a string"});
            }
            auto level = LogLevelFromString(*field_value);
            if (!level.has_value()) {
                return std::unexpected(std::move(level).error());
            }
            config.log_level_ = *level;
        } else {
            return std::unexpected(Error{"unexpected top-level key: \"{}\" (expected an entry table or log_level)", key_name});
        }
    }
```

The `if (config.ReflectorCount() == 0)` check below it is unchanged — it still rejects a config with no enabled reflectors (e.g. only `log_level`).

- [ ] **Step 7: Build and run the config tests**

Run: `cmake --build build && ctest --test-dir build -L unit -R ConfigTest --output-on-failure`
Expected: all rewritten `ConfigTest` cases pass.

- [ ] **Step 8: Full native suite + sanitizer check**

Run: `grep REFLECTOR_SANITIZE build/CMakeCache.txt` → `ON`
Run: `ctest --test-dir build -L unit`
Expected: `100% tests passed`. (The reflector/application/wol/mdns/ssdp reflector tests are unchanged and still pass — they build their configs via `TestConfigBuilder`, not TOML.)

- [ ] **Step 9: Full gate, review, commit on permission**

The e2e `config.toml` still uses the OLD format at this point, so the reflector won't start in e2e — that's why **Task 2 updates e2e/config.toml in the same review batch before the e2e leg is trusted.** Run native + docker debug/release now; defer the e2e run until Task 2's config is in place, then run e2e once for both tasks. STOP and show the `config.cpp` + `config_test.cpp` diff; commit only on explicit permission. Do not `git commit` autonomously.

---

### Task 2: e2e + sample config + README

**Files:**
- Modify: `e2e/config.toml`, `config.toml`, `README.md`

- [ ] **Step 1: Rewrite `e2e/config.toml` to the unified format**

The e2e suite drives WoL (ports 40009 + any-MAC on 40011), mDNS, and SSDP on `wol_src`→`wol_dst`. The current file has two `[[wol]]` entries (one MAC-filtered on 40009, one any-MAC on 40011), one `[[mdns]]`, one `[[ssdp]]`. Express the same reflectors as entries:

```toml
log_level = "debug"

[wol-mac]
source_if = "wol_src"
target_if = "wol_dst"
mac = "02:42:ac:11:00:09"
wol = true
wol_ports = [40009]

[wol-any]
source_if = "wol_src"
target_if = "wol_dst"
wol = true
wol_ports = [40011]

[discovery]
source_if = "wol_src"
target_if = "wol_dst"
mdns = true
ssdp = true
```

This yields the same four reflectors the e2e cases expect: WoL on 40009 (MAC-filtered), WoL on 40011 (any-MAC), mDNS, SSDP — all on `wol_src`→`wol_dst`.

- [ ] **Step 2: Rewrite the sample `config.toml`**

Replace the whole file with a unified example showing a device entry and a network entry:

```toml
# log_level = "info"  # debug | info | warning | error

[tv]
source_if = "en0"
target_if = "lo0"
mac = "B0:37:95:C5:60:BE"  # optional; the device's MAC. Omit for a whole-network entry.
wol = true
wol_ports = [7, 9]         # optional; defaults to [7, 9]. Only valid when wol = true.
mdns = true
ssdp = true

[guest-discovery]
source_if = "en0"
target_if = "lo0"
mdns = true                # network-level (no mac): reflects all mDNS/SSDP both ways
ssdp = true
```

- [ ] **Step 3: Rewrite the README Configuration section**

Replace the three protocol subsections (`### Wake-on-LAN`, `### Multicast DNS`, `### Simple Service Discovery`) and the intro paragraph with: (a) the unified entry format + field table, (b) a short per-protocol behavior reference (relay direction, group/port, what `mac` filters), and (c) the SSDP passive-vs-active note. Update the intro line "at least one reflector entry — a `[[wol]]`, `[[mdns]]`, or `[[ssdp]]` table" to describe `[name]` entries. (Exact prose is drafted during execution and reviewed in the diff.)

- [ ] **Step 4: Validate configs parse and run the full e2e suite**

Run: `python3 e2e/run.py`
Expected: `PASS 22 e2e case(s)` — the reflector starts from the rewritten `e2e/config.toml` and all WoL/mDNS/SSDP cases pass unchanged.

- [ ] **Step 5: Full gate, review, commit on permission**

Native + docker debug/release already green from Task 1; the e2e run above is the new coverage. STOP and show the diff (`e2e/config.toml`, `config.toml`, `README.md`); commit only on explicit permission.

---

## Self-review

- **Spec coverage:** format/parsing (§2) → Task 1 Steps 4,6; expansion/internals (§3) → Step 4 + unchanged structs; validation/dedup (§4) → Steps 3,4 + `ReflectorCount` check; code changes (§5) → Steps 3–6; tests/docs (§6) → Step 1 + Task 2; commits (§7) → Tasks 1,2. ✓
- **Placeholder scan:** README prose in Task 2 Step 3 is described, not pre-written — flagged as drafted-during-execution-and-reviewed, acceptable for free prose (not code). All code steps have complete code.
- **Type consistency:** `AppendWol`/`AppendMdns`/`AppendSsdp` signatures match their calls in `ReadEntry`; `ReadEntry` signature matches its call in `FromString`; field names (`source_if`, `target_if`, `mac`, `wol_ports`, `wol`/`mdns`/`ssdp`, `address_family`) consistent across parser and tests; designated initializers list members in declaration order (`name, mac, source_if, target_if, [ports], address_family`) with `ports` skipped to take its `{7,9}` default. ✓
