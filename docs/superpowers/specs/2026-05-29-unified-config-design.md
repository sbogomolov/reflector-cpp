# Unified `[name]` configuration

**Status:** design approved, pending implementation plan
**Date:** 2026-05-29
**Supersedes:** the three per-protocol config sections (`[[wol]]`, `[[mdns]]`, `[[ssdp]]`). This was
originally deferred as the device-centric "PR4" after SSDP.

## 1. Goal

Replace the three separate per-protocol array-of-tables sections with a single named-entry format.
One entry describes a source→target bridge and enables any combination of the three protocols, so
the same shape serves a single device (with `mac`) or a whole network (`mac` omitted).

The unification is coherent because, for a real single-NIC device, the one `mac` plays every role:
it is the WoL magic-packet target MAC, and it is the L2 source MAC of that device's mDNS and SSDP
advertisements (the frame-source filter on the target→source direction). One `mac` field = "this
device"; omitting it = "any device on the network".

## 2. Config format

Top-level **tables** are entries (the table name is the entry name). The scalar `log_level` remains
the one top-level setting. Any other top-level scalar is an error (so a mistyped setting is still
caught). Entry names are free-form, so an entry-name typo cannot be detected — that is inherent to
named entries and accepted.

```toml
log_level = "info"            # optional; debug | info | warning | error (default: info)

[tv]
source_if = "en0"             # required; interface to listen on (must differ from target_if)
target_if = "lo0"             # required; interface to emit reflected traffic on
mac = "B0:37:95:C5:60:BE"     # optional; the device's MAC (see §1). Omitted = whole network.
wol_ports = [7, 9]            # optional; WoL UDP ports (default [7, 9]). Only valid when wol = true.
wol = true                    # optional; default false
mdns = true                   # optional; default false
ssdp = true                   # optional; default false
address_family = "default"    # optional; default | dual | ipv4 | ipv6 (default "default")
```

### Field rules

- **Enable flags** (`wol`/`mdns`/`ssdp`) are TOML booleans (`true`/`false`). Omitted = `false`. At
  least one must be `true`, else the entry is an error (a no-op entry is a mistake).
- **`mac`** optional. When set, it is the device MAC: WoL re-emits only magic packets targeting it,
  and mDNS/SSDP relay target→source only frames whose L2 source MAC matches it. When omitted, WoL
  proxies any magic packet and mDNS/SSDP relay unfiltered.
- **`wol_ports`** optional, default `[7, 9]`. It is an **error** to set `wol_ports` when `wol` is
  not enabled (catches a likely mistake rather than silently ignoring it).
- **`address_family`** optional, default `"default"`, applies to every protocol the entry enables.
- **`source_if`/`target_if`** required and must differ (existing per-protocol `Verify` rule).

## 3. Expansion and internals

Each entry expands into up to three of the existing `WolConfig` / `MdnsConfig` / `SsdpConfig`, one
per enabled protocol, each carrying the entry's `name`, `source_if`, `target_if`, `mac`, and
`address_family` (WoL additionally carries `wol_ports`). The internal `Config` keeps its three
vectors (`wol_configs_`, `mdns_configs_`, `ssdp_configs_`).

**Unchanged:** the `WolConfig`/`MdnsConfig`/`SsdpConfig` structs, their `Verify()`, the per-protocol
formatters, the dedup helpers (`MacSelectionsOverlap`, `AddressFamiliesOverlap`), `TestConfigBuilder`,
and the entire reflector / `Application` / `ConfigureReflectors` machinery. This is a config
parsing-layer change only.

## 4. Validation and dedup

After expansion, run the existing per-protocol `Verify()` and dedup on each vector. So two entries
that both enable WoL with overlapping mac × source_if × target_if × ports collide on the WoL dedup
rule, exactly as today; mDNS/SSDP likewise (no ports). The whole-config "at least one reflector"
check still applies (≥1 entry enabling ≥1 protocol).

Entry order is preserved within each protocol vector, so dedup and logs read in file order. The
entry name becomes each spawned reflector's name (logger `WolReflector:<name>:…`, etc.).

## 5. Code changes

Confined to `config.{h,cpp}`:

- Replace `ReadWolConfig`/`ReadWolConfigs`/`ReadMdnsConfig`/`ReadMdnsConfigs`/`ReadSsdpConfig`/
  `ReadSsdpConfigs` and the `FromString` section dispatch with a single `ReadEntry(name, table)`
  that parses one entry and appends to the three vectors, plus a top-level loop that classifies each
  root key as an entry table, the `log_level` scalar, or an error.
- Keep the structs, `Verify()`, formatters, dedup helpers, and `Config` accessors.

## 6. Tests and docs

- **`config_test.cpp`** — rewrite the parse cases for the new format: single-protocol entry,
  multi-protocol entry (expands to N reflectors), network entry (no mac) vs device entry (mac),
  `wol_ports` default and the wol-disabled-with-ports error, at-least-one-protocol error, unknown
  field error, unknown top-level scalar error, per-protocol dedup across entries, disjoint entries
  coexist, all-three-protocols-together. The existing per-protocol `Verify`/dedup unit coverage is
  unchanged (those functions don't change).
- **`e2e/config.toml`**, sample **`config.toml`** — rewrite into the unified format.
- **`README.md`** — collapse the three Configuration subsections into one entry format plus a
  per-protocol behavior reference (relay direction, groups/ports, mac meaning) and the SSDP
  passive-vs-active note.

## 7. Commit breakdown

1. **config**: unified `[name]` parsing (`ReadEntry` + top-level loop), reusing the structs/Verify/
   dedup; rewrite `config_test.cpp`. Full gate (the parse logic is the contract; native + docker).
2. **e2e + docs**: rewrite `e2e/config.toml`, sample `config.toml`, README; run the e2e suite.

## 8. Out of scope

SSDP steps 2 (unicast M-SEARCH response proxy) and 3 (DIAL proxy) — unchanged by this; they consume
the same internal `SsdpConfig`.
