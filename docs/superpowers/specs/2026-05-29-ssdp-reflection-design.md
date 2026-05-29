# SSDP reflection — PR3 (step 1, multicast-only)

**Status:** design approved, pending implementation plan
**Date:** 2026-05-29
**Scope:** Step 1 of the 3-step SSDP roadmap (multicast forwarding → unicast proxy → DIAL proxy).
This document covers step 1 only.

## 1. Goal and scope

Add SSDP (UPnP/DLNA Simple Service Discovery Protocol) reflection between two interfaces, as a
third network-level reflector alongside WoL and mDNS. SSDP discovery runs over UDP port 1900 on
multicast group `239.255.255.250` (IPv4) and the scoped `ff0x::c` groups (IPv6). For IPv6 the
reflector handles **two** groups: `ff02::c` (link-local) and `ff05::c` (site-local) — see §3.2.

This builds on the architecture established for mDNS: the `Reflector` base class and the
`Application::ConfigureReflectors<R>` template already exist, so an `SsdpReflector` of the same
shape as `MdnsReflector` plugs in with no wiring changes.

### What step 1 delivers (and does not)

SSDP is **not** an exact mirror of mDNS. mDNS responses are multicast, so reflecting them
target→source works. SSDP's M-SEARCH **response** is a **unicast** `HTTP/1.1 200 OK` sent directly
back to the searcher's source IP:port (UPnP Device Architecture 1.0 §1.2.3). Multicast-only
reflection therefore delivers:

- **Passive discovery, fully.** `NOTIFY ssdp:alive` / `ssdp:byebye` advertisements relayed
  target→source. Devices periodically re-announce (governed by `CACHE-CONTROL: max-age`), so
  source-side clients see target-side devices. This is the primary value of step 1.
- **Active search, incomplete.** An `M-SEARCH` relayed source→target reaches target devices, but
  their unicast `200 OK` cannot cross back to the searcher until **step 2 (unicast proxy)**.

This limitation is inherent to multicast-only reflection and is resolved in step 2. Step 1 relays
M-SEARCH anyway (decision D1 below) so the directional path is in place for step 2 to complete.

## 2. Directionality

- **M-SEARCH** (search request) → relay **source → target**.
- **NOTIFY** (advertisement: `ssdp:alive` / `ssdp:byebye` / `ssdp:update`) → relay
  **target → source**.

`source_if` is where casting clients live; `target_if` is where the renderers/TVs live — the same
orientation as mDNS. The target→source (NOTIFY) direction may be restricted to a single device by
its L2 source MAC via the optional `mac` config field. M-SEARCH (source→target) is never
MAC-filtered.

A datagram whose start line is neither `M-SEARCH` nor `NOTIFY` (e.g. a stray unicast `HTTP/1.1 200
OK` that appears on the group) is logged at INFO and dropped — mirroring the mDNS "non-mDNS packet"
path.

## 3. Components

### 3.1 `ssdp_message.{h,cpp}` — message classification

UPnP Device Architecture 2.0 specifies the SSDP start line **shall be one of exactly three**
literals. Classification matches the leading ASCII token (case-sensitive against the uppercase spec
literals), rather than mDNS's QR bit at a fixed offset:

```cpp
enum class SsdpMessageKind : uint8_t { Search, Advertisement };

// "M-SEARCH " -> Search; "NOTIFY " -> Advertisement; "HTTP/" or anything else -> nullopt.
std::optional<SsdpMessageKind> ClassifySsdpMessage(std::span<const std::byte> payload) noexcept;
```

Returns `nullopt` for any payload that does not begin with a recognized request token (too short,
an `HTTP/` status line, or junk). The classifier inspects only the start line; no header parsing.

### 3.2 `ip_address.{h,cpp}` — group constants

SSDP has a **set** of groups per IPv6 family, unlike mDNS's single group per family. Per UDA Annex
A, `ff02::c` (link-local) is the mandatory baseline and `ff05::c` (site-local) is an optional scope
— both are included here. The accessor returns a list:

```cpp
static IpAddress SsdpGroupV4() noexcept;            // 239.255.255.250
static IpAddress SsdpGroupV6LinkLocal() noexcept;   // ff02::c
static IpAddress SsdpGroupV6SiteLocal() noexcept;   // ff05::c
// V4 -> [239.255.255.250]; V6 -> [ff02::c, ff05::c]
static std::vector<IpAddress> SsdpGroupsFor(Family family);
```

### 3.3 `ssdp_reflector.{h,cpp}` — the reflector

Mirrors `MdnsReflector`: derives from `Reflector`, immovable, validates config, gates address
families (`reflectable` = both sockets `CanSend(family)`; `Requires*` → invalid, `Uses*` → skip).
The one structural difference is the per-family setup loops over the **group list**:

- For each used + reflectable family, **for each group in `SsdpGroupsFor(family)`**:
  - join the group on both `source_socket` and `target_socket`;
  - register source→target filtered to `{dest_ip = group, dest_port = 1900}` → `OnSourcePacket`
    (relays `Search`);
  - register target→source filtered to `{dest_ip = group, dest_port = 1900, source_mac =
    config.mac}` → `OnTargetPacket` (relays `Advertisement`).
- `ShouldRelay(packet, kind)`: classify; `nullopt` → log INFO + drop; else relay iff the kind
  matches the direction.
- `Relay`: re-emit the captured payload verbatim to the same group on port 1900, with
  **TTL/hop-limit reset to 2** (UDA 2.0 default — not mDNS's 255), re-originated fresh rather than
  forwarding the decremented value. Verbatim re-emit preserves MX / `CACHE-CONTROL: max-age` /
  BOOTID semantics (verified against the spec).

Constants: `SSDP_PORT = 1900`, `SSDP_TTL = 2`.

### 3.4 `config.{h,cpp}` — `[[ssdp]]` section

`SsdpConfig` is identical in shape to `MdnsConfig`: `name`, optional `mac`, `source_if`,
`target_if`, `address_family`. Same `Verify()` (non-empty name/source_if/target_if, source ≠
target), same formatter. Parsing mirrors `ReadMdnsConfig` / `ReadMdnsConfigs` as a parallel loop
sharing the existing leaf helpers (`ReadStringField`, `AddressFamilyFromString`,
`MacSelectionsOverlap`, `AddressFamiliesOverlap`). Dedup is identical to mDNS: unique name, plus
rule-dedup on overlapping MAC selection + same `source_if` + same `target_if` + overlapping address
family (no ports — SSDP is always on 1900). `Config` gains `ssdp_configs_`, `SsdpConfigs()`, and
`ReflectorCount() += ssdp_configs_.size()`.

### 3.5 `application.cpp` — wiring

`Configure` extends its short-circuit chain to a third protocol, reusing the existing template:

```cpp
return ConfigureReflectors<WolReflector>(config.WolConfigs(), "wol")
    && ConfigureReflectors<MdnsReflector>(config.MdnsConfigs(), "mdns")
    && ConfigureReflectors<SsdpReflector>(config.SsdpConfigs(), "ssdp");
```

No changes to the template, the transactional rollback, or the `Run` invariant assert. Sockets are
shared per-interface across all three protocols via `GetOrCreateSocket`.

## 4. Loop prevention

The existing direction-based mechanism (Linux `PACKET_IGNORE_OUTGOING`, macOS `BIOCSSEESENT=0`) is
sufficient, because it gates on capture direction rather than source IP — confirmed adequate for
SSDP multicast reflection. The `dest_ip = group` PacketFilter additionally restricts captured
traffic to the relevant group, so unicast traffic to the reflector (including the unicast M-SEARCH
variant and unicast 200 OK responses) is not picked up in step 1.

## 5. Testing

### Unit (`tests/ssdp_message_test.cpp`, `tests/ssdp_reflector_test.cpp`)

Mirror the mDNS tests:
- Classification: `M-SEARCH`/`NOTIFY` start lines → correct kind; `HTTP/` and junk/short → nullopt.
- Validity and family gating (Requires → invalid, Uses → skip; both-socket `CanSend`).
- Group joins on **both** sockets for **every** group in the family set.
- Registration counts: IPv4 = 2, IPv6 = 4 (2 groups × 2 directions), Dual = 6; rollback on failure.
- Directional relay: `Search` source→target, `Advertisement` target→source; wrong-direction drop;
  MAC filter on target→source.
- Re-emit fields: same group, port 1900, TTL forced to 2.
- Malformed/`HTTP/`-on-group logged and dropped.
- Destructor unregisters.

### Application (`tests/application_test.cpp`)

Add SSDP cases mirroring the mDNS ones: wired on both interfaces (count + registrations), socket
sharing across protocols, source/target socket-invalid failures, reflector-setup failure,
cross-protocol fail-fast/rollback.

### e2e (`e2e/run.py`, `e2e/config.toml`, `e2e/probe.py`)

Add an `[[ssdp]]` config entry and cases with ASCII payloads (`M-SEARCH * HTTP/1.1\r\n...`,
`NOTIFY * HTTP/1.1\r\n...`):
- `reflects_ssdp_msearch` (source→target, v4) + IPv6 twin.
- `reflects_ssdp_notify` (target→source, v4) + IPv6 twin.
- Wrong-direction drops (M-SEARCH in NOTIFY direction; NOTIFY in M-SEARCH direction), v4.
- `HTTP/1.1 200 OK`-on-group drop.

The probe already supports multicast send / group join / `--expect-payload-hex` from the mDNS work;
SSDP reuses them with ASCII payloads and group 239.255.255.250 / ff02::c. The IPv6 twins use the
link-local group `ff02::c`; the site-local group `ff05::c` is exercised by the unit/registration
tests rather than e2e (a Docker bridge is a single link, so link-local already covers the e2e
path). Port 1900.

## 6. Commit breakdown (mirrors PR2)

1. `ip_address`: SSDP group constants + `SsdpGroupsFor` (+ tests)
2. `ssdp_message`: classifier + tests
3. `config`: `[[ssdp]]` section, Verify, dedup, formatter + tests
4. `ssdp_reflector`: the reflector + tests
5. `application`: wire `SsdpReflector` + tests
6. `e2e`: SSDP cases
7. `docs`: README `[[ssdp]]` section + sample config entry

Each commit follows the project's full-gate methodology before committing (native unit + docker
debug/release + e2e for the data-path commits), per the established workflow.

## 7. Decisions

- **D1 — Relay both directions in step 1.** Register M-SEARCH (source→target) and NOTIFY
  (target→source), mirroring mDNS. The M-SEARCH relay is harmless and forward-compatible: step 2's
  unicast proxy bolts the return path onto an already-wired path, and the code stays a uniform
  mirror of the other reflectors. (Alternative considered: NOTIFY-only now — rejected as it makes
  `SsdpReflector` asymmetric and diverges from the template.)
- **D2 — Re-emit TTL = 2.** The UPnP Device Architecture 2.0 recommended default; reaches the local
  target segment without leaking beyond intended scope. Reset fresh, not forwarded-decremented.
- **D3 — Handle both IPv6 groups.** `ff02::c` (mandatory) and `ff05::c` (optional site-local). The
  group accessor returns a per-family list and the reflector loops over it.
- **D4 — Keep the optional `mac` filter** on the target→source (NOTIFY) direction, as in mDNS.

## 8. Out of scope (later steps)

- **Step 2 — unicast M-SEARCH response proxy.** Source-IP/port rewrite + tracked mapping
  (UDP-NAT-like) + unicast capture on `target_if`, to bridge the `200 OK` back to the searcher.
  Enabled by default once implemented.
- **Step 3 — DIAL proxy.** HTTP/TCP proxy for the DIAL REST endpoint (LG TV accepts DIAL only from
  its own subnet). Architecturally distinct from the UDP-multicast L2 reflector; warrants its own
  design pass and possibly its own config section.
