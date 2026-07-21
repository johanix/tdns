# Transport Selection Policy for the IMR

**Date**: 2026-06-12
**Status**: DESIGN + IMPLEMENTATION PLAN
**Component**: tdns-imr resolver (`tdns/v2`)

Supersedes the reasoning in (kept for the trail, marked superseded):
- `tdns-project/docs/2026-06-12-part3-ds-transport-signaling.md`
- `tdns-project/docs/2026-06-12-dnskey-transport-upgrade-analysis.md`
- `tdns-project/docs/2026-06-12-dnskey-probabilistic-bypass-summary.md`

---

## 1. Motivation

Three forces converge on "which transport should the IMR use for an
outgoing query":

1. **Large responses.** Post-quantum DNSKEY RRsets exceed the ~1232-byte
   UDP ceiling; we want them off UDP to avoid truncate-then-retry. This
   is draft-johani-dnsop-dnssec-alg-split Part 3.

2. **Privacy.** An end user (stub) may want the IMR's upstream queries
   carried over an encrypted transport (DoT/DoQ). Today this is the PR
   (Privacy Requested) EDNS(0) flag, bit 12.

3. **Server-advertised capability.** Auth servers signal which
   transports they support (and at what weights) via SVCB/TSYNC. The IMR
   distributes queries across those transports.

The current code expresses these with two separate, blunt mechanisms:

- `requireEncrypted bool` — threaded through the whole resolution path,
  sourced from the PR flag. All-or-nothing: "encrypted only, or
  SERVFAIL".
- `dnskeyTransport` enum (added 2026-06-12) — DNSKEY-specific, four
  values, bypasses probabilistic selection.

These overlap (`force_encrypted` in the DNSKEY enum is the same
capability as `requireEncrypted`) and they are spelled differently. The
large-response intent and the privacy intent **want different
fallbacks** (TCP vs UDP), which neither mechanism captures.

This document unifies them into one **transport-selection policy** that
applies to any qtype, composes cleanly with a per-query end-user signal,
and leaves room for a future richer signal (EDNS(0) option).

---

## 2. The policy vocabulary

A single enum, `TransportPolicy`, with six values:

| value | consults signals | prefers encrypted | fallback floor | forbids |
|-------|:---------------:|:----------------:|:--------------:|---------|
| `none` | no | no | UDP/53 | (nothing) — ignores discovered transports entirely |
| `use_transport_signal` | yes | no (weighted) | UDP | — |
| `use_ds_signal` | yes | (meta) | (escalates) | — |
| `encrypted_or_udp` | yes | yes | **UDP** | — |
| `encrypted_or_tcp` | yes | yes | **TCP** | UDP |
| `encrypted_or_fail` | yes | yes | (none) | UDP **and** TCP |

Two of these are *decision rules* ("meta" values), the rest are
*targets*:

- **`none`** — apply no policy. Ignore SVCB/TSYNC-discovered transports;
  query plain UDP/53 (with the intrinsic TC→TCP fallback that Do53
  always has). This is the deliberate opt-out and, crucially, the
  **measurement control arm** (see §5).

- **`use_transport_signal`** — honor the server's advertised transports,
  distributed by whatever mechanism the IMR currently implements
  (today: deterministic weighted hash per qname; tomorrow possibly
  query-count or byte-count based — the policy name names the *intent*,
  not the mechanism). This reproduces today's default behavior.

- **`use_ds_signal`** — DNSKEY-specific meta-value: if the cached parent
  DS uses a large algorithm (`dnssec.large_algorithms`), escalate this
  query to `encrypted_or_tcp`; otherwise behave as
  `use_transport_signal`.

- **`encrypted_or_udp`** — prefer an encrypted transport; if none is
  available, fall back all the way to UDP. Best-effort privacy:
  availability wins over privacy. This is the right *default-level*
  choice for a privacy-leaning resolver.

- **`encrypted_or_tcp`** — prefer an encrypted transport; if none is
  available, fall back to TCP, but **never UDP**. This is the
  large-response floor: the whole point is to escape UDP truncation, so
  UDP is not an acceptable fallback even when encryption is unavailable.

- **`encrypted_or_fail`** — encrypted transport or nothing: if the
  server advertises no encrypted transport, fail the query with
  SERVFAIL + EDE `EDEPrivacyRequestedUnavailable`. This is exactly
  today's `requireEncrypted == true` behavior.

### Why `try_encrypted` was split

An earlier iteration had a single `try_encrypted` with an implicit
fallback. It conflated two distinct intents that want **opposite**
fallbacks:

- privacy (best-effort) → fall back to **UDP** (`encrypted_or_udp`)
- large-response → fall back to **TCP**, never UDP (`encrypted_or_tcp`)

Naming the fallback target in the value removes the ambiguity at the
point of configuration.

---

## 3. Config schema

```yaml
transport_selection:
   default: use_transport_signal   # IMR's disposition absent a per-query signal
   dnskey:  use_ds_signal          # qtype override: large DS → encrypted_or_tcp
   # future: key: ..., tlsa: ..., etc.
```

Resolution of the **config policy** for a query of type Q:

1. If `transport_selection.<qtype>` is set for Q, use it.
2. Else use `transport_selection.default`.
3. If neither is set, the default is `use_transport_signal` (today's
   behavior, backward compatible).

**Allowed values per level:**

- `default` and per-qtype keys: `none`, `use_transport_signal`,
  `encrypted_or_udp`, `encrypted_or_tcp`, `encrypted_or_fail`.
- per-qtype keys additionally: `use_ds_signal` (only meaningful for
  qtypes whose parent publishes a DS — in practice DNSKEY). Rejected
  at parse time under `default`.

### Migration from the current keys

The `dnssec.large_algorithms` list stays (it is what `use_ds_signal`
consults). The `dnssec.dnskey_query_transport` key added earlier today
is **renamed and relocated** into `transport_selection.dnskey`, with the
value vocabulary updated:

| old `dnssec.dnskey_query_transport` | new `transport_selection.dnskey` |
|-------------------------------------|----------------------------------|
| `force_udp` | `use_transport_signal` (or `none` to ignore signals) |
| `use_ds_signal` | `use_ds_signal` |
| `try_encrypted` | `encrypted_or_tcp` (DNSKEY wants TCP floor) |
| `force_encrypted` | `encrypted_or_fail` |

Per project policy (no backwards compatibility, operator migrates own
config): the old key is removed, not dual-parsed.

---

## 4. Composition with the per-query end-user signal

The config policy is the IMR's disposition **in the absence of** an
explicit per-query signal. A present signal (today: PR flag; tomorrow:
an EDNS(0) option) can only **raise the bar for that query, never lower
it**. The IMR issues queries on behalf of the end user; ignoring a
signalled requirement makes no sense, but a stub also cannot ask the IMR
to be *less* careful than its configured floor.

Model the effective policy on **two independent axes** rather than one
linear lattice (because `encrypted_or_udp` and `encrypted_or_tcp` are
not comparable on a single "strictness" scale):

- **encryption requirement** ∈ {none, prefer, require}
  - `none`/`use_transport_signal` → none
  - `encrypted_or_udp`/`encrypted_or_tcp` → prefer
  - `encrypted_or_fail` → require
- **UDP allowed** ∈ {yes, no}
  - `none`/`use_transport_signal`/`encrypted_or_udp` → yes
  - `encrypted_or_tcp`/`encrypted_or_fail` → no

A signal raises an axis; it never lowers it. The effective policy is
recomposed from the raised axes:

| encryption req. | UDP allowed | effective policy |
|-----------------|-------------|------------------|
| none | yes | (config as-is: none / use_transport_signal) |
| prefer | yes | encrypted_or_udp |
| prefer | no | encrypted_or_tcp |
| require | (n/a) | encrypted_or_fail |

`use_ds_signal` is resolved to its target (`encrypted_or_tcp` on large
DS, else `use_transport_signal`) **before** composition, so the signal
composes against the resolved target.

### Worked examples

- Config `default: encrypted_or_udp`, query arrives with a privacy
  "force" signal → encryption axis raised none→require →
  **`encrypted_or_fail`** for that query.
- Config `dnskey: use_ds_signal`, large parent DS → resolves to
  `encrypted_or_tcp` (UDP-forbidden). Same query *also* carries a "force"
  signal → encryption axis raised prefer→require, UDP-forbidden already
  set → **`encrypted_or_fail`**.
- Config `default: none`, query with a privacy "force" signal →
  baseline `none` is overridable; encryption axis raised →
  **`encrypted_or_fail`**. (`none` governs the IMR's own disposition,
  not its obedience to an explicit request.)
- Config `default: encrypted_or_fail`, query with **no** signal → stays
  `encrypted_or_fail` (config floor; signal absence cannot lower it).

### Today's signal mapping (PR flag)

The PR flag is a single bit: present means "encrypted required, no
cleartext fallback". So today:

- `PR == true` → signal contributes **encryption=require**.
- `PR == false` → no signal contribution.

This reproduces current behavior exactly (PR → `encrypted_or_fail`).
When the richer EDNS(0) option lands (able to express
prefer-with-fallback, choose UDP vs TCP floor, etc.), only the
"decode signal → axis contributions" step changes; the composition and
resolution machinery is untouched.

---

## 5. `none` as the measurement control arm

`none` is not merely a debug escape hatch — it is the **A/B control**
for proving the whole feature works. Run the IMR with
`default: none` for a window and record (UDP query count, truncations).
Then run with `use_transport_signal` + `use_ds_signal` and record
(truncations, DoT/DoQ counts). The hypothesis the feature exists to
validate:

```
truncations(policy)  <<  truncations(none)
DoT/DoQ(policy)       >>  0
```

This pairs with the existing large-KSK counters
(`tdns-cli imr stats large-ksk`: DS-encountered, DNSKEY-lookups,
bypassed). Because `none` must produce a clean baseline, it has to
**genuinely suppress** discovered transports (query UDP/53 even when the
server is known to speak DoT), not merely "not prefer" them.

Implication: `none` is a real branch in `candidateTransports` /
`prioritizeServers`, not just "encryption not required".

---

## 6. Implementation plan

The guiding principle is **preserve-then-generalize**: keep current
behavior bit-exact at each step, introduce the enum alongside the
existing `requireEncrypted bool`, derive the bool from the enum, then
remove the bool once every consumer reads the enum. Build + test green
at every step.

### Step 0 — Vocabulary + config (no behavior change)

- Define `TransportPolicy` (string enum) + the six constants. Rename the
  existing `DNSKEYTransportPolicy` type to `TransportPolicy`; keep the
  DNSKEY constants but rename to the new vocabulary
  (`encrypted_or_tcp`, `encrypted_or_fail`, `use_ds_signal`,
  `use_transport_signal`, `encrypted_or_udp`, `none`).
- Predicate methods on the enum (the lattice lives here, nowhere else):
  - `ConsultsSignals() bool` — false only for `none`.
  - `PrefersEncrypted() bool` — true for the three `encrypted_or_*`.
  - `RequiresEncrypted() bool` — true only for `encrypted_or_fail`.
  - `AllowsUDP() bool` — false for `encrypted_or_tcp`, `encrypted_or_fail`.
  - `AllowsCleartextFallback() bool` — false only for `encrypted_or_fail`.
- New config struct `TransportSelectionConf { Default string; Dnskey string; ... }`
  under `Config` (top-level `transport_selection:`).
- `parseTransportPolicy(string) (TransportPolicy, error)` +
  per-level validation (`use_ds_signal` rejected under `default`).
- Derived `Internal.TransportSelection` holding resolved
  `map[uint16]TransportPolicy` (per-qtype) + a default.
- Remove `dnssec.dnskey_query_transport`; move semantics to
  `transport_selection.dnskey`.
- **Verify**: config round-trips; `parseTransportPolicy` unit tests for
  all six values, default, bad value, `use_ds_signal`-under-default
  rejection.

### Step 1 — Per-query effective-policy chokepoint

- `effectivePolicy(qname string, qtype uint16, signal SignalReq) TransportPolicy`:
  1. config policy = lookup(qtype) else default.
  2. if `use_ds_signal`: resolve to `encrypted_or_tcp` (large cached DS)
     or `use_transport_signal`.
  3. compose with `signal` on the two axes (§4); recompose to a value.
- `SignalReq` decoded from `msgoptions`: today `PR==true →
  {encryption: require}`. One decode function, isolated.
- **Verify**: table-driven test of the §4 composition matrix, including
  the four worked examples.

### Step 2 — Wire the enum into resolution (alongside the bool)

- Change `IterativeDNSQuery` / `IterativeDNSQueryWithLoopDetection` /
  `prioritizeServers` / `candidateTransports` to accept a
  `TransportPolicy` instead of (or initially in addition to)
  `requireEncrypted bool`.
- Transitional: compute `requireEncrypted := policy.RequiresEncrypted()`
  and leave existing downstream checks untouched. This keeps the diff
  small and behavior identical while the signature changes propagate.
- `candidateTransports`:
  - `none` → `[Do53]` only, ignore `server.Transports`.
  - `PrefersEncrypted()` → encrypted tuples first; UDP tuple included
    only if `AllowsUDP()`, TCP tuple included if `!AllowsUDP()` and
    `AllowsCleartextFallback()`.
  - `RequiresEncrypted()` → encrypted tuples only (today's
    `requireEncrypted` filter).
  - else (`use_transport_signal`) → unchanged weighted behavior.
- **Verify**: existing `prioritizeServers`/`candidateTransports` tests
  still pass; add cases for `none`, `encrypted_or_udp`,
  `encrypted_or_tcp`.

### Step 3 — Fold DNSKEY bypass into the unified path

- Replace `dnskeyTransportBypass` / `preferredDNSKEYTransport` usage in
  `tryServer` with the policy resolved by `effectivePolicy`. The
  "bypass probabilistic weights for DNSKEY" behavior becomes: when the
  effective policy is `encrypted_or_tcp`/`encrypted_or_fail`, the tuple
  generation already excludes UDP and prefers encrypted — no separate
  bypass needed. Keep the per-(addr,transport) dedup.
- Keep telemetry (`noteDSEncountered`, `noteDNSKEYLookup`,
  large-ksk counters) — rename "forcedTCP" counter to "bypassed" /
  "off-udp" to match the generalized meaning.
- **Verify**: the DNSKEY tests from earlier today, adapted to the new
  vocabulary; large-DS query still goes off-UDP.

### Step 4 — Retire `requireEncrypted bool`

- Once every consumer reads the policy, remove the transitional bool and
  the `requireEncrypted` parameter. Cache-admission checks (skip cached
  data that arrived over cleartext) read
  `policy.RequiresEncrypted()` (or `!AllowsCleartextFallback()`)
  instead.
- **Verify**: full `tdns/v2` test suite (minus the two pre-existing
  `TestGlobalStuffValidate*` URL failures); manual `dog`/`tdns-cli`
  sanity against a lab IMR if available.

### Step 5 — Sample config + docs

- Update `cmdv2/imr/tdns-imr.sample.yaml`: replace the `dnssec`
  `dnskey_query_transport` block with a `transport_selection:` block,
  documenting all six values and the default.
- Mark the three superseded docs with a "superseded by this doc" note.
- Update memory file `project_part3_ds_signaling.md`.

### Risk notes

- `requireEncrypted` touches ~15 sites incl. cache admission; Step 4 is
  the riskiest. Preserve-then-generalize keeps each step behavior-exact.
- `none` must be a genuine branch (suppress discovered transports), or
  the measurement baseline is invalid (§5).
- The two-axis composition (not a linear lattice) is the subtle part;
  Step 1's table-driven test is the guard.

---

## 7. Open questions (none blocking)

- A future EDNS(0) privacy option's exact wire format and how it encodes
  prefer-vs-require and UDP-vs-TCP floor — out of scope here; the
  `SignalReq` decode chokepoint isolates it.
- Whether other qtypes (KEY, TLSA) want their own `transport_selection`
  entries in practice — the schema allows it; we add them when a use
  case appears.
