# Snapshot-branch findings from live reload testing (2026-07-14)

**Context:** live bring-up of the `test reload` tdns-debug family against the
running snapshot-branch `tdns-auth` (the merge gate). Several findings emerged,
some real bugs, some design decisions. Captured here so they survive.

Server: snapshot-branch build, DNS 127.0.0.1:5354, API 127.0.0.1:8989, zones in
`/etc/tdns/auth-zones.yaml`, DNSSEC policies in `/etc/tdns/tdns-auth.yaml`.

---

## Finding 1 — a signing failure is silently masked (query-signed, AXFR-unsigned)

**Symptom:** a zone (`test002`) served **signed** answers to queries (every
`+dnssec` query returned RRSIGs) but its **AXFR carried the DNSKEY and zero
RRSIGs** — the transferred zone was unsigned, at the same serial. A secondary
would AXFR it and serve BOGUS.

**Root cause (this instance, partly self-inflicted):** `test002` was created
under `pq-sqisign` (MAYO5 KSK + SQISIGN1 ZSK), then its config policy was edited
to `pq-mldsa` (MLDSA44). MLDSA44 ≠ MAYO5, so signing now needs a **KSK
algorithm rollover** — which is *"not yet built"*. `SignZone` therefore fails on
every attempt (`zone_utils.go:1104`: *"KSK algorithm rollover not implemented …
active KSK is MAYO5, policy wants MLDSA44"*), so **no RRSIGs are ever stored**.

**Why queries still look signed:** the query path online-signs **ephemerally**.
`signedApexRRsets` is explicitly *"without mutating zone data"*
(`queryresponder.go:92`) and `signRRsetForZone` signs a by-value copy and
discards it (`queryresponder.go:135`) — so the snapshot is **not** mutated (the
C1 read-only invariant holds, good). But the fallback at
`queryresponder.go:141` ephemerally signs **any** stored RRset that lacks
RRSIGs, using whatever active keys exist (here the leftover SQISIGN1 ZSK). So a
zone that cannot be signed still *appears* signed to every DO query, while AXFR
exposes the truth.

**Net:** a genuine, insidious gap — a broken (unsignable) zone looks healthy to
queries, healthy in `config status`, and only reveals itself via AXFR or a
validating secondary.

### Decision 1 (Johan): SERVFAIL, not ephemeral-sign, not serve-unsigned

If a zone **must** be signed (online/inline-signing configured) and the served
RRset has **no** signatures in the snapshot, the zone is broken and the correct
response is **SERVFAIL**. Both current behaviours are wrong: ephemeral-signing
masks the failure; serving unsigned is a silent downgrade. Remove the blanket
ephemeral-sign fallback; scope any *genuinely* ephemeral cases (e.g. CDE)
explicitly. A broken zone must look broken.

---

## Finding 2 — config-reload is not transactional on a failed policy change

Changing a zone's DNSSEC policy via the **`set-policy`/`change-policy` command**
IS transactional (`apihandler_zone.go:405-420`): apply new → re-sign → on
failure **revert to the old policy** and error; on success persist a per-zone
override (`SetZonePolicyOverride`, `ZonePolicyOverride` DB table,
`db_schema.go:182`).

But changing the policy via a **config-file edit + reload** takes the
config-reload path (`parseconfig.go:966`), which applies the new policy, calls
`SetupZoneSigning`, and on failure merely logs *"SetupZoneSigning failed on
reload"* and **moves on** — no revert, no transactionality. The zone is left
bound to the new, unusable policy with no stored signatures (Finding 1).

### Decision 2 (Johan): make reload transactional; persist the effective policy

- **Persist the effective DNSSEC policy for every signed zone** in the DB (reuse
  / extend the `ZonePolicyOverride` mechanism so it is not limited to
  command-set changes). The operator's *intent* is the policy; **do not infer
  the "current" policy from whatever keys happen to be in the keystore** — a
  keystore can hold retired/multiple-alg keys while the policy is a single
  operator choice.
- **At load (reload and restart): compare config-policy vs stored-policy.** If
  they differ, that is an algorithm rollover — route it through the (unbuilt)
  auto-rollover engine, or refuse the switch and **keep the previously effective
  policy**, rather than silently applying an unusable one.
- **On an unapplicable change: keep the working state and raise a warning** (see
  Decision 3). On reload the old policy is still in memory; with the persisted
  policy this also works across restart.

---

## Decision 3 (deferred) — surface signing/policy errors on the zone

The warning/error for a rejected policy change, and for signing failures
generally (Finding 1, and the falcon/qruov codepoint issues), is the same
work: a non-service-impacting error/warning set on the zone and surfaced in
`config status` instead of a swallowed log line. This is the separate
signing-error design doc (the other agent's), to be undertaken **after the
snapshot branch merges** (avoids a competing `SetError` redesign vs the
snapshot branch's — see the branch-strategy note in
`[[falcon-codepoint-renumber-orphan]]`).

---

## Finding 3 — reload-storm deadlock (OPEN — awaiting goroutine dump)

Under a storm of ~11 concurrent `config reload` / `reload-zones` operations
(operator reload racing tool-driven reloads) while the PQ zones were re-signing,
the daemon **deadlocked**: no log activity for minutes, `zone list` blocked on a
held lock, DNS queries still answered. A `daemon restart` cleared it (no dump
captured — the daemon's stderr was `/dev/null`; the Go `SIGQUIT` dump was lost).

**CONFIRMED 2026-07-14 (goroutine dump `/tmp/tdns-auth.sigquit2.txt`, 448
goroutines, 200 blocked on `sync.Mutex.Lock`):** it is a **re-entrant `zd.mu`
self-deadlock** — the same *class* as the fixed `SignZone` deadlock (6e090a9),
a NEW instance. Root goroutine holds `zd.mu` and tries to re-lock it:

```
RefreshEngine → initialLoadZone → Refresh → FetchFromFile
  → applyRefreshReplacementLocked          (zd.mu HELD from here down)
    → publishWorkingSetLocked
      → resignWorkingSetSOAIfSigned
        → SignRRset
          → EnsureActiveDnssecKeys
            → PublishDnskeyRRs
              → zd.mu.Lock()               ← re-entrant → deadlock
```

Dominoes: `ParseZones` (holding `confMu`) then blocks on that same `zd.mu`; the
~200 reload handlers pile up on `confMu` at `ReloadConfig` (config.go:562). One
self-deadlocked goroutine wedges the whole daemon.

**Trigger:** a refresh/initial-load that re-signs during publish AND hits the
DNSKEY-publish branch (fresh keys) — test003's initial SQISIGN load did exactly
that. The concurrent-reload storm only made it *visible* as a mass pile-up; the
self-deadlock itself is deterministic once that path is reached.

**Fix:** route the publish-resign path through the `*Locked` variants
(`publishDnskeyRRsLocked` already exists and is what `SignZone` uses) so
`EnsureActiveDnssecKeys`/`PublishDnskeyRRs` don't re-lock a held `zd.mu`.

**Broader:** this is instance #2 of the "a `zd.mu`-holding `*Locked` path calls
a method that re-locks `zd.mu`" class. A **systematic audit** of that class
(grep every lock-holding path for calls into `zd.mu`-locking methods) belongs in
landing the snapshot branch — there may be a #3.

---

## Finding 4 — `confMu` is held across zone signing on reload (contention/serialization; NOT a deadlock)

Distinct from Finding 3 (the deadlock, now fixed): even with no deadlock, the
config mutex `confMu` is held across potentially long-lived signing on every
`config reload-zones`, so slow PQ signing serialises **all** config operations.

**Lock scope.** Both reload entry points hold `confMu` for their entire body:
- `config reload` → `ReloadConfig` (config.go:562): `confMu.Lock()` +
  **`defer confMu.Unlock()`** wrapping `ParseConfig(true)`.
- `config reload-zones` → `ReloadZoneConfig` (config.go:600): `confMu.Lock()` at
  entry, `confMu.Unlock()` only at config.go:662 — *after* `ParseZones` + the
  zone-removal loop.

**Who signs.** `config reload` (`ParseConfig`) re-parses the config *sections*
(dnssec, keys, apiservers) — it does **not** re-parse or sign zones — but it
shares `confMu`, so a `config reload` **blocks behind** any concurrent
`reload-zones` that is signing. `config reload-zones` (`ParseZones`) is the
signer: for every existing signed zone it synchronously calls
`SetupZoneSigning` → **`SignZone(kdb, false)`** (parseconfig.go:966 →
zone_utils.go:1102), all under `confMu`.

**Two ways `confMu` ends up spanning signing:**
**Queries are NOT in scope — the DNS answer path is lock-free.** The read path
takes **no `zd.mu`**: `GetOwner` (zone_utils.go:441) reads
`getOwnerFrom(zd.publishedSnapshot(), qname)`, and `publishedSnapshot()`
(zone_snapshot.go:247) is a bare `zd.snapshot.Load()` over
`atomic.Pointer[zoneSnapshot]` (structs.go:176) — an atomic load of an immutable
snapshot, then a map read. So `zd.mu` here is a **writer-side lock only** (guards
the mutable working set + the publish pointer-swap at sign.go:817); nothing the
signer does to `zd.mu` can stall a query. This whole finding is about the
**config plane**, not the query plane.

1. **Directly.** `SignZone`'s RRSIG-generation loop (`SignRRset` per RRset,
   sign.go:807) runs *before* it takes `zd.mu` (only grabbed at sign.go:817 for
   the publish), and **it is under `confMu`.** Steady-state `force=false` is
   additive (skips already-signed RRsets → O(zone-size) checks, cheap-ish); any
   zone actually needing signatures (fresh/expired/key-change, esp. PQ) generates
   RRSIGs **under `confMu`**.
2. **Indirectly (the source of the long holds) — writer-vs-writer.** `SignZone`
   grabs `zd.mu` at :817 to publish. That contends with the **async refresh
   engine**, which does the re-read + full re-sign off `RefreshZoneCh` and holds
   the same `zd.mu` across *its* work. Under rapid/concurrent reloads, a prior
   reload's slow async re-sign still holds `zd.mu` when the next reload's
   synchronous `SetupZoneSigning` reaches :817 → it **blocks on `zd.mu` while
   holding `confMu`**, for the full PQ-sign duration. This is exactly the dump
   picture: `ParseZones` holding `confMu`, parked on a `zd.mu` held by the
   refresh-engine goroutine. Note this is writer-vs-writer (config path vs
   refresh path); a query would sail past on the current snapshot regardless.

**Consequence.** `confMu` serialises **all config ops** — every `reload`,
`reload-zones`, `reload-tsig`, `config status` — behind zone signing. Under a
reload storm they pile up on `confMu` (the ~200 blocked handlers we saw); slow
PQ signing stretches each hold to seconds-minutes. Separate from the deadlock:
it would make config ops sluggish under PQ load even with the deadlock fixed.
**DNS queries are unaffected** — they read the immutable snapshot lock-free.

**Fix direction (post-merge, non-gating) — it's mostly a deletion.** The async
path already runs on every reload: `ParseZones` unconditionally queues a
`ZoneRefresher{Force: true}` to `RefreshZoneCh` (parseconfig.go:1099), and the
refresh engine re-reads the file and re-signs off `confMu` (refreshengine.go:512
→ `SetupZoneSigning`), then `resignq` → `ResignerEngine.resignNow` force-resigns.
So the synchronous `SetupZoneSigning` at parseconfig.go:966 is largely
**redundant** — it signs the *old* data with the *old* policy (the policy rebind
happens in the refresh engine, not at :966) while holding `confMu`. **Fix: delete
the :966 synchronous call; the already-queued ZoneRefresher covers the signing
off-lock.** `confMu` then covers only fast config work.

Safety: :966 runs only for *already-loaded* zones (new zones take the
`FirstZoneLoad`/`OnFirstLoad` branch), which already hold a signed snapshot behind
the atomic pointer — they keep serving it until the async re-sign atomically
swaps in the new one, so **no unsigned blip**. Fail-closed (A3 SERVFAIL +
AXFR-refuse) covers any genuinely-unsigned transient.

Homework before doing it: (a) confirm no caller banks on "signed by the time
reload returns" (reload response text, tests that reload then assert RRSIGs);
(b) leave the `FirstZoneLoad`/`OnFirstLoad` branch alone (restart-time, separate
path); (c) note the async path still double-signs (`force=false` at :512 then
resigner `force=true`) — pre-existing, a separate cleanup.

---

## Status & branch/defer contract (2026-07-14)

**Principle (agreed):** the `SetError` / `DnssecError`-subtype restructuring is
urgent but does **not gate the snapshot merge.** On THIS branch, ensure the
server **behaves correctly** for every signing/DNSSEC failure —
**fail-closed (SERVFAIL / refuse transfer), no deadlock, no crash** — with **no
error-registry changes.** **Defer all error *surfacing*** (zone-list /
`config status` `ERROR`, the subtype split, independent set/clear lifecycles) to
post-merge (item 9, `docs/2026-07-14-dnssec-error-single-bucket.md`).

**Split of every identified signing/DNSSEC issue:**

| Issue | Behave-correctly on THIS branch | Surfacing (→ item 9, deferred) |
|---|---|---|
| A1 re-entrant `zd.mu` deadlock | **DONE** `23710d1` | — |
| Query serves unsigned (must-be-signed) | **DONE** — SERVFAIL, A3 `449a9e2` | zone `ERROR` |
| **AXFR transfers unsigned (must-be-signed)** | **OPEN** — AXFR analog of A3 (`ZoneTransferOut` must refuse); test002 proved it | zone `ERROR` |
| A3 **wildcard** branch serves unsigned | **OPEN** — `WildcardReplace` bypasses A3 | — |
| SignZone fails (falcon/qruov codepoint orphan, alg mismatch) | fail-closed via A3 + AXFR-refuse | subtype `signing` |
| Unsigned-publish reload window (#2) | fail-closed makes it SAFE; publish-only-when-complete removes the blip → **optional/deferrable** | — |
| Policy change half-breaks a zone (test002 alg switch) | **OPEN** — minimal guard: refuse an incompatible alg change, keep old policy | full transactional + warn (#4) |
| falcon "bad private key" vague error | tdns-side clear-error-at-load (Easy) | fuller surfacing |
| `DnssecError` P1/P2/P3 bucket overload | avoided (A3 doesn't set it) | the whole B2 redesign |

**Fixed + committed (signed):** A1 `23710d1`, A3 `449a9e2` (snapshot); I10
cross-check `e117121` (tdns-debug).
- A1: `EnsureActiveDnssecKeys` gained `zdLocked bool`; `resignWorkingSetSOAIfSigned`
  resolves the dak before the lock and passes it in, routing DNSKEY publish
  through `publishDnskeyRRsLocked`. All 7 call sites audited; timeout-guarded test.
- A3: query-path (`ErrZoneUnsigned` → SERVFAIL), P1-safe (does NOT set
  `DnssecError`); CDE/referral NSECs carved out via `isSynthesizedDenial`.

**OPEN behaviour items for THIS branch (fail-closed correctness — belong here, not deferred):**
1. **AXFR fail-closed** — `ZoneTransferOut` must refuse to transfer a
   must-be-signed zone that has no RRSIGs (the AXFR analog of A3). Highest
   priority: without it a broken zone still hands DNSKEY-but-no-RRSIGs to
   secondaries (exactly what test002 did).
2. **A3 wildcard gap** — the `WildcardReplace` positive-answer branch bypasses
   the A3 SERVFAIL, so a broken-zone wildcard would still serve unsigned.
3. **Minimal policy-refuse guard** — a config-reload algorithm change that needs
   the (unbuilt) rollover must be **refused, keeping the old policy**, so a
   reload can't half-break a zone (the test002 scenario). Behaviour only; the
   *warn* is #4.
4. **A1 CLASS AUDIT — IMPORTANT.** A1 was **instance #2** of "a `zd.mu`-holding
   `*Locked` path calls a method that re-locks `zd.mu`" (first was 6e090a9).
   Do a **systematic sweep** of every lock-holding path for calls into
   `zd.mu`-locking methods — there may be a #3 lurking. This is a
   correctness / merge-gate concern (not surfacing) and belongs on this branch.

**Deferred to post-merge (surfacing / non-gating):**
- **item 9** — the `DnssecError` subtype (B2) redesign + zone `ERROR`
  observability + set/clear lifecycle (`docs/2026-07-14-dnssec-error-single-bucket.md`).
  When it lands, A3 becomes defense-in-depth.
- **#4** — full transactional config-reload (the *warn* half; the *refuse* half
  is the on-branch guard above).
- **#2** — publish-only-when-complete + derive `.Ready()` (an availability
  optimisation once fail-closed is in; not a safety gate).
- **falcon Part 1** — tdns-side clear error at load (`keystore.go:894` check
  before the `readkey.go:285` decode); Easy, no fork, anytime.
- **Finding 4** — `confMu` held across zone signing on reload (contention, not a
  deadlock). Defer the synchronous `SignZone` in `SetupZoneSigning` to the async
  refresh/`resignq` so `confMu` covers only fast config work. Latency/scalability
  under PQ signing; not a safety gate.

## Signing pipeline — post-merge redesign (companion to Finding 4)

Design agreed in discussion 2026-07-14. All post-merge, non-gating; independent
of but complementary to the Finding 4 `confMu` deletion. Target scale: ~100k
signed zones, mixed algs (MLDSA fast … SQISIGN very slow).

**State of play discovered:**
- Refresh is **already** parallel — refreshengine.go:481 spawns `go func` per
  zone (with an explicit `// XXX: Should do refresh in parallel`). But it is
  **unbounded** and has **no same-zone guard**. The resigner (resigner.go) is
  **serial** (single goroutine draining `resignq`).
- `EnsureActiveDnssecKeys` hits the DB on **every** sign (sign.go:406
  `kdb.GetDnssecKeys`). `KeyDB` is shared SQLite + `kdb.mu` + `Tx`.
- `zd.generation` already exists (atomic, bumped on zone replacement,
  config.go:653) and already backs the B5b stale-publish guard.

**1. Bounded worker pool (replaces the unbounded fan-out).** At 100k zones a
bounded pool (~NumCPU) completes *some zones fully, sooner*, with no CPU/memory
thrash — strictly better than launching all signs at once to finish together
much later. Replace the raw `go func` at refreshengine.go:481; feed the resigner
into the same pool.

**2. Per-`zd` active-key cache (takes the DB out of the hot path).** Cache the
active `DnssecKeys` behind `atomic.Pointer[DnssecKeys]` on `zd` — the exact
pattern already used for `snapshot` (structs.go:176) and `options` (:819).
Lock-free read while signing; skip `GetDnssecKeys` when set. Invalidate at the
one choke point where the key *set* changes: `DnssecKeyMgmt` add/setstate/delete
+ the key-state/rollover worker. Result: steady-state signing is pure in-memory
(no DB, no `kdb.mu`); the DB only bites on infrequent key-gen/rollover.
Correctness rests entirely on invalidating on **every** key-state transition
(the active set shifts mid-rollover). Supersedes the shared
`KeystoreDnskeyCache` map (structs.go:811) with a per-zd, lock-free field.

**3. Same-zone ordering (the real hazard) — coalescing dirty-bit + generation
CAS, NOT per-zone locks or hash-sharding.** `zd.mu` serializes critical sections,
not whole logical ops, so two `SignZone` on one zone can interleave SOA-serial
bumps / IXFR appends, or a stale one can publish over a newer one. Hash-sharding
the pool by zone would serialize same-zone for free but load-imbalances badly
(one SQISIGN zone stalls its shard) and can't coalesce. Instead:
- **Single entry point per zone** for *all* triggers (config-reload, refresh,
  resigner, key-state, dynamic update) with a per-zone state
  `idle → running → running+pending`. Request: idle→submit one job; running→set
  `pending` (do **not** submit a second). Worker done: `pending`→re-run once;
  else idle. Guarantees never-two-concurrent per zone, and a burst of N requests
  collapses to ≤2 signs — decisive under a reload storm (enqueue O(in-flight),
  not `zones × reloads`). Coalescing state is O(zones-in-flight), a small sharded
  map / `sync.Map` of atomic states.
- **Generation CAS backstop:** worker snapshots `zd.generation` at start; drop
  the publish if it advanced by completion (extend the existing B5b guard to the
  sign/publish path). Correctness even if a trigger is left un-routed. The guard
  must be **zone-scoped across engines** — the real collision is refresh-resign
  vs. resigner, which is also why the single unified entry point matters.

## Notes for the tdns-debug reload test

- The masked-signing-failure proves I10 needs a **query-vs-AXFR signedness
  cross-check**, not just an AXFR latch: query-only misses it (ephemeral mask),
  AXFR-only latch misses it (never sees a signed transfer to latch on); the
  **divergence** is the signal.
- SQISIGN is unusable at scale for the window (signing cost), but signs fine at
  ~10 records. Calibrate the window with a faster alg (MLDSA) + more records, or
  a mid-cost alg — measured one reload at a time, never a storm.

## Finding — `reset_soa_serial` is dead code (RESURRECT, do not drop) (2026-07-15)

Found while trying to force snapshot republishes for the AXFR-in bombardment:
`service.reset_soa_serial` is present in the config + sample config (comment:
"replace inbound SOA serial with unixtime"), but **nothing in the v2 tree
consumes it** — `grep -rE 'ResetSoaSerial|reset_soa_serial|ResetSOA' v2/*.go`
returns zero hits, so the key isn't even bound to a struct field (it lands in
mapstructure's Unused set). Setting it `true` + `config reload` had no effect;
the served serial stayed the primary's. Almost certainly never ported from the
legacy tree.

**Decision (Johan): resurrect it — wire it up in v2, do not remove the knob.**

Intended semantics (for whoever ports it): rewrite the **served** SOA serial to
unixtime at **publish/serve time**, so a secondary emits a monotonic serial to
downstreams regardless of the primary's serial scheme. Wiring subtlety learned
here: apply it *after* the change-detection check, NOT before. The refresh path
decides whether to republish via `new_zd.IncomingSerial == zd.IncomingSerial`
(FetchFromUpstream, zone_utils.go:303); if the unixtime rewrite happened before
that check, every refresh would look "changed" and republish on every poll even
when the primary is stable. Change-detection must use the primary's real serial;
only the emitted serial is rewritten. (This is why `reset_soa_serial` was not a
usable churn lever for the swap test — `auth zone bump` was used instead.)

## Finding — pq.axfr.net testbed bugs (independent of snapshot) (2026-07-15)

From `tdns-project/pq-testbed/README.md` "Known issues found while building"
(2026-07-13 foffe deployment, 135 PQ leaf zones). None touch the snapshot code;
all are real tdns-auth bugs, and two are wire-correctness issues.

- **TB1 — DS query at a hosted child apex panics when the IMR engine is off.**
  `handleDSQuery` case 2 calls `imr.ParentZone()` unguarded (queryresponder.go:293);
  with `imrengine.active: false`, `imr` is nil → recovered panic → SERVFAIL.
  Workaround deployed on foffe (imr enabled + root trust anchor). Proper fix:
  nil-guard `imr`, and prefer a local `FindZone()` walk (already at :300) for the
  parent before asking the network.
- **TB2 — no TC bit, ever; the EDNS UDP bufsize is ignored.** No `msg.Truncate()`
  exists in the response path. A `bufsize=512` client gets a 1666 B UDP answer;
  a DNSKEY query gets a 7747 B UDP datagram (6 fragments). Net effect on the
  public internet: the 30 zones whose ZSK sigs exceed the fragmentation
  threshold (falcon512/mayo3 ZSKs) **time out over UDP instead of falling back
  to TCP** — the exact failure mode alg-split exists to fix. UDP matrix: 105/135;
  TCP: 135/135. **This is a wire-correctness bug.** (Detailed plan below.)
- **TB3 — NS query at a hosted child apex echoes the answered NS RRset again in
  AUTHORITY.** Redundant (BIND leaves AUTHORITY empty for an authoritative
  positive answer). Cosmetic.

## Post-merge open findings — PRIORITIZED (2026-07-15)

The snapshot branch is merged; this consolidates every remaining open finding in
this doc + the pq-testbed report, in priority order. **Parallelization/perf work
(the signing-pipeline redesign: worker pool, key cache, same-zone ordering) is
explicitly DEFERRED per Johan** — it does not affect wire correctness.

**P0 — wire correctness (do first):**
1. **TB2 — EDNS-aware truncation / TC bit.** 30/135 zones unreachable over UDP.
   Plan A below.
2. **Persist effective DNSSEC policy + transactional config-reload** (= this
   doc's Decision 2 / "#4 refuse half"). A config-file policy change must go
   through the *same* transactional evaluation as a `change-policy` CLI request
   (apply → re-sign → revert/refuse-keeping-old on failure), or a bad edit
   half-breaks a signed zone on the wire. Plan B below.

**P1 — correctness, lower frequency / has a workaround:**
3. **TB1 — DS-query nil-`imr` panic.** Small nil-guard + local-parent walk;
   currently worked around by enabling imr. SERVFAIL only when imr is off.
4. **Error SURFACING (item 9 / `DnssecError` subtype B2).** Broken/unsignable
   zones behave fail-closed (already merged) but still look healthy in
   `config status`. The "raise a warning" half of P0-2 depends on this.
5. **falcon Part 1** — tdns-side clear error at load (`keystore.go:894` alg-check
   before the `readkey.go:285` decode). Easy, no fork.

**P2 — cosmetic / optimization / low-urgency:**
6. **TB3 — NS-in-AUTHORITY echo.** Cosmetic.
7. **`reset_soa_serial` resurrect** — wire up the dead knob (see finding above).
8. **#2 publish-only-when-complete + derive `.Ready()`** — availability
   optimisation now that fail-closed is merged; not a safety gate.
9. **Finding 4 — `confMu` held across signing on reload.** Config-plane latency
   only; queries are lock-free and unaffected. (Its companion the `SignZone`-off-
   `confMu` deletion is cheap and can ride along whenever P0-2 touches the path.)

**DEFERRED (Johan, 2026-07-15):**
10. **Signing-pipeline parallelization** (bounded worker pool + per-`zd` key cache
    + same-zone coalescing) — the "Signing pipeline — post-merge redesign"
    section above. Real scalability win at 100k zones, but not wire correctness.

---

### Plan A (P0-1) — EDNS-aware truncation / TC bit (TB2)

**Fix at one choke point, not ~10.** Responses are written via `w.WriteMsg(m)`
at ~10 sites (defaultqueryhandlers.go ×8, dnsutils.go:442, do53.go:235). Wrap the
`ResponseWriter` **once** in `createAuthDnsHandler` (do53.go:210) so every
downstream `WriteMsg` truncates uniformly — no per-site edits.

1. **Capture the advertised bufsize.** Add `UDPSize uint16` to
   `edns0.MsgOptions` (edns0/edns0.go:13); set it in
   `ExtractFlagsAndEDNS0Options` from `opt.UDPSize()` when an OPT is present.
   Per RFC 6891: value < 512 ⇒ treat as 512; no OPT ⇒ 512 (bare DNS).
2. **Detect transport** in the handler: `udp := w.RemoteAddr().Network() == "udp"`
   (miekg/dns's UDP writer reports `"udp"`; TCP/DoT/DoH/DoQ report `"tcp"` /
   their own). Only UDP truncates.
3. **Wrap the writer:** `truncatingResponseWriter{ dns.ResponseWriter; udp bool;
   bufsize int }` whose `WriteMsg(m)`: `if udp && m.Len() > bufsize {
   m.Truncate(bufsize) }` (miekg/dns drops trailing RRs to fit **and** sets TC=1,
   keeping the OPT), then delegate. Non-UDP → delegate unchanged. Replace `w` with
   this wrapper at the top of `createAuthDnsHandler`.
4. **TSIG ORDERING — the one subtlety.** `TsigSigningHandler` wraps the auth
   handler (do53.go:51) and MACs the outgoing message. Truncation MUST happen
   **before** the TSIG MAC is computed, or the MAC covers a message that is then
   truncated → the client rejects it. So the truncating writer must sit *inside*
   (below) the TSIG signer, or the TSIG signer must truncate-then-MAC. Get this
   ordering right.
5. **Tests:** unit-test the wrapper (>bufsize over `"udp"` → TC + fits; over
   `"tcp"` → untouched). Live: `dig +bufsize=512 @srv DNSKEY` on a PQ zone → TC=1
   + small answer; `+tcp` → full. Re-run the pq-testbed UDP matrix → expect
   **135/135** (TCP fallback) instead of 105/135.

Effort: **moderate** — the wrapper + edns capture are small; the TSIG ordering is
the only place to be careful.

---

### Plan B (P0-2) — persist effective policy + transactional config-reload

**The gap.** The `change-policy` CLI path `setZonePolicy` (apihandler_zone.go:363)
is transactional: rebind → `SignZone(force=true)` → **on failure revert to the old
policy + error** (apihandler_zone.go:417-420) → **persist the override only on
success** (:423). The **config-file-edit + reload** path is not: parseconfig
resolves `zconf.DnssecPolicy` (parseconfig.go:788) and the refresh engine applies
it via `EffectiveDnssecPolicyName` + re-sign (refreshengine.go:264/409/610), but
with **no revert on failure**, no transactional refuse of an incompatible alg
change, and **no persisted "last-applied" policy for config-only zones** — so a
config change can't even be *detected* as a change, and a bad edit half-breaks a
signed zone on the wire (Finding 2 / Decision 2).

**Design (Decision 2, made concrete):**
1. **Persist the effective policy for EVERY signed zone**, not just CLI overrides.
   Extend the `ZonePolicyOverride` store (db_zone_policy_override.go; table
   `zone, policy, set_at` at db_schema.go:188) into a *last-successfully-applied*
   record written on every successful sign — CLI **and** config. Add a `source`
   column (`config` | `command`) so origin is visible, but the stored fact is
   *what the zone was last signed under*. **Do NOT infer the current policy from
   keystore keys** (a keystore holds retired/multi-alg keys; the operator's intent
   is a single policy — this record is authoritative).
2. **Extract the transactional core** from `setZonePolicy` into a reusable
   `applyZonePolicyTransactional(zd, kdb, newPol, newName) error`: rebind
   (`zd.DnssecPolicy`/`Name`) → `UpdateSigValidityFloor` → `SignZone(kdb, true)` →
   on error revert to old + return → on success persist the effective-policy
   record. The CLI handler keeps its response-formatting wrapper around this core;
   the config path calls the **same** core — single source of truth, the two
   paths cannot drift.
3. **At load (reload AND restart): compare intent vs last-applied.** Per signed
   zone: resolve the intent policy (config YAML, or a live CLI override — existing
   `EffectiveDnssecPolicyName` precedence), then GET the persisted last-applied.
   - **equal** → no policy change → today's cheap path (SetupZoneSigning).
   - **different** → policy change → route through `applyZonePolicyTransactional`:
     - compatible (sig-validity/TTL/same-alg) → apply + re-sign; on failure
       revert + keep last-applied + raise a **non-service-impacting** warning
       (→ item 9 surfacing).
     - **incompatible alg change** needing the (unbuilt) KSK rollover → **refuse,
       keep the last-applied policy**, raise the warning. (This is the merged
       c57a564 guard, now wired into the transactional flow instead of a one-off;
       when the parent-DS/auto-rollover engine lands, route here instead of
       refusing.)
4. **Seam:** wire this into the three refresh-engine `EffectiveDnssecPolicyName`
   sites (refreshengine.go:264/409/610), which already resolve the effective
   policy on refresh — extend them to compare against the stored last-applied and
   call the transactional core on a diff. (This composes cleanly with Finding 4's
   "move `SignZone` off `confMu`": the async refresh engine is the right home for
   the transactional re-sign anyway.)

**Interlocks:** the *refuse/keep-old* behaviour (correctness) can land first; the
*warning surfaced in `config status`* is **item 9** and can follow. It shares the
already-merged fail-closed philosophy (A3 SERVFAIL / AXFR-refuse): a zone left on
its old policy after a refused change is still correctly signed on the wire.

Effort: **significant** — DB `source` column + migration, extract-and-share the
transactional core, wire into the refresh engine, and the compatible-vs-
incompatible classification. Highest-value correctness item nonetheless.
