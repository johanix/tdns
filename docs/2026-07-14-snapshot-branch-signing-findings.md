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

## Notes for the tdns-debug reload test

- The masked-signing-failure proves I10 needs a **query-vs-AXFR signedness
  cross-check**, not just an AXFR latch: query-only misses it (ephemeral mask),
  AXFR-only latch misses it (never sees a signed transfer to latch on); the
  **divergence** is the signal.
- SQISIGN is unusable at scale for the window (signing cost), but signs fine at
  ~10 records. Calibrate the window with a faster alg (MLDSA) + more records, or
  a mid-cost alg — measured one reload at a time, never a storm.
