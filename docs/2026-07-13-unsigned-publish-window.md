# Unsigned-publish window on reload/refresh: analysis, fix, and the tdns-debug reload test

**Date:** 2026-07-13
**Branch context:** analysis/fix target `feature/zone-snapshot-correctness`;
test target `feature/tdns-debug`.
**Status:** planning only — no code written. Read-only investigation of the
snapshot branch. Intended sequencing (Johan's lean): **build the tdns-debug
reload test first, use it to observe the window on the current build, then land
the fix and A/B it** — same rigor as the tearing A/B that validated the
snapshot branch.

This document grew out of the `.Ready`-gate discussion. The short version: the
readiness gate today does not mean "has content", it means "has *complete*
(i.e. signed) content". That is load-bearing, and replacing the stored `Ready`
boolean with a derived method is correct **only** if we also stop publishing
incomplete (unsigned) snapshots. Investigating that turned up a real,
pre-existing latent bug: a window on reload/refresh where a signed zone
transiently serves and transfers **unsigned** content while marked Ready.

---

## (a) The defect: an unsigned-publish window on reload / refresh

### The chain

1. `config reload-zones` -> `ReloadZones` -> `ParseZones(reload=true)`
   (`config.go:622`) queues a **forced** refresh:
   `ZoneRefresher{Force:true}` onto `RefreshZoneCh`
   ("force refresh, ignoring SOA serial, when reloading from file",
   `parseconfig.go:1084`).
2. The refresh engine runs `zd.Refresh` ->
   `applyRefreshReplacementLocked(firstLoad=false)` (`zone_utils.go:235`).
   Because `firstLoad == false`, it:
   - publishes the freshly-parsed **unsigned** snapshot (`zone_mutation.go:349`), and
   - sets `Ready = true` / `Status = ZoneStatusReady` (`zone_mutation.go:355-357`)
     — the first-load guard does **not** hold it back on a reload.
3. *Then* the engine re-signs: `SetupZoneSigning` at `refreshengine.go:467`
   (comment: *"Re-sign zone after refresh (upstream data has no RRSIGs)"*) ->
   `SignZone` -> publishes the signed snapshot (`sign.go:127`).

**Between step 2 and step 3, `Ready`/`Status` are true over unsigned content,
and it is not masked** (unlike first load, where the flip is deferred to
`InstallInitialSnapshot`). For an online-signing primary the on-disk zone file
carries no DNSKEY and no RRSIGs (keys live in the keystore, signatures are
generated online), so during the window the zone momentarily serves as if
completely **unsigned** — no apex DNSKEY, no RRSIGs anywhere.

### Two exposure points, both open during the window

- `GetOwner` gates on `!zd.Ready` (`zone_utils.go:434`) -> true -> **serves
  unsigned answers** to validating resolvers -> SERVFAIL.
- `ZoneTransferOut` gates on `Status == ZoneStatusReady` (`dnsutils.go:251`) ->
  passes -> **hands an unsigned zone to a secondary**, which then serves
  unsigned until its *next* transfer — more durable damage than a transient
  query miss.

### Scope

- **Reload** (`config reload-zones`, `Force:true`) of an online-signing primary:
  window on every reload.
- **Any forced/file-changed refresh** of an online-signing primary follows the
  same path.
- **Inline-signing secondary:** every inbound AXFR/IXFR that updates the zone
  (`updated == true`) re-publishes unsigned then re-signs at the same
  `refreshengine.go:467`, so the window recurs on **every** refresh there, not
  just on config reload.

### Severity / window length

Window length == `SignZone` duration. On a large zone signed with an expensive
post-quantum algorithm that is **not** a nanosecond race — tens of ms to
seconds (see the test setup in (c), which deliberately maximises it). Easy to
hit under load.

### Pre-existing, not a snapshot-branch regression

The publish-then-sign *ordering* on refresh predates the snapshot work (that
work changed tearing behaviour, not the signedness ordering), so `main` almost
certainly has this too. Implication: this is **not** a snapshot-merge blocker
on its own — but the fix in (b) closes it for free, and the test in (c) is
exactly what surfaces it.

---

## (b) The fix: publish only a complete snapshot

**Principle:** Store a snapshot only when it is a complete, servable state —
signed, if we sign the zone. Then "has a published snapshot" *is* "ready", and
readiness derives from the snapshot pointer (one source of truth). `SignZone`
already performs a signed publish (`sign.go:127`); that is the "complete"
publish we keep. The only offending publish is the unsigned one at
`zone_mutation.go:349`.

### Change 1 — defer the unsigned publish for to-be-signed zones

In `applyRefreshReplacementLocked`, gate the *Store* (not the staging):

```go
// working set is already staged above (workingSet, wsSignalSynth, repopulate)
willSign := (zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning])
            // && app != agent && zone eligible — mirror SetupZoneSigning's condition exactly
if !willSign {
    zd.publishWorkingSetLocked(zd.generation.Load(), false) // unsigned zone: working set IS complete
}
// signed zone: publish nothing here; SignZone's signed publish is the authoritative first Store
```

Effect:
- **Reload, signed zone:** the *old signed snapshot keeps serving* until
  `SignZone` atomically swaps in the new signed one — the unsigned window is
  gone, and we get the "serve old until the atomic swap" behaviour we want.
- **First load, signed zone:** no snapshot until signed — same masking as
  today, but now *truthful* (no phantom unsigned snapshot behind `Ready=false`).
- **Unsigned zone:** unchanged.

### Change 2 — derive `Ready`, delete the boolean

```go
func (zd *ZoneData) Ready() bool {
    snap := zd.snapshot.Load()
    return snap != nil && snap.SOA != nil
}
```

- `GetOwner` -> `if !zd.Ready()`.
- Secondary synthetic-SOA gate (`zone_utils.go:506`): `!zd.Ready` ->
  `zd.snapshot.Load() == nil`.
- Delete the five `zd.Ready = true` writes (`zone_mutation.go:356/422/431`,
  `zone_utils.go:224/309`) and the `Ready bool` field.

"Ready => valid published snapshot" then holds **by construction** — which is
the invariant we repeatedly failed to maintain by hand (several of the
2026-07-13 live-bring-up bugs were `Ready`/snapshot desyncs).

### Change 3 — Status

`Status` is a richer lifecycle enum (Pending/Loading/Ready/Error) used as the
transfer gate at `dnsutils.go:251`. The nil-snapshot check right below it
(`dnsutils.go:264`) already covers "not servable" once a snapshot means
"complete". Cleanest: make servability derive from the snapshot everywhere, and
keep `Status` as a pure display/telemetry projection (so `auth zone list` still
shows Pending/Loading/Ready/Error) rather than a second source of truth.

### `InstallInitialSnapshot` mostly collapses

Its job was "flip Ready after first-load signing". With `Ready` derived and
`SignZone` doing the first signed publish, it is a no-op for signed zones and
redundant for unsigned ones (they publish at `:349`). It likely reduces to
"start publisher + assert a snapshot exists", or goes away — pending a check of
its other callers (`refreshengine.go:293`, `CreateAutoZone` at
`zone_utils.go:1321`).

### Three things to nail before writing code

1. **Confirm every to-be-signed path re-signs after the deferred publish** —
   first load (OnFirstLoad -> SetupZoneSigning), reload/refresh
   (`refreshengine.go:467`), dynamic (`refreshengine.go:628`). If any signed
   path does *not* call `SignZone` afterward, deferring its publish would leave
   it unpublished. (First glance: all three do; needs a positive check.)
2. **Decide the sign-failure policy.** With the deferral, a failed re-sign on
   reload keeps the *old signed* snapshot serving (good — beats today's "serve
   unsigned"), but silently. That wants a `DnssecError` + surfacing, which
   dovetails with the deferred loud-config / `config status` work.
3. **Decide Status's role** (Change 3): display-only vs. still a gate.

---

## (c) The tdns-debug reload test

### Goal

Observe the (a) window empirically on the current (pre-fix) build, then use the
same run to prove the (b) fix closes it — the tearing-A/B method applied to
signedness. The test targets a **different invariant class** from `churn`
(completeness/signedness, not tearing) but reuses the same actor/ledger/checker
engine.

**Decision: a new, separate `test reload` family — do NOT fold the reload actor
into `churn`.** `churn` is deliberately **mgmt-API-free**: it stresses the
server using only standard DNS (SIG(0) UPDATE, AXFR, queries), which is exactly
why it is portable to BIND/NSD/Knot and any other authoritative implementation.
The reload test is inherently mgmt-API-dependent (it must *trigger* reloads via
the management API), so it belongs in its own family rather than contaminating
`churn`'s portability. This keeps a clean split: `churn` = the reference
portable stress test; `reload` = a tdns-oriented test that drives the server's
own reload machinery.

### The new invariant

**I10 — no unsigned window (signedness/completeness).** If the zone is
DNSSEC-signed, then every observation must be consistent with a signed zone:
the apex DNSKEY is present, and every authoritative RRset the tool tracks (the
SOA, and the `_churn` TXT set) carries a covering RRSIG. An observation missing
the DNSKEY/RRSIGs is an **unsigned-window violation** — the server transiently
served or transferred incomplete (unsigned) content.

How the tool decides the zone is "signed":
- **Declared** at provision time (the test provisions online-signing), and/or
- **Latched**: once the tool has observed an apex DNSKEY (or any RRSIG) for the
  zone, it latches "signed", and any later observation lacking them is a
  violation. Latching keeps I10 portable to non-tdns signed servers.

**Presence, not cryptographic validity.** I10 checks that an RRSIG exists and
covers the right owner/type (miekg/dns parses RRSIG RRs regardless of
algorithm) — it does **not** verify the signature. That is sufficient to catch
the window and keeps tdns-debug free of C-backed algorithm linkage (no
`algs.list`), consistent with its "pure client" build. The tool can therefore
test a SQISIGN-signed zone without itself supporting SQISIGN.

The crispest observable is the SOA/AXFR: in a signed zone the SOA RRset always
carries an RRSIG, and an AXFR always contains RRSIGs. During the window the
freshly-parsed snapshot has neither -> stark, false-positive-free signal.

### The new actor

**Reload actor** (mgmt-API, capability-gated, optional). Periodically triggers
the reload endpoint (`config reload-zones`, `apihandler_funcs.go:324`) to force
the refresh -> republish-unsigned -> re-sign cycle. Cadence tuned so reloads
overlap the AXFR/query sampling.

- Capability-gated per the tool's design: if the target does not expose the
  reload endpoint (non-tdns server, API not configured), the reload actor is
  reported **SKIPPED** — the test then cannot *force* the window (it can still
  passively watch during operator-triggered reloads, but forcing is what makes
  it a controlled experiment).
- I10 itself is pure-DNS and runs regardless (portable).

The existing update-sender / AXFR poller / query hammer keep running; the AXFR
poller and query hammer feed I10 in addition to the tearing checkers. Note the
window opens on **reload**, not on update, so the reload actor is the essential
new stimulus; the churn updates are an orthogonal (realistic) co-stress.

### Widening the window: large zone + expensive algorithm

Window length == `SignZone` duration == (RRset count) x (per-signature cost).
To make the window large and reliably sampled:

- **Large zone: >= 10,000 signable RRsets.** Provisioning emits N filler owner
  names (e.g. `hostNNNNN.<zone>` each with a single A record) plus the `_churn`
  subtree. A records only — no delegations/glue, which would complicate
  coverage checks.
- **Expensive algorithm: SQISIGN** (Johan's suggestion). Very slow per
  signature; 10K RRsets x SQISIGN -> a window of seconds (possibly much more).
  Ideal for both the positive control (catch) and the fix-validation (a large
  window that the fixed build must still show **zero** unsigned observations
  across).
  - Trade-off: SQISIGN makes each reload cycle slow, so reload cadence is
    coarse (e.g. one reload every 20-60 s) — but each window is huge, so even a
    modest AXFR/query cadence lands many observations inside it.
  - Faster fallbacks if SQISIGN iteration is impractical: FALCON1024 or a MAYO
    variant — still slow enough to expose a multi-hundred-ms window on 10K
    RRsets, much quicker to iterate on.

### Provisioning changes (`--generate-config`)

- New knob **`--zone-size N`** (alias `--rrsets N`): emit a zone with N filler
  RRsets. Default large (e.g. 10000) for this family.
- Emitted config enables **online-signing** with a DNSSEC policy referencing
  **SQISIGN1** (algorithm number 65).
- Emitted operator to-do must spell out the server-side prerequisites:
  - a DNSSEC policy referencing **SQISIGN1**. **No rebuild is required** — the
    running `tdns-auth` already includes SQISIGN1 (verify with
    `tdns-cli auth keystore dnssec algorithms | grep -i sqisign`). The old
    `WITH_*` build flags are dead; algorithm inclusion is driven by `algs.list`
    + the genalgs generator, and SQISIGN1 is already in the current binary.
  - the reload endpoint must be reachable by the tool's mgmt-API identity;
  - trust the churn SIG(0) key (`sig0 add` + `sig0 trust`), as with `churn`;
  - AXFR permitted to the tool.

### Command shape (proposed)

`tdns-debug test reload` — the reload/refresh completeness test. Reuses the
churn engine; adds the reload actor and I10.

```
# provision a large SQISIGN-signed zone (server untouched)
tdns-debug test reload --generate-config --base-zone test.axfr.net. \
    --zone-size 10000 --algorithm SQISIGN1

# run it: force reloads while transferring/querying, check I10 (+ churn invariants)
tdns-debug test reload --test test002 --dns 127.0.0.1:5354 \
    --reloadcadence 30s --axfrcadence 400ms --qps 100 --duration 5m
```

Knobs: `--reloadcadence`, plus the existing `--axfrcadence`, `--qps`,
`--updatecadence`, `--duration`, `--json`. (`--updatecadence` optional here —
the window is reload-driven, not update-driven — but running churn concurrently
is a fine combined stress.)

### The A/B plan

1. **Positive control (current build).** Run `test reload` against today's
   snapshot-branch (pre-fix) `tdns-auth`. Expect I10 violations: AXFRs and/or
   queries landing in the re-sign window return the zone with no DNSKEY/RRSIGs.
2. **Fix validation.** Apply the (b) fix, rebuild, run the identical command +
   load. Expect **zero** I10 violations: the old signed snapshot serves
   continuously until the atomic signed swap.

This mirrors the tearing A/B (main tears / snapshot clean) that established the
snapshot branch fixes C1: here the pre-fix build shows the unsigned window and
the fixed build is clean under identical load.

---

## Sequencing / task list (for tomorrow)

Test-first, then fix (Johan's lean). Rationale: proving the tool catches the
defect on the pre-fix build first is what makes the post-fix "clean" result
evidence rather than assertion — the same discipline that made the tearing
result convincing.

### Phase 0 — Verify the signing algorithm actually SIGNS (gates Phase 2, not Phase 1)

**"Listed in `keystore dnssec algorithms`" does NOT mean "actually signs."**
Proven on the running server 2026-07-13: `QRUOV1` is advertised by the registry
but the signer's key-parse path rejects it — `ParsePrivateKeyFromDB failed:
unknown algorithm: QRUOV1` (`keystore.go:983/1225`), 525 recurring errors, zone
`qruov1.pq.axfr.net.` effectively unsignable. A registry-vs-implementation
seam. (`falcon.pq.axfr.net.` fails differently — `dns: bad private key`: the
algorithm is known but the key won't parse.) So SQISIGN1, which **no zone
currently exercises** (0 log mentions), must be proven before we build a 10K
reload test on it — else we get `unknown algorithm` spam instead of slow
signing.

- [ ] Provision a **tiny** SQISIGN1 zone (a handful of RRsets) and confirm it
      signs cleanly: apex DNSKEY + RRSIGs appear, **no** `unknown algorithm:
      SQISIGN*` / `bad private key` in `/var/log/tdns/tdns-auth.log`.
- [ ] If SQISIGN1 is broken (qruov-style or falcon-style), fall back to a
      **verified** algorithm. `MLDSA` signs cleanly on this server today (0
      errors) — the safe default; we trade some window width for a valid test.
      (Chase the SQISIGN break separately — same class as the qruov chip.)

### Phase 1 — Build the `test reload` family *(tdns-debug, `feature/tdns-debug`)*

- [ ] **Reload actor** — mgmt-API call to the reload endpoint (`config
      reload-zones`, `apihandler_funcs.go:324`); capability-gated (SKIPPED if
      absent); `--reloadcadence` knob.
- [ ] **I10 checker** — signedness/completeness. RRSIG *presence* + coverage
      (owner/type-covered/labels), NOT crypto validity. Zone is "signed" if
      declared at provision AND/OR latched on first observed apex DNSKEY/RRSIG.
      Crispest observable: SOA/AXFR carries no RRSIG during the window.
- [ ] **Provisioning** — `--zone-size N` filler-RRset generator (N distinct
      `hostNNNNN.<zone>` A records, no delegations/glue); `--algorithm` knob;
      emit online-signing config with a **SQISIGN1** policy + operator to-do
      (no rebuild; reachable reload endpoint; trust SIG(0) key; AXFR permitted).
- [ ] **`test reload` command** — reuse the churn engine; AXFR poller + query
      hammer feed I10 alongside the existing observation streams.
- [ ] **Unit tests for I10** — false-positive-free: a signed zone trips
      nothing; an unsigned observation is flagged.

### Phase 2 — Positive control (observe the window on the CURRENT build)

- [ ] Provision the large (≈10K) SQISIGN1 zone; install config + DNSSEC policy;
      trust the key; reload. *(No server rebuild — SQISIGN1 already supported;
      just a policy that uses it.)*
- [ ] Run `test reload` against the current snapshot-branch `tdns-auth`; **expect
      I10 violations** (AXFRs/queries landing in the re-sign window come back
      unsigned).
- [ ] Capture the run output as the worked example (mirrors the tearing
      example in `guide/testing.md`).

### Phase 3 — Land the fix *(`feature/zone-snapshot-correctness`)*

- [ ] Verify the three prerequisites: every to-be-signed path re-signs after the
      deferred publish (first load / `refreshengine.go:467` / `:628`);
      sign-failure policy; Status's role.
- [ ] **Change 1** — defer the unsigned publish for to-be-signed zones
      (`zone_mutation.go:349`).
- [ ] **Change 2** — derive `Ready()`; delete the boolean + its 5 writes; fix
      the secondary synthetic-SOA gate (`zone_utils.go:506`).
- [ ] **Change 3** — Status as display-only projection.
- [ ] Collapse/retire `InstallInitialSnapshot` (check callers
      `refreshengine.go:293`, `zone_utils.go:1321`).
- [ ] Full `v2 -race` suite green.

### Phase 4 — Fix-validation A/B

- [ ] Rebuild; run the **identical** `test reload` command + load; **expect zero
      I10 violations** (old signed snapshot serves until the atomic signed swap).
- [ ] Add the A/B pair to `guide/testing.md` as the reload worked example.

### Phase 5 — Follow-up

- [ ] Fold the sign-failure surfacing into the loud-config / `config status`
      work.
- [ ] Document `test reload` in `cmdv2/debug/README.md` + `guide/testing.md`.

## Decisions made

- **New, separate `test reload` family** (not folded into `churn`) — to keep
  `churn` mgmt-API-free and therefore portable. See the rationale in (c).
- **SQISIGN1 needs no server rebuild** — already supported by the running
  binary; only a DNSSEC policy referencing it is required.

## Open questions

- **`--algorithm` default for the emitted config:** SQISIGN1 (maximises the
  window, slow to iterate) vs. a faster PQ fallback (FALCON1024 / MAYO — still
  exposes a multi-hundred-ms window on 10K RRsets). Lean: SQISIGN1 for the
  headline positive-control run, a faster alg for quick iteration.
- **Sign-failure policy** (b, item 2): keep-old-and-flag is the proposed
  behaviour; confirm and decide how loudly to surface it (ties into the
  deferred loud-config / `config status` work).
- **Status's role** (b, Change 3): display-only vs. gate.
- **Passive I10 in `churn`?** I10 is pure-DNS, so running it under `churn` would
  *not* break `churn`'s portability — but `churn` never triggers reloads, so
  I10 would rarely fire there. Low value; leaving it out unless a reason
  appears. (The mgmt-API split is about the reload *actor*, not I10.)
