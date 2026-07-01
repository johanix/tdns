# Merge-safety test plan — dynamic zones + multi-primary + TSIG stack

Status: TEST PLAN (2026-07-01). Goal: reach a state where the stacked
dynamic-zones / multi-primary / TSIG feature branches can be merged to
`main` safely. Covers what is **already tested** vs the **gaps** to close,
organized so each stacked branch can be gated and merged independently.

Verified against the tree on branch `feat/tsig-first-class` (contains the
whole stack). Governing specs:
`2026-06-23-dynamic-zones-interface-and-tsig-transfers.md`,
`2026-06-26-multi-primary-and-hostname-resolution-plan.md`,
`2026-06-29-first-class-tsig-keystore-plan{,-eval,-punch-list}.md`,
`2026-06-30-breaking-changes-and-migration.md`,
`2026-06-30-deferred-fallout-fixes.md`.

Legend: **[covered]** = a unit/integration test already exists;
**[GAP]** = to add; **[testbed]** = needs a running server / restart /
reload / `-race`, not just `go test`.


## 0. The stack

Linear stack, all branched off `main` (`7555e38`):

```
main → multi-primary → dynamic-zones-mgmt → tsig-on-replication → feat/tsig-first-class (HEAD)
```

By content (branch names and content do not fully line up):

| Layer | Branch | Feature | Commits | Coverage today |
|-------|--------|---------|---------|----------------|
| **L1** | `multi-primary` | Dynamic zones (B0–B6) + multi-primary/hostname (P1–P6) | 25 | good unit; lifecycle/race gaps |
| **L2** | `dynamic-zones-mgmt` | PR #268 merge + one review fix | 2 | folds into L1 |
| **L3** | `tsig-on-replication` | Wire TSIG: sign/verify SOA/AXFR/NOTIFY + ACLs | 17 | partial; **wire e2e is the big gap** |
| **L4** | `feat/tsig-first-class` | DB-backed TSIG keystore (steps 1–15 + punch-list) | 39 | **extensive** |


## 1. Merge strategy and the per-layer gate

Merge **bottom-up, one PR at a time**; each layer's gate must pass before
the next merges. L2 folds into L1.

**Per-layer gate =**
1. layer unit suite green;
2. layer integration / e2e green (the T2/T3 rows below);
3. migration assertions for that layer's breaking changes (§5);
4. `go test -race ./v2` clean for the touched packages;
5. no regression to the NOKEY / unauthenticated path.

**Final gate** (before the last/top PR merges): the full-stack scenario
(§4) green on `feat/tsig-first-class`.

### Test tiers (used within each layer)

- **T1 Unit** — mostly present.
- **T2 Integration** — in-process, multi-component; partial.
- **T3 Two-instance e2e** — primary+secondary over the wire; **largest gap**.
- **T4 Lifecycle/testbed** — restart, config-reload, mid-AXFR race; **highest risk**.
- **T5 Migration/upgrade** — some regression guards exist; upgrade path e2e missing.


## 2. L1 — Dynamic zones + multi-primary

### Already covered (unit)
`resolve_primaries_test.go` (literalIP, preservesPort, dedupSameAddr,
keyCollision, unresolvedHostname, partialResolution, sortV4First,
buildUpstreams); `transfer_fallback_test.go` (DoTransfer:
RefusedAdvancesToNextPrimary, TransportErrorAdvances, AllRefusedQuietBackoff,
AllUnreachableIsError, NoUpstreams; FetchFromUpstream_NoUpstreams);
`dynamic_zones_cores_test.go` (ProvisionDynamicZone happy/duplicate,
HostnameNoResolve); `dynamic_zones_b5_test.go`
(ZoneDataToZoneConf_PersistsAsWrittenPrimaries); `peerconf_decode_test.go`;
`zonestatus_test.go`; `zonestore_test.go`; `sample_config_test.go`;
`acl_test.go`.

### Gaps to add

**[GAP][T3] Dynamic-zone lifecycle e2e** (against a live primary):
- `add` returns `accepted` immediately, non-blocking; zone live in
  list-dynamic at once.
- `Provisioning` polls `pending → loading → ready`; add against an
  unreachable primary ends in `error` state (via state, not add failure).
- persist round-trip: zone + file written under `dynamic.storage`; persist
  failure rolls back the register (no live-but-unpersisted zone).
- `delete` removes map + config + file; refuses static and catalog zones.
- `modify` changes primary/key/options, forces re-AXFR; refuses static/catalog.
- `list-dynamic` shows catalog members (immutable) + API-managed (mutable),
  never static.

**[GAP][T4][testbed] Resurrection interlock — highest L1 risk** (spec B5b,
"testbed checkpoint needed"):
- delete **mid-AXFR** → no resurrection (refresh goroutine's pre-persist
  guard sees the bumped generation and returns without persisting).
- modify **mid-AXFR** → old ZoneData's identity check fails; no resurrection.
- deleted/modified zone does **not** reappear on restart.
- run under `go test -race`.

**[GAP][T4][testbed] Marker survival + reload spare:**
- restart: catalog `OptAutomaticZone` re-derived from `SourceCatalog`; API
  `OptApiManagedZone` re-derived from `ApiManaged`.
- config **reload** (SIGHUP): an API zone absent from static config is
  spared (`ShouldPersistZone` widened); a zone removed from static config
  is dropped and its in-flight refresh self-aborts (generation bump).

**[GAP][T3] Multi-primary AXFR fallback** (unit covers SOA-probe; add AXFR):
- first primary REFUSED (per-primary ACL) or down, second succeeds → zone
  transferred from second (REFUSED must **not** terminate).
- per-attempt isolation: a failed attempt's partial data never corrupts
  `IncomingSerial` or the live zone.

**[GAP][T2] Hostname resolution at refresh (D1, landed `5093ccd`):**
- hostnames resolve at **refresh**, not parse/load; re-resolve on reload.
- NOTIFY-triggered minimal `ZoneRefresher` **preserves** both
  `PrimariesConf` and `Upstreams` (does not blank them).
- IMR disabled (nil) → hostname primaries reported unresolved; IP literals
  unaffected. (Document: IMR-off ⇒ primaries must be IP literals.)
- partial resolution → `ConfigWarning`, zone serves from resolved
  addresses; zero resolved → `ConfigError`, zone quarantined, server starts.

### PeerConf / NOKEY (config model)
**[covered]** `peerconf_decode_test.go`. **[GAP]** confirm end-to-end: a
config file with a bare-string `primary:` among valid zones **decodes as a
whole**, only the offending zone in ERROR; a `keys.tsig[]` entry named
`NOKEY` → ERROR; missing/empty `key` → per-zone ERROR.

### L1 gate
lifecycle e2e + resurrection-race on testbed + hostname-refresh + BC-3/BC-4
migration (§5).


## 3. L3 — TSIG on replication

### Already covered (mostly unit)
`tsig_peer_test.go`, `tsig_inbound_test.go`, `tsig_utils_test.go`,
`tsig_keys_test.go`, `acl_test.go` (ip-spec parse: single/CIDR/mask/range,
BLOCKED-supersedes ordering).

### Gaps to add — the two-instance wire matrix (T3), the single biggest gap
Stand up primary + secondary `tdns-auth` (or a miekg/dns test server) and
assert:

**AXFR serve (`downstreams` ACL, primary side):**
- empty `downstreams` → **DENY** (BC-1 hard cutover).
- matched NOKEY → served unsigned; matched named key → served only on
  valid MAC; **wrong key → REFUSED**; BLOCKED supersedes; no match → REFUSED.

**AXFR/SOA pull (secondary side):**
- secondary signs the SOA probe and the AXFR with the per-primary key;
  NOKEY → plain.

**Inbound NOTIFY (`allow-notify` ACL):**
- empty `allow-notify` → accept only from configured `primaries` IPs.
- signed NOTIFY verified; **bad MAC → refused**; response signed with the
  same key when the request was signed (RFC 8945).

**Outbound NOTIFY:** signed per `notify[].key`; NOKEY → plain.

**Multi-key ACL** (`761b9fb`): any key approved for a source is accepted.

**Match semantics:** send to full `addr:port`; match inbound on IP only
(port stripped via `peerIP`).

### L3 gate
wire matrix green + deny-by-default confirmed (empty `downstreams`/open
AXFR is gone) + NOKEY path unchanged (regression).


## 4. L4 — First-class TSIG keystore

### Already covered — extensive
`tsig_keystore_test.go`, `tsig_reconcile_test.go`, `tsig_import_test.go`
(BIND/NSD extractors + comment handling), `tsig_purge_test.go`,
`tsig_migration_test.go`, `tsig_owner_test.go`, `tsig_dynzone_test.go`,
`tsig_integration_test.go`, `cli/keystore_cmds_test.go`. Per the punch-list
eval, **all H1 / M1–M6 / TC-H1–4 / TC-M1–5 are resolved with tests**. This
layer is in the best shape and is nearly merge-ready.

### Gaps to add
**[GAP][T5] Upgrade path e2e:** a real pre-keystore dynamic-zone YAML with
a `keys:` block → boot → migrated to DB (`origin=api`, `owner=api`,
`creator=dynamic-config-migration`) → `keys:` block removed from the file →
a crash between DB-commit and YAML-rewrite is **non-destructive** (secrets
durable in DB, file retained for retry). Commented-out keys not migrated.

**[GAP][T2, live] reload divergence:** config vs DB secret conflict →
withheld + WARN + `config reload-tsig` exits non-zero; **no `--force`
escape** for a config key removed-but-still-referenced (TC-H1 exists as a
unit test — confirm end-to-end).

**Deferred (do not gate):** minimum-secret-length rejection (L item) —
short BIND/NSD keys currently accepted; document in release notes.

### L4 gate
existing suites green (already) + upgrade-path smoke on a real config.


## 5. Migration / upgrade suite (breaking changes)

| ID | Old → New | Assert |
|----|-----------|--------|
| **BC-1** | AXFR open → gated by `downstreams:` (empty = DENY) | old config loads but AXFR refused to unlisted IP; add ACL entry → allowed; BLOCKED overrides allow |
| **BC-2** | NOTIFY from anyone → from configured primaries (+`allow-notify`) | NOTIFY from non-primary refused; `allow-notify` entry permits an unlisted peer |
| **BC-3** | bare-string peers → structs `{addr,key}` / `{prefix,key}` | bare-string `primary`/`notify` **quarantines that zone** with a migration error (server still starts); each new struct form parses; NOKEY + named key both work |
| **BC-4 / D1** | hostname resolved at parse → at refresh | IP-literal primary unaffected; hostname resolves at refresh; re-resolves on reload |
| **keys block → keystore** | dynamic YAML `keys:` → DB (L4 §4) | migrated once, idempotent, DB-then-YAML order, crash-safe |

**[covered]** sample-config regression guards
(`TestSampleZonesConfigDecodes`, `TestSampleTemplatesConfigIsValidYAML`) —
keep green so shipped samples don't drift back to legacy shapes.


## 6. Full-stack integration (final gate, on the top branch)

One scenario exercising L1+L3+L4 together, on `feat/tsig-first-class`:

> primary + secondary `tdns-auth`; TSIG keys in the **keystore**; secondary
> gets a **dynamic zone added via API** with a **hostname primary + TSIG
> key**; zone transfers under TSIG (SOA probe + AXFR signed and verified);
> NOTIFY-driven refresh; then `delete`/`modify` under `-race`.

Passing this on the top branch is the signal that the layers compose.


## 7. Deferred-fix status (verified in code, 2026-07-01)

The 2026-06-30 deferred-fallout doc predates some fixes; actual code status:

| ID | Fix | Status in code | Merge implication |
|----|-----|----------------|-------------------|
| **D1** | hostname primaries resolved at refresh | **DONE** (`5093ccd`, `8037a21`, `051d492`) | not a blocker; test refresh-time behavior (§2) |
| **D2** | soften legacy bare-string `downstreams:` | **OPEN** (no commit) | **soft blocker** — legacy bare-string `downstreams:` currently aborts the whole config load (vs per-zone quarantine). Decide: land D2, or forbid+document legacy `downstreams:` before merge |
| **D3** | ExpandTemplate field propagation | **DONE** (`4e4bc0b`) | covered by `TestExpandTemplatePropagatesAllFields` |
| **D4** | FQDN zonefile-template false-positive | **OPEN** (latent) | low-risk; only trailing-dot names + templated zonefile. Add a guard test; don't block |
| min-secret-length | reject short HMAC secrets | **OPEN** (deferred, L) | document; don't gate |

**Hard merge-blockers:** none intrinsic. **D2 is the one open item to
resolve** before merging the ACL cutover, unless legacy bare-string
`downstreams:` is confirmed absent and documented.


## 8. Test-infrastructure gaps to build

1. **Two-instance harness** (primary + secondary `tdns-auth`, or a
   miekg/dns test server) — unlocks the entire L3 wire matrix (§3) and the
   full-stack scenario (§6). **Pacing item; build first.**
2. **Restart / reload / race testbed** for the L1 lifecycle (§2) — a
   running server for delete/modify-mid-AXFR, marker survival, and
   reload-spare. `-race` helps but restart/reload verification is weak on a
   dev box.


## 9. Priority order

1. **Decide D2** (§7 gate) + **build the two-instance harness** (§8.1) —
   unblocks the most.
2. **L3 wire matrix** (§3) + **L1 resurrection-race / testbed** (§2) — the
   two biggest risk-vs-coverage gaps.
3. **Migration suite** (§5: BC-1/BC-3 + keys-block upgrade).
4. **Full-stack integration** (§6) on the top branch.
5. **L4 upgrade-path smoke** (§4) — everything else in L4 is covered.


## 10. Per-layer merge-readiness checklist

**L1 (dynamic zones + multi-primary):**
- [ ] unit suites green (resolve_primaries, transfer_fallback,
      dynamic_zones_cores/b5, peerconf_decode, zonestatus, zonestore)
- [ ] lifecycle e2e (add/poll/delete/modify against a live primary)
- [ ] resurrection interlock under `-race` on the testbed
- [ ] marker survival + reload-spare across restart/SIGHUP
- [ ] AXFR fallback (REFUSED/down → next primary) + per-attempt isolation
- [ ] hostname resolution at refresh; NOTIFY preserves Upstreams
- [ ] BC-3 / BC-4 migration assertions

**L3 (TSIG on replication):**
- [ ] two-instance AXFR serve matrix (empty→DENY, wrong key→REFUSED,
      BLOCKED supersedes, NOKEY→unsigned)
- [ ] SOA/AXFR pull signed per-primary key
- [ ] inbound NOTIFY verify (bad MAC→refused; empty allow-notify→primaries)
- [ ] outbound NOTIFY signed; multi-key ACL
- [ ] NOKEY regression path unchanged

**L4 (TSIG keystore):**
- [ ] existing keystore/reconcile/import/purge/migration/owner suites green
- [ ] upgrade path e2e (keys-block → DB, crash-safe)
- [ ] reload divergence (withhold + exit non-zero; no `--force` escape)

**Final:**
- [ ] full-stack scenario (§6) green on `feat/tsig-first-class`
- [ ] `go test -race ./v2 ./v2/cli` clean
- [ ] D2 resolved or documented; samples don't drift (regression guards green)
