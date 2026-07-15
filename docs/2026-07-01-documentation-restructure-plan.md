# Documentation restructure plan + coverage-gap catalogue (2026-07-01)

This is the deliverable for "part (b)": a complete sweep of the codebase for CLI
commands and YAML config keys not correctly covered in the guide, **plus** the
decision to restructure docs into a curated **Guide** and a (mostly generated)
**Reference**. It is a planning/triage doc — the actual updates are for later.

Companion to the part-(a) work already landed this session (guide updated for
first-class TSIG, multi-primary, ACLs, policy templates — commit `8973613`).

---

## 1. Decision: split Guide vs Reference

At the current size (≈305 CLI command pages, ≈140 config keys) a single
hand-written guide can no longer be both a teaching narrative and an exhaustive
lookup without rotting. We split along the standard documentation axis
(Diátaxis):

- **Guide** (`guide/`) — curated **how-to + explanation**. Task- and
  topic-oriented, small, slow-changing, human-maintained, links *into* the
  reference. Stays where it is.
- **Reference** (`reference/`, proposed) — exhaustive **information lookup**.
  One entry per command / config key. Complete and flat. **Generated from the
  source of truth wherever possible**, so it cannot drift from the code.

Why generated: every doc bug we fixed this session was drift — `store: MapZone`,
`dnssecpolicies:`, the singular `primary:`. A hand-maintained 305-command
reference would be stale the day after it was written.

---

## 2. The Reference

### 2.1 CLI reference — GENERATED (prototyped, working)

`tdns-cli gen-docs` (hidden command, commit `e30259c`) walks the live cobra
tree via `spf13/cobra/doc.GenMarkdownTree` and emits **one markdown page per
command** (description, usage, flags, inherited flags, cross-links). It needs no
daemon/config and suppresses cobra's auto-gen date footer, so regeneration is a
stable diff.

- Prototype run: **305 pages**, fully in sync with the binary (e.g. the
  `auth keystore tsig add` page already carries the `--secret-file` hardening
  flag and the `owner`/`algorithm` defaults — for free).
- **Proposed home:** `reference/cli/`.
- **Open decisions:**
  - *Check in the generated output?* Recommendation: **yes** — output is stable
    (no date churn), browsable on GitHub, and checking in generated CLI docs is
    normal practice (kubectl, gh, helm). Regenerate via a `make docs` target;
    optionally add a CI "drift check" (`gen-docs` + `git diff --exit-code`).
  - *go-md2man dependency.* `cobra/doc` transitively pulls
    `github.com/cpuguy83/go-md2man/v2` into the shipped `tdns-cli`. If we want it
    out of the production binary, move `gendocs.go` behind a `//go:build docs`
    tag (or a tiny separate generator main) and build a docs-tagged binary only
    when regenerating. Low priority — the dep is small and pure-Go.

### 2.2 Config reference — sample config is the canonical reference

The annotated sample configs already *are* a config reference: one commented
key per line, and now loader-validated (this session). Plan:

- **Treat `cmdv2/auth/tdns-auth.sample.yaml` (+ peer sample configs) as the
  config reference**, linked from the guide.
- **Complete it** — the sweep found keys that are documented *nowhere* (§4.4);
  add them to the sample config so the reference is exhaustive.
- **Optional, later:** a reflective generator that emits a config-key table from
  the struct `yaml:"..."` tags + doc comments, to guarantee completeness the way
  `gen-docs` does for the CLI. Not prototyped; the sample-config-as-reference is
  80% there and testable.

---

## 3. The Guide (curated) — topic gaps to fill later

The guide keeps how-to/explanation pages and links into the reference for
specifics. Topic pages worth adding (none block the reference work):

- **How-to: TSIG-authenticated secondary** — define a key, reference it from
  `primaries:`/`allow-notify:`, verify with `dog`.
- **How-to: AXFR ACLs** — `downstreams:` recipes, the empty-`downstreams`=DENY
  cutover, `NOKEY`/`BLOCKED` semantics.
- **How-to: multiple primaries** — `primaries: [{addr,key}]`, hostname primaries
  (resolved at refresh), failover behaviour.
- **How-to: dynamic zones lifecycle** — add/modify/delete, persistence, the
  dynamic config file.
- **Explanation: DNSSEC policy templates** — deep-merge model (currently only in
  the sample config + auth feature list).
- **Reference-adjacent: zone store types** — map/slice/xfr trade-offs (asked for
  by the sweep; no guide page explains them).

---

## 4. Coverage-gap catalogue (the checklist)

Because the per-command / per-key exhaustive list now lives in the generated
reference, this catalogue is at the **group / section** level, plus the specific
high-value gaps. Status: **Covered** / **Partial** / **Missing** / **Wrong**.

### 4.1 CLI command groups (13 top-level; ≈305 leaf pages)

| Group | Guide status | Notes |
|-------|--------------|-------|
| `auth zone` | Covered | dynamic add/modify/delete + list-dynamic now noted (part a) |
| `auth keystore` (sig0/tsig/dnssec) | Covered | TSIG group + auto-rollover tree documented; `policy-change`/`policy-cleanup` Missing |
| `auth truststore` | Covered | — |
| `auth catalog` | Partial | RFC 9432 mentioned; subcommands not walked through |
| `auth config` | Covered | reload/reload-zones/reload-tsig/status |
| `auth notify` | Covered | — |
| `auth ddns` / `del` | Partial | concept only |
| `auth debug` | Missing (intentional) | internal diagnostics — generated reference will list them |
| `agent` (parentsync) | Partial | parentsync core covered (agent-dsync-proxy.md); election/inquire thin |
| `imr` | Partial | concepts in app-tdns-imr.md; CLI sparse |
| `scanner` | Missing | experimental; no guide |
| `util` (base32/generate/rfc3597/keys) | Missing (intentional) | helper tools |
| `version` | Covered (implicit) | — |

Resolution: the generated CLI reference (§2.1) makes "leaf command not
individually documented" a non-issue — every command gets a page automatically.
The guide only needs the **group-level** how-to pages in §3.

### 4.2 Config sections (18; ≈140 keys)

| Section | Guide status | Notes |
|---------|--------------|-------|
| `zones:` peers/ACLs (primaries/notify/allow-notify/downstreams) | Covered | part a (auth features 1, 16, 17) |
| `zones[].dnssecpolicy` / `template` | Covered | part a + sample config |
| `zones[].store` | Partial | values shown; trade-offs unexplained (§3) |
| `zones[].options[]` | **Missing** | no enumerated reference anywhere — strong reference candidate |
| `dnssec.policies.*` | **Wrong** in key-rollover.md | see §4.3 |
| `dnssec.templates.*` | Covered | sample config (this session) |
| `dnssec.{completeness,large_algorithms,split_algorithms,kasp}` | Covered | key-rollover.md / sample |
| `delegationsync:` | Covered | special-features.md §1 |
| `db:` | Covered | — |
| `log:` (level, subsystems) | Covered | sample config (this session) |
| `dynamiczones:` | Covered | sample config |
| `catalog:` | Covered | sample config |
| `imr:` (base) | Partial | active/root-hints/transports covered; trust-anchor variants + logging Missing |
| `imr.tuning.*` | **Missing** | ~14 keys, fully undocumented (§4.4) |
| `imr.stubs[]` | **Missing** | undocumented |
| `keybootstrap:` | **Missing** | undocumented |
| `childsync:` | **Missing** | undocumented |
| apiserver `server/agent/combiner` sub-blocks | **Missing** | multi-app deployment; needs context |

### 4.3 Highest priority: WRONG keys (verified directly)

`guide/key-rollover.md` uses config keys that do not match the current structs.
These actively mislead operators (a copy-paste fails to load):

- `dnssec-policy:` (zone ref) → must be **`dnssecpolicy:`** (no hyphen;
  `structs.go` `yaml:"dnssecpolicy"`).
- top-level `dnssecpolicies:` → must be nested **`dnssec.policies:`**
  (`config.go` `Dnssec DnssecConf yaml:"dnssec"` → `Policies yaml:"policies"`).
- `sig-validity:` placed under `ksk:` → must be the top-level policy block
  **`sigvalidity:`** (`yaml:"sigvalidity"`); `ksk:`/`zsk:` carry only
  `lifetime`/`algorithm`.

(Note: the automated config sweep reported "no wrong keys" — that was incorrect;
these were confirmed by reading key-rollover.md against the structs. Verify, do
not trust, the agent summary here.)

### 4.4 Notable MISSING config blocks (undocumented anywhere)

- **`imr.tuning.*`** (~14 keys): `backoff.{first_failure,max_failure,multiplier,
  jitter_fraction,routing_failure,lame_delegation}`,
  `address_family.{window_duration,failure_threshold,suspect_duration,
  probe_interval}`, `discovery.{retry_after_failure,max_failures}`,
  `query_budget`, `upgrade_indirect_cache_hits`. Defaults in
  `v2/config.go` `LoadImrTuningDefaults`.
- **`imr.stubs[]`**: `zone`, `servers` — stub/forward zones.
- **`keybootstrap.consistent-lookup.{iterations,interval,nameservers}`**.
- **`childsync.{schemes,update-ns,update-a,update-aaaa,sync-on-boot,
  syncwithparent}`**.
- **apiserver `server`/`agent`/`combiner` address sub-blocks**.
- **`zones[].options[]`** — the full flag set is not enumerated in any doc.

All of these are pure **reference** material → they belong in the completed
sample config (§2.2), not in the curated guide.

### 4.5 Runtime-only fields (exclude from config reference)

`yaml:"-"` fields are internal/display-only and must NOT appear in the config
reference: `Config.Internal.*`, `ZoneConf.{Options,Error,ErrorType,ErrorMsg,
RefreshCount,EffectiveDnssecPolicy,DnssecPolicyOverridden,DnssecPolicyConfigBase,
Provisioning}`, `*EngineConf.Options`, etc.

---

## 5. Already fixed in part (a) (commit `8973613`)

- `app-tdns-auth.md`: dropped stale "No TSIG support (yet)"; keystore item notes
  TSIG keys; new feature items for ACLs (allow-notify/downstreams, NOKEY/BLOCKED,
  empty-downstreams=DENY), first-class TSIG (DB keystore, hostname-primary
  resolution), DNSSEC policies + templates.
- `applications.md`: tdns-auth + tdns-cli summaries.
- `app-tdns-cli.md`: TSIG keys in keystore; runtime dynamic zone add/modify/delete.
- `agent-dsync-proxy.md`: stale singular `primary:` → `primaries: [{addr,key}]`.
- `README.md`: TSIG removed from Future Work.
- `app-dog.md`: rcode→mnemonic error output.

---

## 6. Recommended sequencing (later work)

1. **Stand up `reference/`**: generate `reference/cli/` (decide check-in +
   `make docs` + optional CI drift check); add a `reference/README.md` index.
2. **Fix the WRONG keys** (§4.3) in `key-rollover.md` — smallest, highest-value,
   actively-misleading.
3. **Complete the config reference** (§2.2 / §4.4): add the missing config
   blocks to the sample config so it is exhaustive.
4. **Add the guide how-to pages** (§3) for the session features.
5. **Optional:** reflective config-key generator; build-tag the doc generator.
