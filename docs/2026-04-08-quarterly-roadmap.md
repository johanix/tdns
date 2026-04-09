# Roadmap: tdns and Friends

**Date**: 2026-04-08
**Status**: Draft for discussion
**Framing**: This document is about *dependencies and
ordering*, not calendar scheduling. Where dates appear
(§2), they are external milestones anchoring the work,
not deadlines allocated to phases. The phases in §5 are
ordered by what must come before what, not by which
week they start.

## 1. Scope

This roadmap covers the coordinated work across the
repos that together make up the "tdns family":

| Repo            | Role                                         |
|-----------------|----------------------------------------------|
| `tdns`          | Core DNS library + tdns-auth / tdns-agent / tdns-imr |
| `tdns-transport`| Generic transport (TM, RMQ, routing)         |
| `tdns-mp`       | Multi-provider (mpagent/mpsigner/mpcombiner) |
| `tdns-nm`       | Node Manager — KDC / KRS key distribution    |
| `tdns-es`       | Edge Signer (presently a stub)               |
| `tdns-apps`     | Grab bag of smaller apps                     |

The active focus is on tdns, tdns-mp, and (after the MP
work stabilizes) tdns-transport. tdns-nm and tdns-es are
downstream of tdns-transport being correct; they will
become actionable once the MP lane has finished its work
on the transport layer. tdns-apps is maintained
opportunistically.

Within tdns, two distinct tracks of work run in parallel
(see §4): the MP lane, centered on tdns-mp's path to OARC
Edinburgh; and the IMR lane, centered on
draft-johani-dnsop-delegation-mgmt-via-ddns's path to
IETF 126 Vienna.

## 2. Fixed External Dates

| Date                   | Event                                              |
|------------------------|----------------------------------------------------|
| late May 2026          | OARC Edinburgh — tdns-mp presentation              |
| late July 2026         | IETF 126 Vienna — `draft-johani-dnsop-delegation-mgmt-via-ddns` |

**OARC Edinburgh** is the first hard milestone. By then
tdns-mp must be demonstrably independent, the regression
matrix must be green, and the tdns/tdns-mp relationship
story must be clean enough to present in public.

**IETF 126 Vienna** is the second hard milestone, for
the delegation-management-via-DDNS draft (currently at
-05). This is the anchor for the IMR track: by Vienna
the UPDATE-based delegation sync code must be polished,
hardened, and genuinely tested — not just
self-consistent.

The two milestones are fortunately not in tension: OARC
is tdns-mp, Vienna is core tdns/tdns-auth/tdns-imr.
Different code, different stories, different audiences.
The ~2 months between them give the IMR lane breathing
room that the MP lane does not have.

## 3. State of the World (as of 2026-04-08)

### 3.1 tdns-transport — extracted but not yet correct

Extracted, imported by tdns and tdns-mp, and running in the
lab. But the layering is wrong in several ways and the
repo needs a structural cleanup before it can honestly be
called "stable". The key issues:

**Import path nit.** The import line is currently
`github.com/johanix/tdns-transport/v2/transport` — that
trailing `transport` is one too many. The package should
be importable as `.../tdns-transport/v2`.

**Application messages have leaked into the transport
layer.** Today tdns-transport knows about both "transport
layer messages" (HELLO, BEAT, PING) and "application
messages" (SYNC, UPDATE, KEYSTATE, RFI, CONFIRM). The
application-level handlers (`HandleSync`, `HandleUpdate`,
`HandleKeystate`, `HandleConfirm`, `HandleRfi`, and the
role-specific router wiring) must move up into tdns-mp.
This is section 2 of
`tdns/docs/2026-03-26-architectural-improvements.md`.

**Some responsibilities should move *into* tdns-transport,
not out of it.** The transport layer is missing services
that every tdns-family application will need:

- **Peer registry.** tdns-mp's `AgentRegistry` is really a
  generic "given a peer ID, how do I reach it" service.
  Promote this to `PeerRegistry` in tdns-transport, so
  tdns-mp, tdns-nm, and tdns-es all get it for free.
- **Peer discovery.** The URI + SVCB + JWK discovery
  mechanism was built for agents but is intended to be
  used by every application (KDC/KRS, edge signer, etc.).
  It belongs in tdns-transport, not in application code.
- **Gossip protocol.** Currently being migrated from tdns
  to tdns-mp. Open question whether it should land in
  tdns-transport instead, since gossip over a peer
  registry is a transport-layer concern, not an MP-only
  concern.

**Crypto and encoding expansion.** Today the transport
assumes JOSE + the CHUNK RR. Two parallel tracks:

- **COSE** alongside JOSE. JOSE has huge overhead; COSE
  is the binary equivalent. A companion "BHUNK" (binary
  CHUNK) RR goes with it.
- **HPKE revival.** Encrypted transport over DNS started
  with HPKE and was parked in favor of JOSE because of
  library maturity. HPKE comes back when there's time.

**Net effect on the roadmap**: tdns-transport is *on* the
critical path, not off it. Every downstream repo
(tdns-mp, tdns-nm, tdns-es) is blocked to some degree by
tdns-transport stabilizing, and the restructuring above
is what "stabilize" actually means. The restructuring is
deliberately scheduled *after* the MP-lane OARC work
(phase M4) — see §5 for why.

### 3.2 tdns — MP removal in progress

The three-repo split landed through Phase 1 (tdns-mp hosts
signer + combiner, lab-tested). In parallel, tdns still
contains ~21 legacy MP files (~13k lines) kept alive by
~80 call sites in ~10 non-legacy files. Two design docs
drive this:

- `2026-04-04-tdns-mp-decoupling-plan.md` — 29 inventory
  items (gates, moves, restructurings)
- `2026-04-04-implementation-plan.md` — concrete tasks A–J,
  ordered for safe add-first/remove-second migration

The goal is: tdns is a clean DNS library, with no MP
knowledge in any non-legacy file, and no legacy files
left at all.

### 3.3 tdns-mp — migration in progress, not yet complete

Nuance from the previous draft: the agent *application*
(`tdns-mp/cmd/mpagent/`) already builds. The big-bang
agent extraction plan has been implemented. **But** the
agent still reaches back into tdns for many MP functions
and types, and these have to be migrated one by one. This
is a large, ongoing task.

Until migration is complete, the codebase is in an
unstable half-way state: parts of the code call the
tdns-mp version of a given function, parts still call the
legacy tdns version, and the two can disagree. This is
the source of the "spurious bugs" we keep hitting. We
must not stop in the middle.

Two sibling efforts are already implemented on feature
branches but cannot currently be merged, because they
inherit the half-migrated state:

- **Combiner persistence/editing separation + IGNORED
  status** (`2026-03-31-combiner-persistence-separation.md`)
  — implemented on a branch, merge attempts blocked by
  spurious bugs from the half-migration.
- **MP auditor** (`2026-03-30-mpauditor-design.md`) —
  also implemented on a branch, same problem.

Every step forward in the migration without merging
these branches makes their eventual rebase harder.
That is a real tax on the plan, but the alternative —
merging on top of a half-migrated base — is worse. The
resolution is to push through the migration to a point
where both branches can rebase
cleanly, not to pause.

The regression test plan
(`2026-03-30-mp-regression-test-plan.md`) is the gate
that tells us the migration is actually done.

### 3.4 tdns-nm (KDC/KRS) — blocked on tdns-transport

Built against a pre-split version of tdns. Very likely
does not build today. Waiting for tdns-transport to
stabilize (in the sense of §3.1 — correct layering, peer
registry, discovery) so it has a stable foundation to
rebuild against.

Until then, KDC/KRS work continues on design/docs
(bootstrap, catalog zone migration, HPKE↔JOSE comparison,
phase-4d HPKE signing) but not on integration with the
new tdns-transport.

### 3.5 tdns-es — parked, downstream of everything

Intended to be essentially `tdns-auth + tdns-krs` bundled
into a single edge-signer application. KRS itself is a
testing/debugging tool, not the end state; tdns-es is the
production form. Dependency chain:

```
tdns-transport (restructure)
    → tdns-nm (rebuild against new transport)
        → tdns-es (implementation can begin)
```

Design documents exist (`DESIGN.md`, `DESIGN_EDGESIGNER.md`,
`FUTURE-KRS-AUTH-INTEGRATION.md`). Implementation is out
of scope for this roadmap — tdns-es belongs to whatever
comes after the phases in §5.

### 3.6 tdns-apps — opportunistic
Small apps; maintained as needed, not a planning focus.

### 3.7 tdns-imr — three projects, one codebase

tdns-imr is a pure tdns app — it lives entirely in the
tdns repo, uses no MP code, and has no dependency on
tdns-mp or tdns-transport. That makes it fully
independent of the MP/OARC track. But it has three
major projects converging on it, all touching the same
code (IMR query path, IMR cache, validation). Sequencing
them against each other is the key planning question
for this track.

#### 3.7.1 DNS Transport Signaling (DTS)

**Status**: tdns-auth side is mostly done. tdns-imr
side needs significant updates to the IMR code, the
IMR cache, and nearby query-path machinery to correctly
drive and consume transport signaling end-to-end. Lots
of work has landed; it is not yet working smoothly.

**Scope**:
- Complete the IMR-side signaling: state tracking per
  upstream, cache entries carrying signaling metadata,
  correct behavior on transport changes mid-query.
- Shake-down testing against real upstreams.
- Whatever cache-adjacent refactoring is needed to make
  the above clean rather than bolted on.

#### 3.7.2 IMR DNSSEC validation polish

**Status**: validation exists and mostly works, but is
not robust enough to depend on. A separate
`ValidatorEngine` still exists but its role has drifted
as validation has moved closer to the IMR query path.

**Scope**:
- Harden validation against the edge cases currently
  producing spurious results.
- Decide the fate of `ValidatorEngine`: keep, fold into
  IMR, or delete outright.
- Any remaining cache/state issues around NSEC/NSEC3
  proofs and negative answers.

**Coupling with DTS**: shares the IMR codebase and the
IMR cache. Doing both simultaneously by the same hands
is an invitation to spurious bugs of exactly the kind
the MP migration is suffering from. Sequence rather
than interleave.

#### 3.7.3 UPDATE-based delegation sync hardening

**Status**: code exists behind `draft-johani-dnsop-
delegation-mgmt-via-ddns` (currently at -05). Needs
polish, hardening, and above all comprehensive testing
before IETF Vienna so the presentation can honestly
claim "this works".

**Scope**:
- Testing against diverse parent server implementations,
  not just tdns-auth talking to itself.
- Edge cases: failed UPDATEs, partial success, retry,
  SIG(0) key rotation mid-stream.
- CLI / tooling ergonomics for a live demo.
- Keep draft and implementation in sync through the
  presentation cycle.

**IMR coupling**: the delegation sync client lives in
tdns core, but the *parent discovery* path (DSYNC
lookups) goes through the IMR. Any IMR cache bugs that
§3.7.1 or §3.7.2 surface will show up here too. A
hardened IMR is a prerequisite for trustworthy
delegation-sync testing.

**This is the natural ordering for the IMR track**:
(a) DTS first (foundation — cache and query-path
changes), (b) validation polish next (builds on the
same cache, lets us delete or keep ValidatorEngine with
confidence), (c) UPDATE delegation sync testing last
(consumes the now-trustworthy IMR for DSYNC discovery
and validation).

## 4. Themes

Two parallel tracks. The **MP track** is anchored by
OARC Edinburgh and is internally sequential. The **IMR
track** is anchored by IETF 126 Vienna and is also
internally sequential. They touch disjoint codebases and
so can run concurrently without stepping on each other —
but both compete for the same attention, and when in
conflict the nearer milestone wins.

### MP track (tdns, tdns-mp, later tdns-transport)

1. **Decouple** (tdns) — tdns becomes a clean DNS
   library with no MP knowledge.
2. **Migrate** (tdns-mp) — finish moving every MP
   function and type out of tdns and into tdns-mp. No
   half-state. This is the work that unblocks the
   combiner-separation and auditor feature branches.
3. **Harden** (tdns-mp) — once migration is stable
   enough to merge the parked branches, run the
   regression test matrix and fix what it finds. Target:
   credible public demo at OARC Edinburgh.
4. **Restructure** (tdns-transport) — correct the
   layering: move application messages out, move peer
   registry / discovery / possibly gossip in, fix the
   import path. Deliberately scheduled *after* OARC.
5. **Rebuild** (tdns-nm) — rebuild KDC/KRS against the
   restructured tdns-transport so H2 work on tdns-es is
   not blocked on foundation issues.

### IMR track (tdns only)

All three projects converge on the IMR (pure tdns, no
cross-repo dependencies). They share the IMR code and
cache, so sequencing between them matters more than
parallelism.

6. **Land DTS** — finish the DNS Transport Signaling
   work on the IMR side. Foundation for everything else
   on this track because it reshapes the IMR cache and
   query path.
7. **Polish IMR validation** — harden DNSSEC validation
   and decide the fate of `ValidatorEngine`. Builds on
   the DTS work; do not interleave.
8. **Harden UPDATE delegation sync** — make the code
   behind `draft-johani-dnsop-delegation-mgmt-via-ddns`
   production-quality enough to present at IETF Vienna
   with a straight face. Consumes the now-trustworthy
   IMR for DSYNC discovery and validation.

### IETF drafts cross-referenced

| Draft                                              | Track | Role                                                  |
|----------------------------------------------------|-------|-------------------------------------------------------|
| `draft-leon-dnsop-signaling-zone-owner-intent`     | MP    | HSYNC — intellectual foundation for tdns-mp; implementation now goes well beyond the draft, but the draft remains the point of departure |
| `draft-berra-dnsop-opt-keystate`                   | MP    | KEYSTATE EDNS(0), already implemented                 |
| `draft-johani-dnsop-delegation-mgmt-via-ddns`      | IMR   | UPDATE-based delegation sync, IETF 126 Vienna talk    |

## 5. Phases and Ordering

Two parallel lanes. Within each lane, phases are
strictly ordered by dependency: phase N+1 builds on
state established by phase N and should not start
before N is done. Between lanes there is no ordering —
the MP lane and the IMR lane touch disjoint code and
can progress independently. The two external
milestones (OARC Edinburgh, IETF Vienna) set the rough
pacing but are not the structure.

This section is about *what depends on what*, not
*when things happen*. Dates are in §2; everything else
is ordering.

## 5.1 MP lane

The MP lane exists to get tdns-mp to a state where it
can be credibly presented as an independent
implementation on top of a clean tdns library, in time
for OARC Edinburgh. The phases below are a strict
chain: each one depends on the previous having
actually completed, not just started.

### Phase M1 — Finish the MP migration

**Goal**: every MP function and type lives in tdns-mp,
not in tdns. tdns has no MP references from non-legacy
code. The legacy files are deletable.

Why it's first: everything else in the lane depends on
the codebase being out of its current half-state. The
parked feature branches can't merge, regression tests
can't be trusted, and tdns can't be "a clean library"
until this is done.

- Systematic subsystem-by-subsystem move of MP code
  from tdns into tdns-mp. Recommended ordering is
  bottom-up (leaf types first, then authorization /
  discovery, then hsync utilities, then combiner
  utilities, then the high-level engines) — but see
  open question in §9.
- After each subsystem moves, run the full MP binary
  set in the lab and confirm nothing regresses. **No
  merge of subsystem N+1 until subsystem N is
  verified.** This is the only defense against
  accumulated half-state bugs.
- Maintain a running burn-down list of "symbols still
  reaching back into tdns". The list hitting zero is
  the definition of done.
- On the tdns side, the implementation plan tasks A–J
  fall out naturally as subsystems move. Delete
  `apihandler_agent.go` and
  `apihandler_agent_distrib.go` (both are MP code in
  tdns clothing). Remove `weAreASigner` guards from
  sign.go, resigner.go, key_state_worker.go.
- Do **not** start the tdns-transport restructuring
  during this phase. It would reshape the ground under
  tdns-mp while tdns-mp is in the middle of moving.
  Collect the restructuring TODOs in a parking doc.

**Exit criterion**: tdns builds with zero MP knowledge
in non-legacy code. tdns-mp builds against the
slimmed-down tdns. Both codebases in a "stable single
version of truth" state.

### Phase M2 — Merge the parked branches

**Goal**: the combiner persistence/editing separation
(IGNORED status) and mpauditor branches are rebased
against the migrated tdns-mp main and merged.

Why it's second: these branches were parked precisely
because the half-migrated base made their merges
unstable. They cannot land before M1 is done, and they
should land *right after* so that M3 (hardening) tests
the complete system, not the pre-auditor one.

- Rebase and merge the combiner persistence/editing
  separation + IGNORED branch. Higher-value and likely
  harder; land first.
- Rebase and merge the mpauditor branch. This is the
  branch most likely to produce a concrete "here's
  something new" demo moment.
- Split the `/agent` API endpoint and update all CLIs
  (`tdns-cli`, `mpcli`) to match — this is a
  structural change that should not mix with bugfixes
  in phase M3.
- Second-pass audit of ParseZones for any remaining
  MP-specific corners. Item 14b (MPdata population)
  from the decoupling plan is the critical one — do
  not lose it.
- Clean up `main_initfuncs.go`, `parseconfig.go`,
  `delegation_sync.go`, `parentsync_leader.go` — the
  mixed files that still have MP sections.
- Legacy files in tdns can be deleted in one pass now
  that nothing references them.

**Exit criterion**: tdns is a clean library, tdns-mp
has all its features, and both build cleanly. Nothing
is parked on a branch waiting for something else.

### Phase M3 — Harden for OARC

**Goal**: tdns-mp passes the regression matrix in the
lab, and the demo story is rehearsed.

Why it's third: hardening is only meaningful against a
complete system. Running the regression tests on a
half-migrated tdns-mp would produce noise, not signal.

- Run the full MP regression test plan end-to-end in
  the lab. Every box ticked, or explicit known-issue
  with a workaround documented. Resolve the `HOW?`
  markers in the test plan before running — unknown
  unknowns in the test matrix are worse than failing
  tests.
- Shake down the combiner-separation and mpauditor
  work under regression load. These branches have
  only been tested in isolation.
- Bugfix pass: whatever the regression tests surface
  in the library layer or in tdns-mp.
- Documentation: README/overview needs to reflect
  "tdns = library, tdns-mp = multi-provider", because
  the OARC talk will send people to the repos cold.
- Dry-run the presentation against the live lab
  topology, at least once, preferably twice.

**Exit criterion**: OARC talk delivered. Lab demo
works. Public repos tell a coherent story to a
stranger reading them during the Q&A.

### Phase M4 — Restructure tdns-transport

**Goal**: tdns-transport has the correct layering
(§3.1) — application messages moved out, peer
registry and discovery moved in, import path fixed,
gossip question decided.

Why it's fourth: this phase touches the ground
underneath tdns-mp. Doing it before M3 would
destabilize the OARC demo. Doing it before M1 or M2
would be disastrous. It is deliberately placed *after*
OARC, not because it is less important, but because it
is the first thing that can happen safely once OARC is
done.

- Fix the import path: drop the trailing `transport`
  package level, importable as `.../tdns-transport/v2`.
- Move application message handlers (`HandleSync`,
  `HandleUpdate`, `HandleKeystate`, `HandleConfirm`,
  `HandleRfi`, role-specific router init) up into
  tdns-mp. Keep `HandlePing`, `HandleBeat`,
  `HandleHello` as transport-layer builtins.
- Promote `AgentRegistry` to a generic `PeerRegistry`
  in the transport layer.
- Move URI+SVCB+JWK peer discovery down into the
  transport layer as a service all applications
  consume.
- **Decide** (write the answer down regardless of
  which way it goes): does gossip belong in
  tdns-transport or tdns-mp? Implement the move if
  the answer is "transport"; otherwise leave as-is.
- Start scoping COSE + BHUNK support. Do not expect
  to finish within the lane.
- HPKE revival: scope only.
- tdns-mp absorbs whatever the transport
  simplification leaks back up.

**Exit criterion**: tdns-transport is honest about
what it does and does not know. Downstream repos
(tdns-nm, tdns-es) now have a stable foundation to
build on.

### Phase M5 — tdns tail work

**Goal**: the miscellaneous tdns cleanup that was
explicitly deferred from earlier phases.

This phase has no hard dependency on M4 — most items
can start whenever their preconditions are met — but
they are parked at the end because none of them are
urgent and all of them are lower priority than the
phases above.

- `zd.MP → zd.AppData interface{}` refactor
  (decoupling item 29). Large structural change;
  needed M1–M3 to be done so the demo couldn't break
  on it.
- KeyStateWorker split (decoupling item 25).
- Signing engine MP awareness cleanup (items 22–24).
- `delegation_sync.go:169` investigation — genuinely
  not understood yet, needs a dedicated look.
- CodeRabbit nits.

### Phase M6 — tdns-nm rebuild

**Goal**: tdns-nm builds and runs against the
restructured tdns-transport. KDC/KRS work can resume.

Why last in the lane: blocked on M4. Not blocked on
M5.

- Diagnostic build against current tdns-transport:
  how broken is it? (This step can actually happen
  early — even before M1 — as a cheap experiment to
  measure drift. See §9.)
- Rebuild against the restructured tdns-transport
  once M4 is far enough along to have stable APIs.
- Fix whatever the rebuild surfaces.

**Exit criterion**: tdns-nm is green. tdns-es
implementation (not in scope) is unblocked for H2.

## 5.2 IMR lane

The IMR lane exists to make the IMR *good enough to
depend on* — for its own sake, and because the Vienna
talk on UPDATE-based delegation sync depends on a
trustworthy IMR underneath. All three phases touch the
same code (IMR query path, IMR cache, validation). They
are strictly sequential within the lane.

The lane runs in parallel with the MP lane because it
touches disjoint code. It does not run in parallel with
*itself* — doing DTS and validation polish
simultaneously is an invitation to exactly the kind of
half-state bugs the MP lane is recovering from.

### Phase I1 — Land DTS end-to-end

**Goal**: DNS Transport Signaling works smoothly on
the IMR side, against real upstreams, and the cache
layout is stable enough to build further work on top.

Why it's first: DTS reshapes the IMR cache and query
path. Phase I2 (validation polish) will want to build
on the *reshaped* cache, not the current one. Doing
them in the wrong order means the validation work gets
rebased against itself midway through.

- Complete the outstanding IMR-side signaling work:
  state tracking per upstream, cache entries carrying
  signaling metadata, correct behavior on transport
  changes mid-query.
- Shake-down testing against real upstreams, not just
  local tdns-auth talking to itself.
- Consolidate the cache-adjacent refactoring that DTS
  has already surfaced but left half-applied.
- First order of business in this phase: produce a
  concrete list of what "not yet working smoothly"
  actually means. Without that, the scope is
  open-ended (§8).

**Exit criterion**: DTS works end-to-end in the lab
against at least two independent upstream
implementations. Cache layout is stable.

### Phase I2 — Polish IMR DNSSEC validation

**Goal**: IMR validation is robust enough to be
trusted by code that depends on it (including the
delegation sync client in phase I3).

Why it's second: builds on the cache shape from I1.
Attempting this before DTS is done means doing the
validation work twice.

- **First decision, before any hardening**:
  ValidatorEngine — keep, fold, or delete? Write the
  reasoning down. Subsequent work in the phase
  depends on knowing the answer.
- Harden the validation path against the edge cases
  currently producing spurious results. Start with a
  concrete list of what "spurious" means today.
- If the ValidatorEngine decision is "fold" or
  "delete", do the restructuring now, while the IMR
  code is already under active change. It will be
  harder later.
- NSEC / NSEC3 negative-answer handling fixes.

**Exit criterion**: IMR validation is trustworthy
enough that phase I3 can depend on it without
second-guessing. ValidatorEngine question resolved
one way or the other.

### Phase I3 — Harden UPDATE-based delegation sync

**Goal**: the code behind `draft-johani-dnsop-
delegation-mgmt-via-ddns` is polished and genuinely
tested, ready to be presented at IETF 126 Vienna.

Why it's third: delegation sync's parent discovery
goes through DSYNC lookups, which go through the IMR,
which now needs to be trustworthy. Running this phase
against an unhardened IMR would produce ambiguous
failures — every bug could be in the IMR or in the
delsync code, and we couldn't tell.

- Test against diverse parent server implementations,
  not just tdns-auth talking to itself. This is the
  single most important thing for Vienna credibility.
- Exercise the edge cases: failed UPDATEs, partial
  success, retry semantics, SIG(0) key rotation
  mid-stream.
- CLI / tooling ergonomics so a live demo at the mic
  is credible.
- Update the draft itself against implementation
  experience — versions -06, -07 as the work teaches
  things.
- Dry-run the presentation.

**Exit criterion**: Vienna talk delivered. The room
leaves believing the protocol is real and the code
behind it is real.

### Phase I4 — Post-Vienna follow-up

Whatever the presentation surfaces: questions from
the room, protocol refinements, hallway-conversation
changes. Unscoped by definition.

## 6. Out of Scope / Parked

Items that are explicitly not part of the phases above,
either because they are downstream of everything else or
because they are genuinely not ready to be scheduled:

- **tdns-transport tail items**: COSE + BHUNK support
  and HPKE revival are scoped during phase M4 but will
  not finish there.
- **tdns-es implementation**: downstream of M4 + M6
  (restructured transport + tdns-nm rebuild). The goal
  for this roadmap is only to get the prerequisites in
  place, not to start tdns-es itself.
- **DNS-chat design**
  (`2026-03-22-dns-chat-design-sketch.md`) —
  unscheduled.
- **Signing engine modularization**: the items deferred
  in phase M5 (signing engine MP awareness) are a
  symptom. A proper modularization is a separate
  project, not part of any lane here.
- **CSYNC scanner plan**
  (`2026-03-19-csync-scanner-plan.md`) — partially
  overlaps with the IMR-lane delegation sync work. Pick
  up opportunistically when the overlap becomes
  obvious.
- **Non-signing provider gates Phase 5**
  (`2026-03-20-non-signing-provider-gates.md`) —
  future.
- **Deferred DNS-79/80/81**: agent data bug, ClassANY
  CLI, audit command. Backlog; slot in where they fit.

## 7. Dependency Graph

```
   MP LANE                        IMR LANE
   ──────────                     ─────────

   M1 finish migration            I1 land DTS
          ↓                              ↓
   M2 merge parked branches       I2 polish validation
          ↓                         (ValidatorEngine fate)
   M3 harden for OARC                    ↓
          ↓                       I3 harden UPDATE delsync
      [OARC talk]                        ↓
          ↓                         [IETF Vienna talk]
   M4 tdns-transport                     ↓
        restructure                I4 post-Vienna
          ↓
   M5 tdns tail work
          ↓
   M6 tdns-nm rebuild
          ↓
    (tdns-es, out of scope)

   Inter-lane: no ordering. M1–M3 and I1–I3 run in
   parallel because they touch disjoint code.

   tdns-apps: opportunistic, off both lanes.
```

**Three independent critical paths**, one per lane and
one that spans repos once both lanes are far enough
along:

**MP critical path** (M1 → M2 → M3 → OARC). Strictly
sequential. M1 unblocks M2 unblocks M3. Each phase
depends on the previous having *completed*, not
started.

**IMR critical path** (I1 → I2 → I3 → Vienna). Also
strictly sequential, and for the same reason: each
phase reshapes the same code the next phase will
build on, and running them in the wrong order or
concurrently would produce the same half-state bugs
the MP lane is suffering from.

**Foundation-unblock path** (M4 → M6 → tdns-es). Runs
*after* the MP lane's OARC phase because restructuring
tdns-transport while tdns-mp is under OARC pressure
would be reckless. It does *not* depend on the IMR
lane being finished. tdns-nm rebuild follows M4 because
it needs the new transport shape.

The core design choice is visible in the ordering:
**stabilize what is in flight before opening a new
front**, both within each lane (no interleaving of
phases) and across the roadmap (no tdns-transport
restructuring during MP hardening).

## 8. Risks

- **"No half-state" is easier said than done.** Every
  in-progress migration is a state where some code paths
  disagree about which version of foo() is the real one,
  and every disagreement can produce a spurious bug.
  This is exactly what stalled the combiner-separation
  and mpauditor branches. *Mitigation*: move MP code one
  subsystem at a time, not file by file; after each
  subsystem, run the full lab and fix divergences before
  starting the next. Track "symbols still in tdns" as a
  single burn-down list that drives phase M1's
  definition of done.

- **Migration runs long and eats the hardening
  window.** If M1 is still in progress when OARC
  approaches, M2 cannot merge, M3 cannot start, and the
  demo ends up running on a half-migrated base.
  *Mitigation*: M1 is the single highest-priority work
  on the MP lane until its exit criterion is met.
  Anything that doesn't shrink the legacy footprint is
  deferred.

- **Rebasing the parked branches is painful.** The
  longer they sit, the harder they become to merge.
  Each merge may uncover new half-state bugs even after
  migration "completes". *Mitigation*: dry-run rebases
  near the end of M1 to surface merge pain before M2
  actually starts, even if the branches can't land yet.

- **Regression test gaps.** The MP regression test plan
  has "HOW?" markers in several places (JWK
  verification, heartbeat timing, etc.).
  Unknown-unknowns in the test matrix mean we don't
  know what "done" looks like. *Mitigation*: resolve
  the HOW? markers during M1 (they don't need M1
  finished — the tests just need to be runnable when
  M3 starts).

- **tdns-transport restructuring bleeds into the OARC
  run-up.** The temptation to "just quickly fix the
  import path" or "just quickly move HandleSync" is
  real. Any of these touches tdns-mp at exactly the
  wrong moment. *Mitigation*: the phase M4 TODO list
  lives in a parking doc during M1–M3, and is
  explicitly off-limits.

- **tdns-nm drift is worse than assumed.** Assuming
  "the rebuild is straightforward" is optimistic. The
  longer tdns-nm has been building against a frozen old
  tdns, the more has accumulated. *Mitigation*: do a
  diagnostic build of tdns-nm as a cheap early
  experiment, even during M1, just to measure how
  broken it actually is. This doesn't schedule anything
  — it just replaces a guess with a fact.

- **Public repo narrative.** If anyone reads the repos
  cold around OARC, the mix of `legacy_*` files and
  commented-out blocks will undermine the "clean
  library + clean MP layer" message. *Mitigation*:
  legacy file deletion is part of M2's exit criterion,
  not optional polish.

### Risks specific to the IMR lane

- **Two talks competing for one person's attention.**
  OARC and IETF Vienna are both Johan's talks, and the
  MP hardening (M3) and IMR hardening (I3) are both
  rehearsal-heavy. Even though the codebases are
  disjoint, attention isn't. The ~2 months between OARC
  and Vienna help, but the IMR lane should aim to have
  I1 and I2 finished before M3 starts — that way the
  IMR-lane work that overlaps with OARC prep is the
  relatively self-contained I3 testing work, not active
  restructuring.

- **DTS scope is open-ended.** "Not yet working
  smoothly" is a description, not a scope. The actual
  work to land DTS cleanly could be small or large.
  *Mitigation*: the first action of phase I1 is to
  produce a concrete list of what's broken. If the list
  is large enough to threaten the rest of the lane,
  reduce the I1 goal from "end-to-end DTS" to "DTS
  good enough to not block I2".

- **ValidatorEngine decision is load-bearing.** Keep,
  fold, or delete — each choice shapes the rest of I2
  and possibly the IMR's public API. Making the
  decision late forces rework. *Mitigation*: the
  decision is the *first* action inside I2, explicitly,
  before any hardening work.

- **IMR validation bugs masquerade as delegation sync
  bugs.** During I3 testing, failures could be in the
  IMR (cache, validation, DSYNC lookup) or in the
  delegation sync code itself. Without a trustworthy
  IMR, every delsync failure is ambiguous. *Mitigation*:
  this is exactly why I2 must complete cleanly before
  I3 starts — the whole point of ordering the phases
  is to eliminate this ambiguity.

- **Draft and code drift.** The draft is at -05; every
  IMR-surfaced bug may require a text change, and every
  text change may require code to match. *Mitigation*:
  track draft/code deltas in a single place; refresh
  the draft at least once before Vienna submission,
  ideally twice.

## 9. Open Questions

### MP lane
1. **Gossip ownership.** Does gossip belong in
   tdns-transport (as a generic peer-state service) or
   in tdns-mp (as MP-specific coordination)? The answer
   affects both M1 (don't move gossip into tdns-mp if
   it's going to turn around and leave again in M4)
   and M4 scope. If the decision is unclear at M1
   start, the safe default is to leave gossip in place
   and revisit at M4.
2. **Migration order within M1.** Bottom-up is the
   recommended heuristic (leaf types → authorization /
   discovery → hsync utilities → combiner utilities →
   high-level engines). Is that actually the right
   order given real dependencies, or does the symbol
   burn-down list suggest a different ordering?
3. **Parked-branch rebase strategy.** Rebase
   continuously against the migrating tdns-mp main
   during M1, or let the branches drift and do one
   big rebase at the start of M2? Continuous is more
   work but avoids a cliff.

### IMR lane
4. **DTS scope concretization.** What exactly is "not
   yet working smoothly"? This is the first action
   inside I1, but the answer may shape whether I1 is
   a small phase or a very large one.
5. **ValidatorEngine — keep / fold / delete?** First
   action inside I2. What information is needed to
   make the call?
6. **Delegation sync interop partners.** Which parent
   implementations are realistically available for
   testing during I3? The stronger the "this works
   across X and Y" claim, the better the Vienna talk
   lands.

### Cross-cutting
7. **tdns-nm diagnostic build** — run as a cheap
   experiment during M1 (not a phase, not a
   dependency, just a measurement). Do we have the
   bandwidth?
8. **Long-term home for this doc.** `tdns/docs/`
   (current location, next to the related planning
   docs), a top-level `tdns-project/ROADMAP.md`, or
   its own repo once it becomes a LaTeX/Beamer
   artifact? The current location is slightly awkward
   because the roadmap spans repos but lives inside
   one of them.
