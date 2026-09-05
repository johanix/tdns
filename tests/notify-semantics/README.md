# Notify-semantics rig — one inbound change, how many outbound changes?

A tdns-auth in the middle of a chain — secondary to someone, primary to someone
else — must answer one question: for **one** change made upstream, how many
times does the zone we serve change, and how many NOTIFYs do our downstreams
get? The intended answer is one and one. Nothing measured it before this.

The rig is a sandwich. `tdns-debug test relay` plays the upstream primary on one
side of the SUT and the downstream secondary on the other, so it authors every
change and observes every consequence: no third-party daemon in the loop, and
nothing inferred from logs.

Design and the full argument: [`docs/2026-09-05-notify-semantics-rig.md`](../../docs/2026-09-05-notify-semantics-rig.md).
The fix these findings feed: [`docs/2026-09-05-signing-publish-notify-correctness.md`](../../docs/2026-09-05-signing-publish-notify-correctness.md).

## Running

```
./setup.sh
./run.sh full        # start, both profiles, stop; non-zero exit on violations
```

Or a profile at a time, against a SUT left running:

```
./run.sh start
./run.sh signing --json
./run.sh mirror
./run.sh stop
```

`ROUNDS=n` and `SETTLE=<dur>` change the series length and the quiet period that
ends a round. Requires `tdns-auth`, `tdns-cli` and `tdns-debug` from `cmdv2/`.

| daemon | port | role |
|---|---|---|
| tdns-auth (the SUT) | 5331 | secondary for both zones, primary to the rig |
| rig upstream / downstream, `relay.test.` | 5361 / 5362 | signing profile |
| rig upstream / downstream, `mirror.test.` | 5371 / 5372 | mirror profile |

Both zones are empty until their rig runs: the rig **is** their only primary.

## The two profiles, and why one is not enough

| zone | SUT config | what it must do |
|---|---|---|
| `relay.test.` | `inline-signing` + a DNSSEC policy | originates content, advances the serial in its own space, signs what it received |
| `mirror.test.` | no signing options at all | originates nothing: serves back exactly what it received, **serial included** |

`inline-signing` is what puts a zone on the may-originate side of
`zoneMayOriginateContent`, and that one option changes every expected answer.
The mirror zone is the control: MUST-NOT-MODIFY applies, so the rig compares the
whole zone — signer-owned records included, since the SUT did not originate
those either — and separately checks that the SOA serial it serves is the one it
received. The historical unconditional `++` made every such secondary drift by
one per refresh, so two masters downstream of one signer advertised different
serials for identical content and edge nodes always fetched from the tdns one,
silently collapsing a redundant pair. Nothing but a serial comparison sees that:
the content is perfect.

Running only the signing profile would leave that class of bug untested, and
running only the mirror profile would test none of the signing semantics the rig
was built for.

## What the verdicts mean

Seven invariants per round, three-valued. `N1` one change, one new published
serial. `N2` one NOTIFY per published serial. `N3` every announced version fully
signed. `N4` content equals upstream. `N5` the deltas express the change. `N6`
the served zone is internally consistent. `N7` no version signed twice. `N8`
(mirror only) the serial is upstream's, verbatim.

**`?` is not a pass.** The rig races the server it measures: a defective
intermediate version lasts as long as a signing pass, and the downstream peer
may arrive after it was superseded. A round whose observations cannot decide an
invariant reports `?` and appears on a SKIPPED line, because not observing a
violation is not evidence there was none. Raising `ROUNDS` is the remedy — the
defects being hunted are states, not races, so they reproduce.

**`-` means the invariant does not apply to this profile** (the signing checks on
`mirror.test.`, `N8` on `relay.test.`). Distinct from `?`, and reported once
rather than per round.

## Section 0 comes first, for the same reason as in `ixfr-interop`

Every verdict is a comparison that passes when two things agree, so a comparator
that cannot report a difference makes every `ok` above it worthless — and the run
looks its cleanest exactly when it is most broken. Before any round runs, the rig
hands each comparator a planted difference and requires it to object. A failure
there is a setup error (exit 2), not a violation: the instrument is broken and
nothing it says about the SUT means anything.

## Observed 2026-09-05, `main` @ `d833c683`

`ROUNDS=3 SETTLE=6s`. Full write-up in the design doc, §9.4.

**`mirror.test.` runs and reports a defect.** Content, deltas and serial are all correct —
a non-signing secondary reproduces its input exactly, MUST-NOT-MODIFY included — but **every
version is announced twice**, at the same serial, in every round:

```
round change                       notifies  serials  states  verdicts
1     add +[r001.mirror.test. 360…        2        1       1  N1:ok N2:FAIL N3:- N4:ok N5:ok N6:- N7:- N8:ok
```

The two NOTIFYs come from `refreshengine.go:911` and from `zone_mutation.go:601`, the latter
firing at the end of every publish. Note that **only the first of them logs anything on
success** — an operator reading the SUT's log sees one NOTIFY per change and concludes the
semantics are correct. Counting packets at a listener the rig owns is what finds the second.

Because this profile does not sign, it isolates the duplicate announcement from every signing
defect, which makes it the useful one to validate a NOTIFY fix against.

**`relay.test.` does not run yet.** The zone transfers in, but its DNSSEC policy is not bound
by the time `OnFirstLoad` runs, so `SetupZoneSigning` fails and `ZoneTransferOut` then refuses
every transfer — "configured to be signed but the SOA has no RRSIG". The policy resolves fine
at parse. Root cause not isolated; see §9.4. Until it is, the signing profile reports a setup
error rather than a verdict, which is the correct behaviour: an instrument that cannot observe
must not report a pass.

The expectation for the signing profile once it runs is that it FAILS N1, N2, N3 and N7 — four
NOTIFYs and three serials for one inbound change — while N4 and N5 pass throughout. That is
the defect the companion design document fixes; the rig exists to measure it before and after.
