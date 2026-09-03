# Upgrade note: HSYNCPARAM key numbers now match the draft (2026-09-03)

**Audience:** anyone serving or consuming a zone that carries an HSYNCPARAM
record. If no zone in your deployment has one, there is nothing to do.

## What changed

The HSYNCPARAM key numbers were wrong. `v2/core/rr_hsyncparam.go` assigned them
in a different order from the one
`draft-leon-dnsop-signaling-zone-owner-intent` gives in its "HSYNCPARAM Keys"
registry:

| Key | Was | Draft, and now |
|-----|-----|----------------|
| `servers` | 2 | **0** |
| `signers` | 3 | **1** |
| `auditors` | 7 | **2** |
| `nsmgmt` | 0 | **3** |
| `parentsync` | 1 | **4** |
| `suffix` | 6 | **5** |
| `pubkey` | 4 | **6** |
| `pubcds` | 5 | **7** |

These numbers are wire format: the RDATA is a sequence of
`<2-byte key><2-byte length><value>` pairs sorted by key number, exactly like
SVCB, so a receiver decodes the record *by* them. tdns and tdns-mp shared the
same `core` package, so nothing misbehaved between them — but the records tdns
put on the wire were not the records the draft describes, and would not have
interoperated with a second implementation.

## What is NOT affected

- **Zone files.** Presentation format names keys (`servers="fox,hare"`), never
  numbers. An existing zone file loads to exactly the same record as before.
- **The delta journal.** `ZoneDelta.rr` is `TEXT` — presentation format — so
  stored deltas replay unchanged.
- **Presentation output.** `HSYNCPARAM.String()` walks the value list in the
  order it was built, so a record parsed from a zone file still prints its keys
  in the order the operator wrote them. Only a record decoded from the wire
  prints in key order, and that order has changed.
- **The API and CLI.** Both work in presentation format throughout.

## What IS affected: a transfer between two versions — action required

An HSYNCPARAM record that crosses the wire (AXFR, IXFR, UPDATE, or a query
response) between a pre-change and a post-change instance is decoded with the
wrong key numbers.

Most of those combinations fail loudly, because the value shapes do not match:
`nsmgmt` and `parentsync` carry exactly one byte, the flags carry none, and a
label list carries neither. A new `pubkey` (6, no value) read as an old `suffix`
(6) is rejected as an invalid DNS label; an old `pubkey` (4) read as a new
`parentsync` (4) is rejected on length. In those cases the RR is refused and
logged rather than silently misread.

Two combinations can be decoded without erroring:

- An old `nsmgmt` (0) or `parentsync` (1) — one byte — read by a new instance as
  `servers` or `signers`, giving a one-character provider label. The draft says
  a label matching no HSYNC record is logged and treated as absent, so the
  effect is an ignored role list, not a wrong one.
- A new `servers` (0) or `signers` (1) whose whole value is a **single
  character** (`servers="a"`) read by an old instance as `nsmgmt`/`parentsync`,
  yielding an out-of-range mode value. Single-character provider labels are
  unusual, and this is the one case that is silently wrong rather than empty.

**Migration: upgrade together.** Any set of instances that exchange a zone
containing HSYNCPARAM — primaries, their secondaries, and any tdns-mp component
reading the same zone — should be upgraded in one pass. There is no
compatibility mode: the previous numbers were simply incorrect, and keeping a
translation for them would mean keeping a wrong encoding alive.

tdns-mp consumes `core` from a published `tdns/v2` version, so it picks this up
when it is re-pinned, not before.

## Guardrail

`TestHsyncparamKeyNumbersMatchTheDraft` (`v2/core/rr_hsyncparam_test.go`) names
all eight numbers, and `TestHsyncparamWireEncoding` asserts the RDATA bytes for
a three-key record. The drift happened because no test named a number.
