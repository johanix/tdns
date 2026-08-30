# tests/ — interoperability rigs

Small, committed rigs that stand tdns next to **other implementations** and
check that they agree. Each subdirectory is one rig: a handful of config
files, the zones they serve, a `setup.sh` that seeds a work tree, and a
`run.sh` that starts it and asserts the result.

| Rig | Covers |
|---|---|
| `xot-interop/` | RFC 9103 XFR-over-TLS against NSD, BIND9 and Knot, in both transfer roles, over PKIX and SPKI-pin authentication |
| `zonemd/` | RFC 8976 ZONEMD as a gate on inbound transfer, against Knot: valid, wrong, absent and uncheckable digests |
| `ixfr-interop/` | RFC 1995 incremental transfer against BIND9, in both roles and in cascade: a long update series must leave every server in the chain holding an identical zone, reached incrementally |

## Relative to cmdv2/debug/

`tdns-debug` and its `rig/` exist to test tdns hard against *itself* and its
own invariants — a ledger of states a correct server could be in, driven at
load. These rigs answer a different question: **does another implementation
accept what tdns produces, and does tdns accept what another implementation
produces?** That question needs a second implementation in the room, and its
answer is a config file plus a log line rather than a Go assertion.

The overlap is deliberate at `cmdv2/debug/rig/`, which already pairs
tdns-auth with a real BIND9 secondary for the IXFR/journal work. It stays
where it is: it is evidence for a specific set of PRs and belongs beside them.
What lands here is interop coverage that is not tied to one change.

## Conventions

- **A fixed work root per rig**, `/var/tmp/<rigname>/`, matching
  `cmdv2/debug/rig`. Committed configs name absolute paths under it, so they
  are readable as-is rather than through a template layer.
- **No key material in the repo.** `setup.sh` mints whatever CA and
  certificates the rig needs. Anything whose value changes per issuance — a
  certificate pin, for instance — is a `@PLACEHOLDER@` in the committed
  config and is substituted when the work tree is seeded.
- **`run.sh verify` returns non-zero on failure** and prints one PASS/FAIL
  line per assertion, so a rig can be run from CI or by hand and read the
  same way.
- **Negative cases are part of the rig, not an afterthought.** A rig that only
  shows things working cannot tell you whether the checking it is exercising
  is switched on. Every authentication mechanism covered has a matching
  deliberately-wrong configuration that must be refused.
- Paths to the binaries are overridable by environment variable (`TDNS`,
  `KNOT`, `NSD`, `NAMED`, `RIG`) so a rig can run somewhere other than the
  machine it was written on.
