# TDNS Guide

TDNS is a set of DNS libraries written in Go together with a
number of applications built on those libraries.

The applications include an authoritative nameserver, a
recursive nameserver, a dig-like query tool with extensions
for additional DNS record types, a single-provider agent
for delegation synchronization, and a management CLI.

For multi-provider DNSSEC coordination (RFC 8901), see the
companion [tdns-mp Guide](../../tdns-mp/guide/README.md).

## Documents

- [TDNS Applications](applications.md)
  -- Overview of all tdns applications (tdns-auth,
  tdns-agent, tdns-imr, tdns-cli, dog) with links to
  detailed documentation for each.

- [TDNS Special Features and Extensions](special-features.md)
  -- Delegation sync (parent side, child side, and the
  agent-as-proxy path for DSYNC-unaware primaries, including
  the DSYNC scheme dispatch, the NOTIFY scanner, and the
  pluggable delegation backends), DNS transport signaling,
  experimental record types, and post-quantum algorithm
  support (ML-DSA / SLH-DSA / Falcon / MAYO / SNOVA for both
  SIG(0) and DNSSEC).

- [Agent as a DSYNC proxy](agent-dsync-proxy.md)
  -- Operator how-to for running tdns-agent as a secondary
  that forwards NOTIFY(CDS/CSYNC) to the parent on behalf of
  a DSYNC-unaware primary (BIND/Knot/NSD): when to use it,
  configuration, the change-to-NOTIFY mapping, limitations,
  and verification.

- [Automatic DNSSEC Rollovers](key-rollover.md)
  -- Operator manual for all three rollover kinds:
  parent-coordinated **KSK** rollover (the bulk -- policy
  YAML, the `auto-rollover` CLI tree, status output, PQ-safe
  parent UPDATEs, DSYNC-aware dispatch and verification, the
  three-knob mental model, worked examples, and the
  failure-category model), local **ZSK** rollover, and
  **algorithm** rollover (the relaxed-mode ZSK alg roll via
  `policy-change` + `asap --zsk`, with the `completeness`
  knob and the KSK/CSK/both-role/strict refusals).

- [Rollover Timing Equations](rollover-timing-equations.md)
  -- Canonical reference for the cache-flush invariants,
  the parent-DS-RRset contract, and the timing equations
  (E1-E13) that the rollover engine must satisfy.
  Companion to the key-rollover guide above; required
  reading when changing engine timing behaviour.

- Future Work (coming soon)
  -- IXFR support, TSIG authentication, and UPDATE-scheme
  delegation-sync proxying (the NOTIFY-scheme proxy ships
  now; see the agent-as-proxy guide above).
