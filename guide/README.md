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

- [TDNS Configuration Guide](configuration.md)
  -- How to configure each application, starting from a
  minimal working example. Conventions common to all apps
  (config file location, `include:`, unknown-key warnings,
  zone quarantining), then per-application pages:
  [tdns-auth](config-tdns-auth.md) (TSIG keys, the
  `allow-notify:` / `downstreams:` ACLs, zone declarations
  and options, the zone template system, the `dnsengine:`
  block, DNSSEC policies including policy templates,
  `split_algorithms` and `large_algorithms`),
  [tdns-imr](config-tdns-imr.md) (trust anchors, stub zones,
  the `imrengine.tuning.*` knobs) and
  [tdns-agent](config-tdns-agent.md) (placeholder).

- [TDNS Special Features and Extensions](special-features.md)
  -- Delegation sync (parent side, child side, and the
  agent-as-proxy path for DSYNC-unaware primaries, including
  the DSYNC scheme dispatch, the NOTIFY scanner, and the
  pluggable delegation backends), DNS transport signaling,
  experimental record types, and post-quantum algorithm
  support (ML-DSA / SLH-DSA / Falcon / MAYO / SNOVA for both
  SIG(0) and DNSSEC).

- [Certificate Provisioning: the tdns Minimal CA](cert-provisioning.md)
  -- Operator how-to for `tdns-cli cert`: the one-shot
  `cert init` for the local tdns-auth, upgrading existing
  self-signed certificates to CA-signed ones (locally and
  on remote hosts, keeping the key so pins and TLSA records
  stay valid), creating the `ca-file` for each kind of
  certificate, renewal/rotation, and what the deliberately
  minimal scope (no CRL/OCSP/renewal automation) means in
  practice. Companion to the XoT transfer configuration in
  the tdns-auth config guide.

- [Agent as a DSYNC proxy](agent-dsync-proxy.md)
  -- Operator how-to for running tdns-agent as a secondary
  that forwards delegation-sync (NOTIFY and/or signed DNS
  UPDATE) to the parent on behalf of a DSYNC-unaware primary
  (BIND/Knot/NSD): when to use it, configuration, the
  change mapping, the UPDATE KEY-bootstrap (`zone proxy-key`),
  limitations, and verification.

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

- [Structured Aggressive Testing with tdns-debug](testing.md)
  -- Developer framework for aggressive correctness testing of a
  running tdns server: the actor/ledger/checker architecture, the
  `test churn` zone-snapshot correctness family and its invariants,
  the provision/run/cleanup lifecycle, and a worked A/B example that
  catches a real tearing bug and confirms its fix. A developer tool,
  not an operator tool; expected to grow more test families over time.

- Future Work (coming soon)
  -- IXFR support.
