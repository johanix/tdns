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
  `split-algorithms` and `large-algorithms`),
  [tdns-imr](config-tdns-imr.md) (trust anchors, stub zones,
  forward zones with per-upstream transport/port/TLS,
  the `imrengine.tuning.*` knobs) and
  [tdns-agent](config-tdns-agent.md) (placeholder). The tdns-auth
  page also covers ZONEMD (RFC 8976): `publish-zonemd`,
  `verify-zonemd`, the `zonemd:` parameter block including
  `wire-cache-max-bytes`, and checking a digest by hand with
  `zone zonemd status|verify` or `dog +zonemd`.

- [Changing Zone Content: DDNS and the Management API](zone-updates.md)
  -- The two channels that change a running primary zone
  without touching its file: RFC 2136 UPDATE and the
  management API. How they differ (and why `--via` has no
  default), the five statements (`addrr`, `delrr`,
  `delrrset`, `delname`, `replacerrset`) and their sharp
  edges, what "applied" promises, durability via the zone
  file and the delta journal, the journal CLI
  (`status`/`list`/`truncate`/`purge`) and replaying an
  instruction file, `freeze`/`thaw`/`sync`, and the
  refusals. For a *child's* delegation data in a parent
  zone see delegation sync in
  [special-features.md](special-features.md#1-automatic-delegation-synchronization)
  instead.

- [The tdns Keystore](keystore.md)
  -- What the keystore is and everything you can do with
  it: the three key classes (DNSSEC, SIG(0), TSIG), where
  it lives, key states, the full `tdns-cli auth keystore`
  command tree, and getting key material out and back --
  `bulk-export`/`bulk-import`, the on-disk manifest format,
  and `keystore.preload` for restoring keys at startup
  before any zone is parsed.

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
  practice. Companion to the [XoT transfer guide](xot.md).

- [XFR over TLS (XoT)](xot.md)
  -- Setting up encrypted, mutually-authenticated zone
  transfers (RFC 9103): the `downstream-auth:` ladder, the
  peer's shared TLS fields, and the outbound `upstreams:` fields.
  Complete worked examples for `tls-pkix`, `tls-pin` (SPKI)
  and `tls-dane`, each with `tdns-cli cert` provisioning and
  `dog` test commands.

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
