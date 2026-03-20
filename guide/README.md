# TDNS Guide

TDNS is a set of DNS libraries written in Go together with a
number of applications built on those libraries.

The applications include an authoritative nameserver, a
recursive nameserver, a dig-like query tool with extensions
for additional DNS record types, and several more specialized
servers for multi-provider DNSSEC coordination.

## Documents

- [TDNS Applications](applications.md)
  -- Overview of all applications (tdns-auth, tdns-agent,
  tdns-combiner, tdns-imr, tdns-cli, dog) with links to
  detailed documentation for each.

- [Multi-Provider QuickStart Guide](multi-provider-quickstart.md)
  -- Get a single-host multi-provider setup running with
  agent, combiner and signer serving an example zone.

- [Multi-Provider Advanced Topics](multi-provider-advanced.md)
  -- Parent synchronization, provider zones, provider-to-provider
  sync, gossip protocol, leader elections.

- [TDNS Special Features and Extensions](special-features.md)
  -- Delegation sync, DNS transport signaling, experimental
  record types, multi-signer DNSSEC.

- [MP Change Tracking Semantics](mp-change-tracking-semantics.md)
  -- Design decisions for how multi-provider changes are
  tracked, confirmed, and routed. Corner cases for
  non-signing providers.

- Future Work (coming soon)
  -- IXFR support, API transport for agent-agent comms,
  TSIG authentication, HPKE encryption.
