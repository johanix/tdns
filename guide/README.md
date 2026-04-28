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
  -- Delegation sync, DNS transport signaling, experimental
  record types.

- Future Work (coming soon)
  -- IXFR support, TSIG authentication, scanner integration
  for parent-side delegation sync.
