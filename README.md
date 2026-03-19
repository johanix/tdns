# TDNS

TDNS is a set of DNS libraries written in Go together with
several applications built on those libraries.

The applications include an authoritative nameserver
(tdns-auth), a recursive nameserver (tdns-imr), a dig-like
query tool with support for experimental record types (dog),
a management CLI (tdns-cli), and specialized servers for
multi-provider DNSSEC coordination (tdns-agent, tdns-combiner).

## Key Features

- DNSSEC online signing with automatic key management
- Automatic delegation synchronization via DNS UPDATE (RFC 9859)
- Multi-provider DNSSEC (RFC 8901) with agent-to-agent gossip,
  leader election, and zone combiner
- Experimental record types: DSYNC, HSYNC3, HSYNCPARAM, DELEG
- Modern DNS transports: DoT, DoH, DoQ (in addition to Do53)
- DNS transport signaling between auth servers and resolvers
- DNS Catalog Zones (RFC 9432)
- SIG(0) key management with KeyState EDNS(0) bootstrapping

## Documentation

See the [guide/](guide/) directory:

- [TDNS Applications](guide/applications.md) -- overview of
  all applications with links to detailed docs
- [Multi-Provider QuickStart](guide/multi-provider-quickstart.md)
  -- single-host setup guide
- [Multi-Provider Advanced Topics](guide/multi-provider-advanced.md)
  -- delegation sync, provider zones, gossip, elections
- [Special Features and Extensions](guide/special-features.md)
  -- delegation sync, transport signaling, experimental RR types
- Future Work (coming soon)

## Building

```sh
cd cmdv2
make
sudo make install
```

Requires Go 1.22+.
