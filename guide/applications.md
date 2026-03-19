# TDNS Applications

TDNS includes several applications built on the TDNS Go library.

| Application     | Binary            | Description                              |
|-----------------|-------------------|------------------------------------------|
| tdns-auth       | tdns-authv2       | Authoritative DNS nameserver             |
| tdns-agent      | tdns-agentv2      | Multi-provider coordination agent        |
| tdns-combiner   | tdns-combinerv2   | Zone combiner for multi-provider setups  |
| tdns-imr        | tdns-imrv2        | Recursive DNS nameserver (IMR)           |
| tdns-cli        | tdns-cliv2        | Management CLI for all TDNS services     |
| dog             | dogv2             | DNS query tool with extended RR support  |

## tdns-auth -- Authoritative Nameserver

An authoritative DNS nameserver with support for DNSSEC
online signing, inbound/outbound NOTIFY and AXFR, SIG(0)
signed dynamic updates, delegation synchronization (both
parent and child roles), DNS catalog zones (RFC 9432),
dynamic zone management via REST API, and zone templates.

Also serves as the DNSSEC signer in multi-provider setups
(configured with `multi-provider.role: signer`).

[Full documentation](app-tdns-auth.md)

## tdns-agent -- Multi-Provider Agent

A secondary-only server that coordinates multi-provider
DNSSEC operations. Watches HSYNC3 records to discover and
communicate with remote agents, synchronizes NS, DNSKEY,
CDS and CSYNC RRsets across providers, and detects changes
to delegation information for parent synchronization.

[Full documentation](app-tdns-agent.md)

## tdns-combiner -- Zone Combiner

A single-purpose service that receives a zone via inbound
zone transfer (from the zone owner's authoritative server),
replaces the four apex RRsets (NS, DNSKEY, CDS, CSYNC) with
data received from the agent, and publishes the combined
zone via outbound zone transfer to the signer.

[Full documentation](app-tdns-combiner.md)

## tdns-imr -- Recursive Nameserver

A recursive DNS nameserver (Iterative Mode Resolver). Does
recursive lookups with caching, supports modern transports
(DoT, DoH, DoQ) in addition to Do53, and provides an
interactive CLI for manual queries and cache inspection.

[Full documentation](app-tdns-imr.md)

## tdns-cli -- Management CLI

A CLI tool to interact with all TDNS services via their
REST APIs. Sub-commands cover zone management (signing,
NSEC chains, reload), DNS UPDATE composition, keystore
and truststore management, generalized NOTIFY, DSYNC
inspection, agent status, gossip state, and more.

[Full documentation](app-tdns-cli.md)

## dog -- DNS Query Tool

A DNS query tool similar to dig, with native support for
additional record types that TDNS implements (DSYNC, DELEG,
HSYNC3, HSYNCPARAM, SVCB, and others). CLI syntax is as
close to dig as possible.

[Full documentation](app-dog.md)
