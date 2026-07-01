# TDNS Applications

TDNS includes several applications built on the TDNS Go library.

| Application     | Binary       | Description                              |
|-----------------|--------------|------------------------------------------|
| tdns-auth       | tdns-auth    | Authoritative DNS nameserver             |
| tdns-agent      | tdns-agent   | Single-provider delegation-sync agent    |
| tdns-imr        | tdns-imr     | Recursive DNS nameserver (IMR)           |
| tdns-cli        | tdns-cli     | Management CLI for all TDNS services     |
| dog             | dog          | DNS query tool with extended RR support  |

For the multi-provider applications (tdns-mpagent,
tdns-mpcombiner, tdns-mpsigner, tdns-mpcli), see the
[tdns-mp Applications](../../tdns-mp/guide/applications.md)
document.

## tdns-auth -- Authoritative Nameserver

An authoritative DNS nameserver with support for DNSSEC
online signing and named signing policies, inbound/outbound
NOTIFY and AXFR (optionally TSIG-authenticated, with NSD-style
access-control lists and multiple primaries per secondary
zone), SIG(0) signed dynamic updates, delegation
synchronization (both parent and child roles), DNS catalog
zones (RFC 9432), dynamic zone management via REST API, and
zone templates.

[Full documentation](app-tdns-auth.md)

## tdns-agent -- Delegation-Sync Agent

A secondary-only server that detects changes to a child
zone's delegation data (NS, glue, DS) and synchronizes
those changes with the parent zone via generalized NOTIFY
or SIG(0)-signed DNS UPDATE, as advertised by the parent's
DSYNC RRset.

Full documentation (coming soon).

## tdns-imr -- Recursive Nameserver

A recursive DNS nameserver (Iterative Mode Resolver). Does
recursive lookups with caching, supports modern transports
(DoT, DoH, DoQ) in addition to Do53, and provides an
interactive CLI for manual queries and cache inspection.

[Full documentation](app-tdns-imr.md)

## tdns-cli -- Management CLI

A CLI tool to interact with TDNS services via their REST
APIs. Sub-commands cover zone management (signing, NSEC
chains, reload, and dynamic add/modify/delete), DNS UPDATE
composition, keystore management (DNSSEC, SIG(0), and TSIG
keys) and truststore management, generalized NOTIFY, and
DSYNC inspection.

[Full documentation](app-tdns-cli.md)

## dog -- DNS Query Tool

A DNS query tool similar to dig, with native support for
additional record types that TDNS implements (DSYNC, DELEG,
TSYNC, SVCB, and others). CLI syntax is as close to dig as
possible.

[Full documentation](app-dog.md)
