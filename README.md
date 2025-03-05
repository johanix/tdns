# tdns

tdns is a small authoritative nameserver written in Go to be used various
experiments and tests. It used to be intended to be really simple to understand
and modify as needed. Now the traditional authoritative nameserver part is still
almost trivial, but it has sprouted a bunch of additional functionality on the side.

The repo consists of several separate programs:

## tdns-server
A simple authoritative DNS nameserver with some special features. 
See **server/README.md**

## tdns-agent
A version of **tdns-server** that must be configured as a secondary, downstream
of whatever is in use as the primary. The point with **tdns-agent** is to enable 
a zone to safely use the new synchronisation mechanisms without any requirement
to change the existing zone generation and publication setup. See **agent/README.md**.

## tdns-combiner
A DNS zone transfer proxy, intended to sit between a "zone owner" and a signer
(like tdns-server configured to do online-signing). In addition to acting as a
proxy tdns-combiner is able to manage four specific apex RRsets that may (according
to policy) be automatically managed: these are the DNSKEY, NS, CDS and CSYNC RRsets.

## tdns-cli
A CLI tool to interact with the different server applications (**tdns-server**,
**tdns-agent** and **tdns-combiner**) via a REST-ful API. See **cli/README.md**

## dog
A CLI tool that seems like a very simplistic cousin to
the much more powerful tool "dig", which is part of the BIND9
distribution from ISC. The primary raison d'etre for "dog" is that
it understands the experimental new record types **DSYNC** **HSYNC** and **DELEG**.

# tdns features:

## Automatic Delegations Synchronization via DNS UPDATE

## DNS Provider Configuration via the HSYNC RRset

## Distributed Multi-signer Synchronization




