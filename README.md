# tdns

TDNS started as a small authoritative nameserver written in Go to be used various
experiments and tests. It used to be intended to be really simple to understand
and modify as needed. Now the traditional authoritative nameserver part is still
almost trivial, but it has sprouted a bunch of additional functionality on the side.

The repo consists of several separate programs:

## tdns-auth
A simple authoritative DNS nameserver with some special features. 
See **auth/README.md**

## tdns-imr
An extremely simplistic iterative mode resolver, i.e. recursive nameserver.
The special features for **tdns-imr** are primarily in the ability to understand and
utilize so-called "DNS transport signals" from authoritative nameservers. Another
feature is that it is possible to run tdns-imr in "interactive mode", where it is
possible to both issue queries (of course) but also interactively examine various internal data
structures (most interesting are usually different sections of the cache).

## tdns-agent
A version of **tdns-server** that must be configured as a secondary, downstream
of whatever is in use as the primary. The point with **tdns-agent** is to enable 
a zone to safely use the new synchronisation mechanisms without any requirement
to change the existing zone generation and publication setup. See **agent/README.md**.

## tdns-combiner
A DNS zone transfer proxy, intended to sit between a "zone owner" and a signer
(like tdns-server configured to do online-signing). In addition to acting as a
proxy **tdns-combiner** is able to manage four specific apex RRsets that may (according
to policy) be automatically managed: these are the DNSKEY, NS, CDS and CSYNC RRsets.

## tdns-cli
A CLI tool to interact with the different server applications (**tdns-server**,
**tdns-agent** and **tdns-combiner**) via a REST-ful API. See **cli/README.md**.
It would be possible to also intersct with **tdns-imr**, but as the IMR already has its own
interactive mode that is not needed.

## dog
A CLI tool that seems like a very simplistic cousin to
the much more powerful tool "dig", which is part of the BIND9
distribution from ISC. The primary raison d'etre for **dog** is that
it understands the experimental new record types **DSYNC** **HSYNC** and **DELEG**.
Another useful feature is that **dog** speaks all sorts of DNS transports, including
DoT, DoQ and DoH.

# General TDNS Features:

## Support for SIG(0) key management (create, roll, use, remove)

In the originator end (typically the child zone, with the "keystore") SIG(0) key pairs
are automatically generated when needed. The public key is communicated to the receiver
end (typically the parent, with the "truststore"). There is also support for a novel EDNS(0)
option, called KeyState, which enables the two parties to communicate questions and responses
about the state of a public key (like whether the key has been successfully validated or not,
if it is trusted, etc.

## Support for various experimental new DNS record types

tdns has a complete implementation of the DSYNC record, but as that is now standardized (RFC 9859)
it cannot be considered experimental anymore. There are also multiple variants of HSYNC records (used to
specify "zone owner intent" in multi-provider setups) and the authoritative part of the DELEG record.
For transport signaling without using SVCB there is another experimental record, tentatively called
TSYNC.

## Support for new DNS transports (in addition to Do53): DoT, DoH, DoQ.

All three are supported in tdns-auth (the authoritative server) and in dog (the testing tool similar
to dig). The recursive server is able to issue queries over new transports, but does not yet listen.

## Support for DNS transport signaling

The support in the authoritative end is more robust than the support in **tdns-imr**, but both have
enough support to be able to agree on upgrading connections to use integrity protecting transports.

## Automatic Delegations Synchronization via DNS UPDATE.

This functionality is built on top of the SIG(0) key management support in combination with the new
**DSYNC** record type.

## DNS Multi-Provider Configuration via the HSYNC RRset.

This is built using the **HSYNC** RRset (to express zone owner intent) in combiation with
**tdns-agent** (for communication and synchronization between providers) and **tdns-combiner** 
(for managing updates to the specific RRsets that require synchronization across providers).

## Distributed Multi-signer Synchronization.

Multi-signer is in practice just a special case of multi-provider where more than one provider
is requested by the zone owner to sign the zone. this requires additional synchronization among the
providers using the same mechanisms as for all multi-provider synchronization.

