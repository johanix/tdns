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

# Running agent in Docker

## Building the image:

```
$ docker buildx build --no-cache -t tdns - < Dockerfile
[+] Building 137.3s (24/24) FINISHED                                                                                                                                                                                         docker:desktop-linux
 => [internal] load build definition from Dockerfile                                                                                                                                                                                         0.0s
 => => transferring dockerfile: 1.83kB                                                                                                                                                                                                       0.0s
 => [internal] load metadata for docker.io/library/alpine:latest                                                                                                                                                                             1.0s
 => [internal] load metadata for docker.io/library/golang:1.25.2-alpine                                                                                                                                                                      0.0s
 => [internal] load .dockerignore                                                                                                                                                                                                            0.0s
 => => transferring context: 2B                                                                                                                                                                                                              0.0s
 => CACHED [stage-1  1/12] FROM docker.io/library/alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659                                                                                                      0.0s
 => CACHED [builder 1/7] FROM docker.io/library/golang:1.25.2-alpine                                                                                                                                                                         0.0s
 => [stage-1  2/12] RUN apk add --no-cache ca-certificates openssl                                                                                                                                                                           5.3s
 => [builder 2/7] RUN apk add --no-cache make git gcc musl-dev                                                                                                                                                                              43.1s
 => [stage-1  3/12] WORKDIR /etc/tdns                                                                                                                                                                                                        0.0s
 => [builder 3/7] WORKDIR /app                                                                                                                                                                                                               0.0s
 => [builder 4/7] RUN git clone --branch multi-signer-support-3 https://github.com/johanix/tdns.git .                                                                                                                                        6.9s
 => [builder 5/7] RUN make all                                                                                                                                                                                                              82.5s
 => [builder 6/7] RUN mkdir -p /usr/local/libexec /usr/local/bin     && find . -type f -name "tdns*" -executable -exec cp {} /usr/local/bin/ ;                                                                                               0.5s
 => [builder 7/7] RUN make install                                                                                                                                                                                                           0.9s
 => [stage-1  4/12] COPY --from=builder /usr/local/bin/tdns-* /usr/local/bin/                                                                                                                                                                0.4s
 => [stage-1  5/12] RUN mkdir -p /etc/tdns/certs                                                                                                                                                                                             0.1s
 => [stage-1  6/12] COPY --from=builder /app/cmdv2/agentv2/tdns-agent.sample.yaml /etc/tdns/tdns-agentv2.yaml                                                                                                                                0.0s
 => [stage-1  7/12] COPY --from=builder /app/cmdv2/agentv2/agent-zones.yaml /etc/tdns/                                                                                                                                                       0.0s
 => [stage-1  8/12] COPY --from=builder /app/cmdv2/cliv2/tdns-cli.sample.yaml /etc/tdns/tdns-cli.yaml                                                                                                                                        0.0s
 => [stage-1  9/12] COPY --from=builder /app/cmdv2/authv2/tdns-auth.sample.yaml /etc/tdns/tdns-authv2.yaml                                                                                                                                   0.0s
 => [stage-1 10/12] COPY --from=builder /app/utils/ /tmp/utils/                                                                                                                                                                              0.0s
 => [stage-1 11/12] RUN tdns-cli db init -f /var/tmp/tdns-agent.db     && cd /tmp/utils     && for cn in localhost. agent.provider. agent.jose. ; do echo $cn | sh gen-cert.sh ; done     && cp *.key *.crt /etc/tdns/certs/     && rm -rf   0.3s
 => [stage-1 12/12] RUN tdns-cliv2 keys generate --jose                                                                                                                                                                                      0.1s
 => exporting to image                                                                                                                                                                                                                       0.4s
 => => exporting layers                                                                                                                                                                                                                      0.4s
 => => writing image sha256:58d76957faa361ebc7d2ab2d707b74101046957f045b8907ae409f3aada51720                                                                                                                                                 0.0s
 => => naming to docker.io/library/tdns                                                                                                                                                                                                      0.0s

View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/ppi50nbelmoja3erifxhb5k0h

What's next:
    View a summary of image vulnerabilities and recommendations → docker scout quickview
```

## Running the image built

```
$ docker run -it tdns
*** TDNS tdns-agentv2 version v0.8-multi-signer-support-3-ad46c23 mode of operation: "agent" (verbose: false, debug: false)
2026/03/05 19:42:39 WARN unknown config keys ignored (possible misspellings) subsystem=config keys="[Service.refresh Service.maxrefresh server delegationsync validator common resolver keybootstrap]"
2026/03/05 19:42:39 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=log
2026/03/05 19:42:39 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=service
2026/03/05 19:42:39 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=db
2026/03/05 19:42:39 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=apiserver
2026/03/05 19:42:39 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=dnsengine
Logging to file: /var/log/tdns/tdns-agent.log
TDNS tdns-agentv2 version v0.8-multi-signer-support-3-ad46c23 starting.
Zone "test.net." refers to the non-existing template "parent-primary". Ignored.
Zone "johani.org." refers to the non-existing template "secondary". Ignored.
PRINT AT github.com/johanix/tdns/v2.(*KeyDB).GenerateKeypair(sig0_utils.go:232)
string("/opt/local/bin/dnssec-keygen -K /tmp -a ED25519 -T KEY -f KSK -n ZONE dns.agent.provider."), #len=89
```

