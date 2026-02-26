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
[+] Building 66.1s (22/22) FINISHED                                                                                                               docker:desktop-linux
 => [internal] load build definition from Dockerfile                                                                                                              0.0s
 => => transferring dockerfile: 1.57kB                                                                                                                            0.0s
 => [internal] load metadata for docker.io/library/golang:1.25.2-alpine                                                                                           5.3s
 => [internal] load metadata for docker.io/library/alpine:latest                                                                                                  5.4s
 => [internal] load .dockerignore                                                                                                                                 0.0s
 => => transferring context: 2B                                                                                                                                   0.0s
 => CACHED [stage-1  1/10] FROM docker.io/library/alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659                           0.0s
 => CACHED [builder 1/7] FROM docker.io/library/golang:1.25.2-alpine@sha256:06cdd34bd531b810650e47762c01e025eb9b1c7eadd191553b91c9f2d549fae8                      0.0s
 => [builder 2/7] RUN apk add --no-cache make git gcc musl-dev                                                                                                    4.7s
 => [stage-1  2/10] RUN apk add --no-cache ca-certificates openssl                                                                                                2.8s
 => [stage-1  3/10] WORKDIR /etc/tdns                                                                                                                             0.0s
 => [builder 3/7] WORKDIR /app                                                                                                                                    0.0s
 => [builder 4/7] RUN git clone https://github.com/johanix/tdns.git .                                                                                             3.3s
 => [builder 5/7] RUN make all                                                                                                                                   50.3s
 => [builder 6/7] RUN mkdir -p /usr/local/libexec /usr/local/bin     && find . -type f -name "tdns*" -executable -exec cp {} /usr/local/bin/ ;                    0.4s
 => [builder 7/7] RUN make install                                                                                                                                0.5s
 => [stage-1  4/10] COPY --from=builder /usr/local/bin/tdns-* /usr/local/bin/                                                                                     0.2s
 => [stage-1  5/10] RUN mkdir -p /etc/tdns/certs                                                                                                                  0.1s
 => [stage-1  6/10] COPY --from=builder /app/agent/tdns-agent.sample.yaml /etc/tdns/tdns-agent.yaml                                                               0.0s
 => [stage-1  7/10] COPY --from=builder /app/agent/agent-zones.yaml /etc/tdns/                                                                                    0.0s
 => [stage-1  8/10] COPY --from=builder /app/cli/tdns-cli.sample.yaml /etc/tdns/tdns-cli.yaml                                                                     0.0s
 => [stage-1  9/10] COPY --from=builder /app/utils/ /tmp/utils/                                                                                                   0.0s
 => [stage-1 10/10] RUN tdns-cli db init -f /var/tmp/tdns-agent.db     && cd /tmp/utils     && for cn in localhost. agent.provider. ; do echo $cn | sh gen-cert.  0.2s
 => exporting to image                                                                                                                                            0.3s
 => => exporting layers                                                                                                                                           0.3s
 => => writing image sha256:3ae118b7141299307e8f93f9e73bd1db9b7dd4d8adad83245e5fffc634fbfeda                                                                      0.0s
 => => naming to docker.io/library/tdns                                                                                                                           0.0s

View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/xszczfw3zdzqykmtray03bmse

What's next:
    View a summary of image vulnerabilities and recommendations → docker scout quickview
```

## Running the image built

```
$ docker run -it tdns
*** TDNS tdns-agent mode of operation: "agent" (verbose: false, debug: false)
Verifying existence of TDNS DB file: /var/tmp/tdns-agent.db
2026/02/05 18:49:01 TDNS-AGENT: Validating config for "log" section
2026/02/05 18:49:01 TDNS-AGENT: Validating config for "service" section
2026/02/05 18:49:01 TDNS-AGENT: Validating config for "db" section
2026/02/05 18:49:01 TDNS-AGENT: Validating config for "apiserver" section
2026/02/05 18:49:01 TDNS-AGENT: Validating config for "dnsengine" section
Logging to file: /var/log/tdns/tdns-agent.log
TDNS tdns-agent version v0.8-main-f233696 starting.
Zone "test.net." refers to the non-existing template "parent-primary". Ignored.
Zone "johani.org." refers to the non-existing template "secondary". Ignored.
PRINT AT github.com/johanix/tdns/tdns.(*KeyDB).GenerateKeypair(sig0_utils.go:233)
string("/opt/local/bin/dnssec-keygen -K /tmp -a ED25519 -T KEY -f KSK -n ZONE dns.agent.provider."), #len=89
```
