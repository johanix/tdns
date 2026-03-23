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

See the [TDNS Guide](guide/README.md):

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

# General TDNS Features:

# Running agent in Docker

## Building the image:

```
$ docker buildx build --no-cache -t tdns - < Dockerfile
[+] Building 132.7s (24/24) FINISHED                                                                                                                                                                                                                                                                     docker:desktop-linux
 => [internal] load build definition from Dockerfile                                                                                                                                                                                                                                                                     0.0s
 => => transferring dockerfile: 1.81kB                                                                                                                                                                                                                                                                                   0.0s
 => [internal] load metadata for docker.io/library/golang:1.25.2-alpine                                                                                                                                                                                                                                                  0.0s
 => [internal] load metadata for docker.io/library/alpine:latest                                                                                                                                                                                                                                                         1.3s
 => [internal] load .dockerignore                                                                                                                                                                                                                                                                                        0.0s
 => => transferring context: 2B                                                                                                                                                                                                                                                                                          0.0s
 => CACHED [stage-1  1/12] FROM docker.io/library/alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659                                                                                                                                                                                  0.0s
 => CACHED [builder 1/7] FROM docker.io/library/golang:1.25.2-alpine                                                                                                                                                                                                                                                     0.0s
 => [stage-1  2/12] RUN apk add --no-cache ca-certificates openssl                                                                                                                                                                                                                                                       5.3s
 => [builder 2/7] RUN apk add --no-cache make git gcc musl-dev                                                                                                                                                                                                                                                          41.7s
 => [stage-1  3/12] WORKDIR /etc/tdns                                                                                                                                                                                                                                                                                    0.0s
 => [builder 3/7] WORKDIR /app                                                                                                                                                                                                                                                                                           0.0s
 => [builder 4/7] RUN git clone --branch main https://github.com/johanix/tdns.git .                                                                                                                                                                                                                                      7.1s
 => [builder 5/7] RUN make all                                                                                                                                                                                                                                                                                          79.8s
 => [builder 6/7] RUN mkdir -p /usr/local/libexec /usr/local/bin     && find . -type f -name "tdns*" -executable -exec cp {} /usr/local/bin/ ;                                                                                                                                                                           0.3s
 => [builder 7/7] RUN make install                                                                                                                                                                                                                                                                                       0.6s
 => [stage-1  4/12] COPY --from=builder /usr/local/bin/tdns-* /usr/local/bin/                                                                                                                                                                                                                                            0.3s
 => [stage-1  5/12] RUN mkdir -p /etc/tdns/certs                                                                                                                                                                                                                                                                         0.1s
 => [stage-1  6/12] COPY --from=builder /app/cmdv2/agentv2/tdns-agent.sample.yaml /etc/tdns/tdns-agentv2.yaml                                                                                                                                                                                                            0.0s
 => [stage-1  7/12] COPY --from=builder /app/cmdv2/agentv2/agent-zones.yaml /etc/tdns/                                                                                                                                                                                                                                   0.0s
 => [stage-1  8/12] COPY --from=builder /app/cmdv2/cliv2/tdns-cli.sample.yaml /etc/tdns/tdns-cli.yaml                                                                                                                                                                                                                    0.0s
 => [stage-1  9/12] COPY --from=builder /app/cmdv2/authv2/tdns-auth.sample.yaml /etc/tdns/tdns-authv2.yaml                                                                                                                                                                                                               0.0s
 => [stage-1 10/12] COPY --from=builder /app/utils/ /tmp/utils/                                                                                                                                                                                                                                                          0.0s
 => [stage-1 11/12] RUN tdns-cli db init -f /var/tmp/tdns-agent.db     && cd /tmp/utils     && for cn in localhost. agent.provider. agent.jose. ; do echo $cn | sh gen-cert.sh ; done     && cp *.key *.crt /etc/tdns/certs/     && rm -rf /tmp/utils                                                                    0.3s
 => [stage-1 12/12] RUN tdns-cliv2 keys generate --jose                                                                                                                                                                                                                                                                  0.1s
 => exporting to image                                                                                                                                                                                                                                                                                                   0.4s
 => => exporting layers                                                                                                                                                                                                                                                                                                  0.4s
 => => writing image sha256:9e7dfed4c4f033ecc03e8a57a574cc876993c26cf258eb1da31f5d4eaf924467                                                                                                                                                                                                                             0.0s
 => => naming to docker.io/library/tdns                                                                                                                                                                                                                                                                                  0.0s

View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/zmhrn3bvdd2vx2pcja70b6yi3

What's next:
    View a summary of image vulnerabilities and recommendations → docker scout quickview
```

## Running the image built

```
$ docker run -it tdns
*** TDNS tdns-agentv2 version v0.8-main-b2158dd mode of operation: "agent" (verbose: false, debug: false)
2026/03/09 17:39:49 WARN unknown config keys ignored (possible misspellings) subsystem=config keys="[Service.maxrefresh Service.refresh delegationsync common validator resolver keybootstrap server]"
2026/03/09 17:39:49 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=apiserver
2026/03/09 17:39:49 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=dnsengine
2026/03/09 17:39:49 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=log
2026/03/09 17:39:49 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=service
2026/03/09 17:39:49 INFO validating config section subsystem=config app=TDNS-AGENTV2 section=db
Logging to file: /var/log/tdns/tdns-agent.log
TDNS tdns-agentv2 version v0.8-main-b2158dd starting.
Zone "test.net." refers to the non-existing template "parent-primary". Ignored.
Zone "johani.org." refers to the non-existing template "secondary". Ignored.
PRINT AT github.com/johanix/tdns/v2.(*KeyDB).GenerateKeypair(sig0_utils.go:232)
string("/opt/local/bin/dnssec-keygen -K /tmp -a ED25519 -T KEY -f KSK -n ZONE dns.agent.provider."), #len=89
```
