# Multi-Provider QuickStart Guide

This guide sets up a complete TDNS multi-provider environment on
a single host. All three services (agent, combiner, signer) run
on the same machine, using distinct ports.

## 1. Overview

| Service    | Binary            | Role     | DNS port | Mgmt API port |
|------------|-------------------|----------|----------|---------------|
| Agent      | tdns-mpagent      | agent    | 8054     | 8074          |
| Combiner   | tdns-mpcombiner   | combiner | 8055     | 8075          |
| Signer     | tdns-mpsigner       | signer   | 8053, 53 | 8073          |
| IMR        | tdns-mpimr        | resolver | --       | --            |
| CLI        | tdns-mpcli        | tool     | --       | --            |
| dog        | dog             | tool     | --       | --            |

The signer should also listen on port 53 so it can interact
with other authoritative nameservers for zone transfers etc.

```
  External            NOTIFY + XFR
  Auth Server  --------------------->  Combiner (:8055)
  (ZONESERVER,                              |
   customer zone)                           | NOTIFY + XFR
                                            v
                                          Signer (:8053, :53)
                                            |
                                            | KEYSTATE
                                            v
                                          Agent (:8054)
                                            |
                                            | BEAT/SYNC (DNS CHUNK)
                                            v
                                        Remote Agents
                                       (other providers)
```

The external auth server publishes the customer zone and sends
it to all providers' combiners. Each combiner merges it with
contributions from all providers. The signer signs it. The
agent coordinates with peer agents at other providers.

## 2. Prerequisites

There are three primary prerequisites:

1. A zone from which the agent identity may be delegated.
2. A "customer zone" to test with.
3. A public IP address (referred to as `PUBADDRESS`
   throughout this guide) from which to provide service
   on various ports.

### 2.1 The Agent's Parent Zone

Each provider's agent has a DNS identity (published in the
customer zone's HSYNC3 record). Remote agents discover each
other by looking up DNS records under this identity name:

- A **URI** record describing where the agent listens.
- An **SVCB** record with additional agent details.
- A **JWK** record containing the agent's public
  encryption key.

The agent generates, publishes, and DNSSEC-signs all of
these records automatically into its own zone. However,
for remote agents to look up this information (a process
called "agent discovery"), the agent's zone must be
delegated in the public DNS namespace.

Assume that the "test provider" controls the domain name
"alpha.example." and that it is possible to delegate the
zone "agent.alpha.example." to the multi-provider agent
(and/or its secondaries).

The zone "agent.alpha.example." should be delegated to the
intended auth servers for this zone. The secondaries (if
any) should be configured to listen to NOTIFYs from and
request zone transfers from PUBADDRESS:8054 (or whatever
port is configured for the agent).

### 2.2 HSYNC3 and HSYNCPARAM Records

Agent discovery is initiated when a local agent and a
remote agent are both present in the same HSYNC3 RRset
for a customer zone. The HSYNC3 record defines the
*identity* of an entity (typically a DNS provider). It
does not say anything about what *role* that entity has
been assigned by the customer.

The HSYNCPARAM record defines the roles for each entity
listed in the HSYNC3 records. There must be exactly one
HSYNCPARAM record per zone; multiple HSYNCPARAM records
in the same zone is not allowed. The roles that may be
specified in the HSYNCPARAM are:

- **servers** -- providers that serve the zone via
  authoritative nameservers
- **signers** -- providers that sign the zone
- **nsmgmt** -- who is responsible for managing the NS
  RRset for the zone
- **parentsync** -- who is responsible for synchronizing
  delegation information with the parent zone

### 2.3 The Customer Zone

You need a zone published on the Internet from a separate host.
This is the zone that TDNS will manage across multiple
providers.

Publish this zone from any authoritative DNS server you
control, on a host reachable from the Internet. The server
must:

1. Allow outbound zone transfers (AXFR/IXFR) to your
   combiner's public address (port 8055 by default).
2. Send NOTIFY to your combiner's public address.
3. Send NOTIFY to the combiner of any other provider
   participating in the same zone.

The address of this server is referred to as `ZONESERVER`
below -- it must be a different host from where TDNS runs
(otherwise the zone can only be served to one provider).

Example zone file for `customer.zone.`:

```
$ORIGIN customer.zone.
$TTL 3600

customer.zone.   SOA  ns1.customer.zone. hostmaster.customer.zone. (
                      2026031901  ; serial
                      3600        ; refresh
                      900         ; retry
                      604800      ; expire
                      300         ; minimum
                      )

; Nameservers -- one per provider
customer.zone.        NS   ns1.customer.zone.
customer.zone.        NS   ns2.bravo.example.

; Glue for our own NS
ns1.customer.zone.    A    PUBADDRESS

; Multi-provider coordination records
; HSYNC3: one record per provider
;   Format: owner HSYNC3 state label identity upstream
customer.zone.        HSYNC3  ON  alpha  agent.alpha.example.  .
customer.zone.        HSYNC3  ON  bravo  agent.bravo.example.  .

; HSYNCPARAM: zone-wide multi-provider policy
customer.zone.        HSYNCPARAM  servers="alpha,bravo" nsmgmt="agent" signers="alpha,bravo"

; Example content
www.customer.zone.    A    PUBADDRESS
mail.customer.zone.   A    PUBADDRESS
customer.zone.        MX   10 mail.customer.zone.
```

Configure your authoritative server to allow zone transfers
to your combiner's public address and send NOTIFY to it on
port 8055.

### 2.4 Placeholders

The configuration files below use these placeholders:

- `PUBADDRESS` -- the host's public IP address
- `PUBSECONDARY` -- IP address of the secondary for the
  agent zone
- `ZONESERVER` -- IP address of the external auth server
  hosting the customer zone

Replace them after installing the configs:

```sh
sed -i 's/PUBADDRESS/198.51.100.1/g' /etc/tdns/*.yaml
sed -i 's/PUBSECONDARY/192.0.2.10/g' /etc/tdns/*.yaml
sed -i 's/ZONESERVER/203.0.113.10/g' /etc/tdns/*.yaml
```

## 3. Building and Installation

The code is split across three repositories that must be
cloned next to each other (the build uses `go.mod`
`replace` directives that reference sibling directories).

```sh
# Clone all three repos into the same parent directory
git clone https://github.com/johanix/tdns.git
git clone https://github.com/johanix/tdns-transport.git
git clone https://github.com/johanix/tdns-mp.git

# Build (requires Go 1.22+)
cd tdns-mp/cmd
make

# Install (as root)
sudo make install
# Installs:
#   /usr/local/bin/tdns-mpcli
#   /usr/local/bin/dog
#   /usr/local/libexec/tdns-mpagent
#   /usr/local/libexec/tdns-mpcombiner
#   /usr/local/libexec/tdns-mpsigner
#   /usr/local/libexec/tdns-mpimr
```

Create the directory structure:

```sh
sudo mkdir -p /etc/tdns/certs /etc/tdns/zones /etc/tdns/keys
sudo mkdir -p /var/lib/tdns
sudo mkdir -p /var/log/tdns
```

## 4. Configuration

### 4.1 Generating Certificates and Keys

TLS certificates (for management API endpoints):

```sh
cd /etc/tdns/certs
tdns/utils/gen-cert.sh
# When prompted:
#   Name: tdns
#   DNS names: localhost
#   IP addresses: 127.0.0.1,PUBADDRESS
```

Multi-provider synchronization requires both private
(encrypted) and authenticated (signed) communication
between agents. While DNSSEC provides authentication,
it does not provide encryption. For this reason DNS
multi-provider uses JSON Web Keys (JWKs, RFC 7517)
which support both operations. The experimental JWK
DNS record type is a direct representation of the
standard JWK format as defined in RFC 7517.

Communication between roles (agent to agent, agent to
combiner, etc.) uses another experimental DNS record
type, CHUNK. A CHUNK record carries a JWS(JWE(JWT))
in JOSE terms: a signed (JWS, RFC 7515) and encrypted
(JWE, RFC 7516) payload in JOSE standard format (JWT,
RFC 7519). See also RFC 7518 (JWA) for the underlying
algorithm definitions.

JOSE keypairs (for securing CHUNK transport between services):

```sh
tdns-mpcli keys generate --jose \
   --jose-outfile /etc/tdns/keys/agent.jose.private \
   --jose-pubfile /etc/tdns/keys/agent.jose.pub

tdns-mpcli keys generate --jose \
   --jose-outfile /etc/tdns/keys/combiner.jose.private \
   --jose-pubfile /etc/tdns/keys/combiner.jose.pub

tdns-mpcli keys generate --jose \
   --jose-outfile /etc/tdns/keys/signer.jose.private \
   --jose-pubfile /etc/tdns/keys/signer.jose.pub
```

### 4.2 Combiner Configuration

`/etc/tdns/tdns-mpcombiner.yaml`:

```yaml
include:
   - /etc/tdns/mpcombiner-zones.yaml

multi-provider:
   role:         combiner
   identity:     combiner.alpha.example.
   long_term_jose_priv_key: /etc/tdns/keys/combiner.jose.private
   agents:
      - identity: agent.alpha.example.
        address:  PUBADDRESS:8054
        long_term_jose_pub_key: /etc/tdns/keys/agent.jose.pub

apiserver:
   usetls:      true
   addresses:   [ 127.0.0.1:8075 ]
   apikey:      change-this-api-key
   certfile:    /etc/tdns/certs/tdns.crt
   keyfile:     /etc/tdns/certs/tdns.key

service:
   name:       TDNS-COMBINER

dnsengine:
   addresses:  [ PUBADDRESS:8055, '127.0.0.1:8055', '[::1]:8055' ]
   transports: [ do53 ]

db:
   file: /var/lib/tdns/tdns-mpcombiner.db

log:
   file:  /var/log/tdns/tdns-mpcombiner.log
   level: info

common:
   command: /usr/local/libexec/tdns-mpcombiner
```

`/etc/tdns/mpcombiner-zones.yaml`:

```yaml
templates:
   - name:      mp-combiner
     type:      secondary
     store:     map
     options:   [ allow-edits ]
     primary:   ZONESERVER:53
     notify:    [ PUBADDRESS:8053 ]

zones:
   - name:      customer.zone.
     template:  mp-combiner
```

### 4.3 Signer Configuration

The signer is a separate instance of `tdns-mpsigner`.

`/etc/tdns/tdns-mpsigner.yaml`:

```yaml
include:
   - /etc/tdns/mpsigner-zones.yaml

multi-provider:
   role:         signer
   active:       true
   identity:     signer.alpha.example.
   long_term_jose_priv_key: /etc/tdns/keys/signer.jose.private
   agents:
      - address:  PUBADDRESS:8054
        identity: agent.alpha.example.
        long_term_jose_pub_key: /etc/tdns/keys/agent.jose.pub

service:
   name:       TDNS-SIGNER

dnsengine:
   addresses:  [ PUBADDRESS:53, PUBADDRESS:8053, '127.0.0.1:8053', '[::1]:8053' ]
   transports: [ do53 ]
   certfile:   /etc/tdns/certs/tdns.crt
   keyfile:    /etc/tdns/certs/tdns.key

resignerengine:
   interval:   300
   keygen:
      mode:      internal
      algorithm: ED25519

apiserver:
   addresses:  [ 127.0.0.1:8073 ]
   apikey:     change-this-api-key
   certfile:   /etc/tdns/certs/tdns.crt
   keyfile:    /etc/tdns/certs/tdns.key

dnssecpolicies:
   default:
      algorithm: ED25519
      ksk:
         lifetime:     forever
         sigvalidity:  168h
      zsk:
         lifetime:     forever
         sigvalidity:  2h

kasp:
   propagation_delay: 1h
   check_interval:    1m
   standby_zsk_count: 1
   standby_ksk_count: 0

db:
   file: /var/lib/tdns/tdns-mpsigner.db

log:
   file:  /var/log/tdns/tdns-mpsigner.log
   level: info

common:
   servername: tdns-signer
   command:    /usr/local/libexec/tdns-mpsigner
```

`/etc/tdns/mpsigner-zones.yaml`:

```yaml
templates:
   - name:      mp-signing
     type:      secondary
     primary:   PUBADDRESS:8055
     notify:    [ PUBADDRESS:8054 ]
     store:     map
     options:   [ multi-provider ]
     dnssecpolicy: default

zones:
   - name:      customer.zone.
     template:  mp-signing
```

### 4.4 Agent Configuration

`/etc/tdns/tdns-mpagent.yaml`:

```yaml
include:
   - /etc/tdns/mpagent-zones.yaml

multi-provider:
   role:         agent
   identity:     agent.alpha.example.
   supported_mechanisms: [ dns ]
   long_term_jose_priv_key: /etc/tdns/keys/agent.jose.private
   combiner:
      address:   PUBADDRESS:8055
      long_term_jose_pub_key: /etc/tdns/keys/combiner.jose.pub
   signer:
      address:   PUBADDRESS:8053
      long_term_jose_pub_key: /etc/tdns/keys/signer.jose.pub
   local:
      notify:    [ PUBSECONDARY ]
      nameservers: [ ns1.alpha.example. ]
   remote:
      LocateInterval: 60
      BeatInterval:   30
   dns:
      addresses:
         publish:  [ PUBADDRESS ]
         listen:   [ 127.0.0.1:8054 ]
      baseurl:     dns://dns.{TARGET}:{PORT}/
      port:        8054

service:
   name:       TDNS-AGENT

dnsengine:
   addresses:  [ PUBADDRESS:8054, 127.0.0.1:8054, '[::1]:8054' ]
   transports: [ do53 ]

apiserver:
   addresses:  [ 127.0.0.1:8074 ]
   apikey:     change-this-api-key
   certfile:   /etc/tdns/certs/tdns.crt
   keyfile:    /etc/tdns/certs/tdns.key

db:
   file: /var/lib/tdns/tdns-mpagent.db

imrengine:
   active:      true
   addresses:   [ '127.0.0.1:5453', '[::1]:5453' ]
   transports:  [ do53 ]
   require_dnssec_validation: false

log:
   file:  /var/log/tdns/tdns-mpagent.log
   level: info

common:
   servername: tdns-agent
   command:    /usr/local/libexec/tdns-mpagent
```

`/etc/tdns/mpagent-zones.yaml`:

```yaml
templates:
   - name:      mp-secondary
     type:      secondary
     primary:   PUBADDRESS:8055
     store:     map
     options:   [ multi-provider ]

zones:
   - name:      customer.zone.
     template:  mp-secondary
```

### 4.5 CLI Configuration

`/etc/tdns/tdns-mpcli.yaml`:

```yaml
apiservers:
   - name:      tdns-agent
     baseurl:   https://127.0.0.1:8074/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key
     command:   /usr/local/libexec/tdns-mpagent

   - name:      tdns-combiner
     baseurl:   https://127.0.0.1:8075/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key
     command:   /usr/local/libexec/tdns-mpcombiner

   - name:      tdns-signer
     baseurl:   https://127.0.0.1:8073/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key
     command:   /usr/local/libexec/tdns-mpsigner

log:
   file:  /var/log/tdns/tdns-mpcli.log
   level: info
```

## 5. Running the Servers

All three services must be running before the agent will
receive the customer zone. Once the zone arrives, the
agent analyzes its HSYNC3 and HSYNCPARAM records and
initiates discovery of remote agents.

```sh
# Terminal 1: Combiner
tdns-mpcombiner --config /etc/tdns/tdns-mpcombiner.yaml

# Terminal 2: Signer
tdns-mpsigner --config /etc/tdns/tdns-mpsigner.yaml

# Terminal 3: Agent
tdns-mpagent --config /etc/tdns/tdns-mpagent.yaml
```

## 6. Testing

### 6.1 Check zone loads

```sh
# Query the combiner for the zone
dig @127.0.0.1 -p 8055 customer.zone. SOA

# Query the signer (should have DNSSEC signatures)
dig @127.0.0.1 -p 8053 customer.zone. SOA +dnssec

# Query the agent
dig @127.0.0.1 -p 8054 customer.zone. SOA
```

### 6.2 Check HSYNC3 and HSYNCPARAM records

Use `dog` (not dig) to examine HSYNC3 and HSYNCPARAM records
-- dig cannot decode the private RR type RDATA:

```sh
# HSYNC3 records (type code 65285)
dog @127.0.0.1:8055 customer.zone. HSYNC3

# HSYNCPARAM record (type code 65286)
dog @127.0.0.1:8055 customer.zone. HSYNCPARAM
```

### 6.3 Check agent status

```sh
# Zone list
tdns-mpcli agent zone list
agent.alpha.example.  primary    MapZone  false  false  [allow-updates automatic-zone online-signing]
customer.zone.        secondary  MapZone  false  false  [delegation-sync-child multi-provider]

# Peer discovery status
tdns-mpcli agent peer list

# Gossip state (if multiple providers configured)
tdns-mpcli agent gossip group list
```
