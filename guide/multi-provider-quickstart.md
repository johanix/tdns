# Multi-Provider QuickStart Guide

This guide sets up a complete TDNS multi-provider environment on
a single host. All three services (agent, combiner, signer) run
on the same machine, using distinct ports.

## 1. Overview

| Service    | Binary            | Role     | DNS port | Mgmt API port |
|------------|-------------------|----------|----------|---------------|
| Agent      | tdns-agentv2      | agent    | 8054     | 8074          |
| Combiner   | tdns-combinerv2   | combiner | 8055     | 8075          |
| Signer     | tdns-authv2       | signer   | 8053, 53 | 8073          |
| IMR        | tdns-imrv2        | resolver | --       | --            |
| CLI        | tdns-cliv2        | tool     | --       | --            |
| dog        | dogv2             | tool     | --       | --            |

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
3. A public IP address from which to provide service on
   various ports.

### 2.1 The Agent's Parent Zone

Assume that the "test provider" controls the domain name
"somewhere.example." and that it is possible to delegate the
zone "agent.somewhere.example." to the multi-provider agent
(and/or its secondaries).

The zone "agent.somewhere.example." should be delegated to the
intended auth servers for this zone. The secondaries (if any)
should be configured to listen to NOTIFIES from and request
zone transfers from PUBADDRESS:8054 (or whatever port is
configured for the agent).

### 2.2 The Customer Zone

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

Example zone file for `example.mp.`:

```
$ORIGIN example.mp.
$TTL 3600

@   SOA  ns1.example.mp. hostmaster.example.mp. (
         2026031901  ; serial
         3600        ; refresh
         900         ; retry
         604800      ; expire
         300         ; minimum
         )

; Nameservers -- one per provider
    NS   ns1.example.mp.
    NS   ns2.beta-provider.net.

; Glue for our own NS
ns1 A    PUBADDRESS

; Multi-provider coordination records
; HSYNC3: one record per provider
;   Format: owner HSYNC3 state label identity upstream
    HSYNC3  ON  alpha  agent.somewhere.example.  .
    HSYNC3  ON  beta   agent.beta-provider.net.  .

; HSYNCPARAM: zone-wide multi-provider policy
    HSYNCPARAM  nsmgmt="agent" signers="alpha,beta"

; Example content
www  A    PUBADDRESS
mail A    PUBADDRESS
@    MX   10 mail.example.mp.
```

Configure your authoritative server to allow zone transfers
to your combiner's public address and send NOTIFY to it on
port 8055.

### 2.3 Placeholders

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

```sh
# Clone
git clone https://github.com/johanix/tdns.git
cd tdns

# Build (requires Go 1.22+)
cd cmdv2
make

# Install (as root)
sudo make install
# Installs:
#   /usr/local/bin/tdns-cliv2
#   /usr/local/bin/dogv2
#   /usr/local/libexec/tdns-agentv2
#   /usr/local/libexec/tdns-combinerv2
#   /usr/local/libexec/tdns-authv2
#   /usr/local/libexec/tdns-imrv2
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
openssl req -x509 -newkey rsa:2048 -nodes \
   -keyout tdns.key -out tdns.crt -days 3650 \
   -subj "/CN=tdns" \
   -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:PUBADDRESS"
```

JOSE keypairs (for securing CHUNK transport between services):

```sh
tdns-cliv2 keys generate --jose \
   --jose-outfile /etc/tdns/keys/agent.jose.private \
   --jose-pubfile /etc/tdns/keys/agent.jose.pub

tdns-cliv2 keys generate --jose \
   --jose-outfile /etc/tdns/keys/combiner.jose.private \
   --jose-pubfile /etc/tdns/keys/combiner.jose.pub

tdns-cliv2 keys generate --jose \
   --jose-outfile /etc/tdns/keys/signer.jose.private \
   --jose-pubfile /etc/tdns/keys/signer.jose.pub
```

### 4.2 Combiner Configuration

`/etc/tdns/tdns-combiner.yaml`:

```yaml
include:
   - /etc/tdns/combiner-zones.yaml

multi-provider:
   role:         combiner
   identity:     combiner.somewhere.example.
   long_term_jose_priv_key: /etc/tdns/keys/combiner.jose.private
   agents:
      - identity: agent.somewhere.example.
        address:  127.0.0.1:8054
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
   file: /var/lib/tdns/tdns-combiner.db

log:
   file:  /var/log/tdns/tdns-combiner.log
   level: info

common:
   command: /usr/local/libexec/tdns-combinerv2
```

`/etc/tdns/combiner-zones.yaml`:

```yaml
templates:
   - name:      mp-combiner
     type:      secondary
     store:     map
     options:   [ allow-edits ]
     primary:   ZONESERVER:53
     notify:    [ PUBADDRESS:8053 ]

zones:
   - name:      example.mp.
     template:  mp-combiner
```

### 4.3 Signer Configuration

The signer is `tdns-authv2` running with `role: signer`.

`/etc/tdns/tdns-signer.yaml`:

```yaml
include:
   - /etc/tdns/signer-zones.yaml

multi-provider:
   role:         signer
   active:       true
   identity:     signer.somewhere.example.
   long_term_jose_priv_key: /etc/tdns/keys/signer.jose.private
   agents:
      - address:  127.0.0.1:8054
        identity: agent.somewhere.example.
        long_term_jose_pub_key: /etc/tdns/keys/agent.jose.pub
   sync_api:
      addresses:
         listen: [ 127.0.0.1:8073 ]
      cert_file: /etc/tdns/certs/tdns.crt
      key_file:  /etc/tdns/certs/tdns.key

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
   file: /var/lib/tdns/tdns-signer.db

log:
   file:  /var/log/tdns/tdns-signer.log
   level: info

common:
   servername: tdns-signer
   command:    /usr/local/libexec/tdns-authv2
```

`/etc/tdns/signer-zones.yaml`:

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
   - name:      example.mp.
     template:  mp-signing
```

### 4.4 Agent Configuration

`/etc/tdns/tdns-agent.yaml`:

```yaml
include:
   - /etc/tdns/agent-zones.yaml

multi-provider:
   role:         agent
   identity:     agent.somewhere.example.
   supported_mechanisms: [ dns ]
   long_term_jose_priv_key: /etc/tdns/keys/agent.jose.private
   combiner:
      address:   127.0.0.1:8055
      long_term_jose_pub_key: /etc/tdns/keys/combiner.jose.pub
   signer:
      address:   127.0.0.1:8053
      long_term_jose_pub_key: /etc/tdns/keys/signer.jose.pub
   local:
      notify:    [ PUBSECONDARY ]
      nameservers: [ ns1.somewhere.example. ]
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
   file: /var/lib/tdns/tdns-agent.db

imrengine:
   active:      true
   addresses:   [ '127.0.0.1:5453', '[::1]:5453' ]
   transports:  [ do53 ]
   require_dnssec_validation: false

log:
   file:  /var/log/tdns/tdns-agent.log
   level: info

common:
   servername: tdns-agent
   command:    /usr/local/libexec/tdns-agentv2
```

`/etc/tdns/agent-zones.yaml`:

```yaml
templates:
   - name:      mp-secondary
     type:      secondary
     primary:   127.0.0.1:8055
     store:     map
     options:   [ multi-provider ]

zones:
   - name:      example.mp.
     template:  mp-secondary
```

### 4.5 CLI Configuration

`/etc/tdns/tdns-cli.yaml`:

```yaml
apiservers:
   - name:      tdns-agent
     baseurl:   https://127.0.0.1:8074/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key

   - name:      tdns-combiner
     baseurl:   https://127.0.0.1:8075/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key

   - name:      tdns-server
     baseurl:   https://127.0.0.1:8073/api/v1
     apikey:    change-this-api-key
     authmethod: X-API-Key

log:
   file:  /var/log/tdns/tdns-cli.log
   level: info
```

## 5. Running the Servers

Start in this order: combiner first (it receives the zone
transfer), then signer (signs it), then agent (coordinates).

```sh
# Terminal 1: Combiner
tdns-combinerv2 --config /etc/tdns/tdns-combiner.yaml

# Terminal 2: Signer
tdns-authv2 --config /etc/tdns/tdns-signer.yaml

# Terminal 3: Agent
tdns-agentv2 --config /etc/tdns/tdns-agent.yaml
```

## 6. Testing

### 6.1 Check zone loads

```sh
# Query the combiner for the zone
dig @127.0.0.1 -p 8055 example.mp. SOA

# Query the signer (should have DNSSEC signatures)
dig @127.0.0.1 -p 8053 example.mp. SOA +dnssec

# Query the agent
dig @127.0.0.1 -p 8054 example.mp. SOA
```

### 6.2 Check HSYNC3 and HSYNCPARAM records

Use `dogv2` (not dig) to examine HSYNC3 and HSYNCPARAM records
-- dig cannot decode the private RR type RDATA:

```sh
# HSYNC3 records (type code 65285)
dogv2 @127.0.0.1:8055 example.mp. HSYNC3

# HSYNCPARAM record (type code 65286)
dogv2 @127.0.0.1:8055 example.mp. HSYNCPARAM
```

### 6.3 Check agent status

```sh
# Zone list
tdns-cliv2 agent zone list
agent.somewhere.example.  primary    MapZone  false  false  [allow-updates automatic-zone online-signing]
example.mp.               secondary  MapZone  false  false  [delegation-sync-child multi-provider]

# Peer discovery status
tdns-cliv2 agent peer list

# Gossip state (if multiple providers configured)
tdns-cliv2 agent gossip group list
```
