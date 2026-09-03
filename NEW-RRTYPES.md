**TDNS** supports various experimental DNS RR types:

## DSYNC

An implementation of the DSYNC records as defined in RFC 9859
(Generalized DNS Notifications).

## DELEG

A start of an implementation of the DELEG record as discussed in the dd@ietf.org WG.

## HSYNC3

Per-provider enrollment record. One HSYNC3 per provider at the zone apex.
Format:

```
owner TTL CLASS HSYNC3 {state} {label} {identity} {upstream}
```

state:       ON or OFF
label:       unqualified provider tag (e.g. "netnod"), NOT an FQDN
identity:    FQDN for agent discovery (e.g. "agent.netnod.se.")
upstream:    label of upstream provider, or "." if none (NOT an FQDN)

Example:

```
customer.zone. 3600 IN HSYNC3 ON cloudflare agent.cloudflare.com. netnod
customer.zone. 3600 IN HSYNC3 ON netnod    agent.netnod.se.      .
```

## HSYNCPARAM

Zone-wide multi-provider policy record. SVCB-style key=value pairs.
One HSYNCPARAM at the zone apex.
Format:

```
owner TTL CLASS HSYNCPARAM key1="val1" key2="val2" ...
```

Known keys, with the key numbers
draft-leon-dnsop-signaling-zone-owner-intent assigns them:

  0  servers="label1,label2,..."   - providers designated to serve the zone
  1  signers="label1,label2,..."   - providers designated to sign the zone
  2  auditors="label1,label2,..."  - observer-only auditor labels
  3  nsmgmt="owner|agent"          - who manages the NS RRset
  4  parentsync="owner|agent"      - who handles parent synchronisation
                                     (the mechanism is announced by the
                                     parent via DSYNC)
  5  suffix="label"                - DNS label for provider NS+glue
  6  pubkey                        - flag: publish the zone's SIG(0) KEY at
                                     _sig0key.<zone>._signal.<ns>
  7  pubcds                        - flag: publish the zone's CDS/CDNSKEY at
                                     _dsboot.<zone>._signal.<ns>

0-32767 is the IANA-registered range and 32768-65534 is Private Use; an
unregistered number is preserved on read-back, never acted on, and written
as keyN in presentation format. 65535 is reserved.

Example:

```
example.com. 3600 IN HSYNCPARAM nsmgmt="agent" servers="alpha,echo" signers="alpha" auditors="audit"
```

Wire format: each key=value pair is encoded as 2 bytes key code + 2 bytes
value length + value data, sorted by key code. Same layout as SVCB/HTTPS.
The key numbers are wire format, so they must match the draft exactly; the
presentation order above is the draft's registry order and is not the order
the keys appear in the RDATA.

## CHUNK

Chunked distribution format for transporting large payloads through DNS.
Used for key operations, manifests, and other structured data with optional
HMAC-SHA256 validation.

Format:

```
owner TTL CLASS CHUNK {sequence} {total} {format} {hmac} {data}
```

sequence:    uint16, 0 = manifest chunk, 1..N = data chunks
total:       uint16, total number of data chunks
format:      format identifier (e.g. "JSON")
hmac:        hex-encoded HMAC-SHA256 (manifest) or "" (data chunks)
data:        JSON (manifest) or base64-encoded payload (data chunks)

Examples:

```
node.distid.control. 3600 IN CHUNK 0 9 JSON a889a20e...c897092 {"chunk_count":9,...}
node.distid.control. 3600 IN CHUNK 1 9 JSON "" bWhBdGR...PQ==
```

## JWK

Stores a JSON Web Key (RFC 7517) in DNS as base64url-encoded JSON.

Format:

```
owner TTL CLASS JWK "base64url-encoded-jwk-json"
```

Example:

```
_jwk.example.com. 3600 IN JWK "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii4uLiIsInkiOiIuLi4ifQ"
```

## Legacy RR types

### HSYNC

First-generation provider enrollment record. Superseded by HSYNC3.

```
owner.name.  IN HSYNC {state} {nsmgmt} {sign} {identity} {upstream}
```

### HSYNC2

Second-generation provider enrollment record with string-based flags.
Superseded by HSYNC3 + HSYNCPARAM.

```
owner.name.  IN HSYNC2 {state} "nsmgmt={val}; sign={val}; audit={val}; parentsync={val}" {identity} {upstream}
```

### OBE: NOTIFY and MSIGNER

Older RR types replaced by improved versions. NOTIFY was obsoleted by
DSYNC, MSIGNER by HSYNC.
