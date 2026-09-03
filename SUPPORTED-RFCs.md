# Supported DNS RFCs

This document tracks DNS-related RFCs that are implemented (or partially implemented) in the TDNS codebase.

## Core DNS Specifications

### RFC 1035 - Domain Names - Implementation and Specification
**Status**: ✅ Fully Supported  
**Implementation**: Core DNS protocol implementation  
**Notes**: 
- Standard DNS message format, wire format, and record types
- Domain name encoding/decoding
- Standard query/response handling

---

## DNSSEC Specifications

### RFC 1982 - Serial Number Arithmetic
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/dnssec_validate.go`, `tdns/cache/rrset_validate.go`  
**Notes**: 
- Used for DNSSEC validation period calculations
- Implements 32-bit serial arithmetic for SOA serial number comparisons

### RFC 4033, RFC 4034, RFC 4035 - DNSSEC Protocol Modifications
**Status**: ✅ Mostly Supported  
**Implementation**: `tdns/dnssec_validate.go`, `tdns/queryresponder.go`  
**Notes**: 
- DNSSEC validation support
- RRSIG, DNSKEY, NSEC, NSEC3 handling
- DO (DNSSEC OK) bit support
- Negative response handling (partially complete per README)

### RFC 9824 - Compact Denial of Existence for DNSSEC
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/queryresponder.go`, `tdns/cache/rrset_validate.go`, `tdns/edns0/edns0.go`, `dog/cmd/dog.go`  
**Notes**: 
- **CO (Compact Ok) Bit**: Full support for the CO bit (bit 14) in EDNS(0) OPT header TTL
  - Extracted in `ExtractFlagsAndEDNS0Options()` in `tdns/edns0/edns0.go`
  - Supported in `dog` tool via `+CO` or `+COMPACT` option
- **Compact Denial Responses**: Complete implementation of compact denial format
  - **NXDOMAIN**: NSEC with owner=qname, bitmap containing exactly RRSIG, NSEC, NXNAME; Rcode=NXDOMAIN
  - **NODATA**: NSEC with owner=qname, bitmap containing RRSIG, NSEC, and existing types (not qtype); Rcode=NOERROR
  - Implemented in `addCDEResponse()` function
  - Rcode handling based on CO bit: CO=1 uses compact denial Rcode semantics, CO=0 uses traditional DNSSEC
- **Unsigned Referrals (Section 3.4)**: Full support for adding NSEC to referral responses
  - NSEC covering the delegation point (zone cut)
  - Type bitmap contains NS, NSEC, RRSIG (indicating delegation point exists)
  - NextDomain correctly computed as leftmost label + "\000" + rest
  - Implemented in `addReferralNSEC()` function
- **NXNAME Query Rejection**: Explicit queries for NXNAME type are rejected
  - Returns RcodeFormatError with EDE code 30 ("Invalid Query Type")
  - NXNAME is only valid in NSEC type bitmaps, not as a query type
- **Validation Support**: Compact denial validation in `ValidateNegativeResponse()`
  - Detects compact denial NXDOMAIN (bitmap = RRSIG, NSEC, NXNAME)
  - Detects compact denial NODATA (qtype not in bitmap)
  - Modifies Rcode from NOERROR to NXDOMAIN when appropriate

---

## Extended DNS Error (EDE)

### RFC 8914 - Extended DNS Errors
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/edns0/edns0_ede.go`  
**Notes**: 
- Full support for EDE codes in EDNS(0) options
- Standard EDE codes from RFC 8914
- Custom EDE codes (513+) for TDNS-specific errors:
  - SIG(0) key management errors
  - Zone state errors
  - Delegation sync errors
  - TSIG validation errors
- EDE codes are attached to responses when validation fails or errors occur

---

## DNS Error Reporting

### RFC 9567 - DNS Error Reporting
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/edns0/edns0_er.go`, `reporter/main.go`, `tdns/do53.go`  
**Notes**: 
- **EDNS(0) ER Option (Option Code 18)**: Full support for adding and extracting the Error Reporting option
  - Implemented in `tdns/edns0/edns0_er.go`
  - Support in `dog` tool via `+ER=agent.domain` option
- **Error Channel Queries**: Full support for receiving and parsing error channel queries
  - QNAME format: `_er.<orig qtype>.<orig-qname>.<ede code>._er.<agent domain>`
  - Implemented in `ErrorChannelReporter()` function
  - tdns-reporter can act as a monitoring agent
- **Integration**: 
  - ER option extraction in `ExtractEDNS0Options()`
  - Error channel query handling in `createAuthDnsHandler()` for reporter app type

---

## DNS Record Types

### RFC 9859 - Generalized NOTIFY (DSYNC)
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/core/rr_dsync.go`  
**Notes**: 
- Complete implementation of the DSYNC record type
- Used for child-to-parent synchronization
- Supports delegation synchronization via DNS UPDATE

### RFC 7477 - Child-to-Parent Synchronization in DNS (CSYNC)
**Status**: ✅ Partially Supported  
**Implementation**: `tdns/scanner_csync.go`  
**Notes**: 
- CSYNC record parsing and processing
- References RFC 7477 procedures in code comments
- Used for scanning child zones for delegation changes

### RFC 7344 - Automating DNSSEC Delegation Trust Maintenance (CDS)
**Status**: ✅ Supported  
**Implementation**: Standard DNS record type support  
**Notes**: 
- CDS record type is recognized and can be queried/managed
- Used in multi-provider synchronization scenarios

### RFC 8078 - Managing DS Records from the Parent via CDS/CDNSKEY (CDNSKEY)
**Status**: ✅ Supported  
**Implementation**: Standard DNS record type support  
**Notes**: 
- CDNSKEY record type is recognized and can be queried/managed
- Used alongside CDS for delegation trust maintenance

### RFC 9460 - Service Binding and Parameter Specification via the DNS (SVCB)
**Status**: ✅ Supported  
**Implementation**: `tdns/ops_svcb.go`, `music/sidecar.go`  
**Notes**: 
- SVCB record type support
- Used for DNS transport signaling
- Supports IPv4/IPv6 hints and port specification

### RFC 9461 - Service Binding Mapping for DNS Servers (HTTPS)
**Status**: ✅ Supported  
**Implementation**: Standard DNS record type support  
**Notes**: 
- HTTPS record type (SVCB alias) support
- Used for DNS-over-HTTPS service discovery

---

## DNSSEC Bootstrapping

### RFC 9615 - Automatic DNSSEC Bootstrapping Using Authenticated Signals from the Zone's Operator
**Status**: ✅ Supported (both sides)
**Implementation**: `tdns/v2/signal_republish.go` (producer), `tdns/v2/scanner.go` and `tdns/v2/truststore_verify.go` (consumers)
**Notes**:
- **The signaling names**: a child's bootstrap records are published in the
  zone of each of the child's *nameservers*, under
  `_dsboot.<child>._signal.<ns>`, so a parent can fetch them over the child's
  own delegation and DNSSEC-validate them under the nameserver's keys rather
  than the child's. `signalOwnerName()` is the single spelling of that name,
  shared by the producer and both consumers so they cannot drift.
- **Consumer, parent side** (`queryCDSAtSignalingNames`, `tdns/v2/scanner.go`):
  a scanner configured with the `at-ns` option verifies every NOTIFY(CDS) this
  way instead of by direct DNSSEC validation. It queries CDS at the signaling
  name under each *out-of-bailiwick* NS via the IMR, requires each answer to be
  DNSSEC-validated (unless run with `no-dnssec-validation`), requires every NS
  to agree, and checks the result against a direct query to the child; any
  failure rejects the NOTIFY. A child whose NS are all in-bailiwick has no
  signaling name a parent can validate, so that case falls back to the
  direct/apex path.
- **Consumer, SIG(0) side** (`LookupChildKeyAtSignal`, `tdns/v2/truststore_verify.go`):
  the same shape for a child's SIG(0) `KEY` at `_sig0key.<child>._signal.<ns>`,
  used to verify a child's key before trusting a cross-zone-cut DNS UPDATE.
  That name belongs to `draft-ietf-dnsop-delegation-mgmt-via-ddns`, which
  reuses the `_signal` label RFC 9615 registered in the "Underscored and
  Globally Scoped DNS Node Names" registry (RFC 8552).
- **Producer** (`tdns/v2/signal_republish.go`): tdns publishes at these names for
  the zones it serves, in two paths.
  - A **secondary** with the `use-hsyncparam` zone option republishes a
    transferred zone's apex `CDS`/`CDNSKEY` (and SIG(0) `KEY`) at the signaling
    names owned by that zone's nameservers, into whichever zone this server
    holds as primary. The instruction comes from the zone owner, via the
    `pubcds` and `pubkey` flags of the apex HSYNCPARAM record
    (`draft-leon-dnsop-signaling-zone-owner-intent`) -- which is how tdns avoids
    RFC 9615 §3.1's alternative of *scanning* customer zones for
    bootstrap-shaped content and inferring intent. Publication is change-gated
    and skips any nameserver whose zone is not served here as primary. See
    [guide/special-features.md](guide/special-features.md#18-secondary-publishing-a-customers-bootstrap-records-at-the-_signal-names).
  - A **child** whose own SIG(0) bootstrap ceremony selects the `at-ns` method
    publishes its KEY at the signaling name before sending the self-signed
    UPDATE, so the parent's verification finds it. The publication is confirmed
    (waited on to actually apply), not merely enqueued, and `at-ns` is offered
    only when at least one of the zone's nameservers is served here as primary.
- **Not implemented**: withdrawing records already published at a signaling
  name when the option is removed or delegation sync is turned off for a zone.

---

## Zone Management

### RFC 8976 - Message Digest for DNS Zones (ZONEMD)
**Status**: ✅ Fully Supported (SIMPLE scheme; SHA-384 and SHA-512)
**Implementation**: `tdns/v2/zonemd.go`, `tdns/v2/zonemd_publish.go`, `tdns/v2/zonemd_verify.go`, `tdns/v2/zonemd_cache.go`, `tdns/v2/cli/zone_zonemd_cmds.go`
**Notes**:
- **Digest**: SIMPLE scheme (the only one defined), SHA-384 (§5 codepoint 1)
  and SHA-512 (codepoint 2). Canonical ordering per RFC 4034 §6.1/§6.3,
  RDATA domain-name case folding per §6.2, and the §3.3.1 exclusions
  (apex ZONEMD, the RRSIGs covering it, out-of-zone names, duplicates).
  Checked against the RFC's Appendix A vectors and cross-checked against
  dnspython's independent implementation.
- **Publishing** (`publish-zonemd` zone option): the digest is computed and
  signed INSIDE every publish, over the snapshot that publish installs, so
  `ZONEMD.Serial` always equals the SOA serial being served and the digest
  always describes what a recipient receives — over AXFR, over IXFR or from
  the zone file. Works on unsigned zones; not part of the DNSSEC policy.
  One ZONEMD RR per configured algorithm (`zonemd.algorithms`).
- **Verification** (`verify-zonemd` zone option): the apex ZONEMD is checked
  before a zone is adopted, on every load from file and every inbound
  transfer. `zonemd.on-verify-failure` selects `refuse` (default) or `warn`.
  An unimplemented scheme or hash algorithm is reported as *unsupported*
  rather than invalid — reserved codepoints are how a publisher says
  "not for you".
- **Operator surface**: `tdns-cli auth zone zonemd status|verify` (exits
  non-zero on a bad digest) and `dog AXFR ... +zonemd` for verifying a
  remote zone. `+ignoreserial` / `--ignore-serial` digest against the serial
  each ZONEMD names, as a diagnostic.
- **Cost**: the canonical wire form is cached per owner name, bounded by
  `zonemd.wire-cache-max-bytes`, so a publish re-renders only the names it
  changed.
- **Not implemented**: no scheme other than SIMPLE, which is the only one
  the registry defines.

---

### RFC 9432 - DNS Catalog Zones
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/v2/catalog.go`, `tdns/v2/apihandler_catalog.go`, `tdns/v2/cli/catalog_cmds.go`, `tdns/v2/refreshengine.go`  
**Notes**: 
- **Catalog Zone Format**: Full support for RFC 9432 catalog zone structure
  - Version TXT record: `version.{catalog-zone}. IN TXT "2"` (required)
  - Member zone PTR records: `{hash}.zones.{catalog-zone}. IN PTR {member-zone}`
  - Group TXT records: `group.{hash}.zones.{catalog-zone}. IN TXT "group1" "group2"` (multiple groups per zone)
  - Invalid. NS records for autozones (recommended by RFC)
- **Catalog Zone Parsing**: Complete implementation of catalog zone parsing
  - Extracts member zones and their associated groups
  - Categorizes groups into service groups, signing groups, and meta groups
  - Handles multiple groups per zone via TXT record RDATA
- **Auto-Configuration**: Full support for automatic zone configuration from catalog zones
  - Policy-based auto-configuration (`catalog.policy.zones.add: auto`)
  - Meta group configuration for upstream, store, and zone options
  - Automatic zone transfer initiation for newly configured zones
  - Manual configuration always takes precedence over catalog entries
- **Primary and Secondary Catalog Zones**: Catalog zones can be configured as either primary or secondary
  - Primary catalog zones persist across restarts
  - Secondary catalog zones are transferred via AXFR
- **CLI Management**: Complete CLI support for catalog zone operations
  - `catalog create` - Create a new catalog zone
  - `catalog zone add/delete/list` - Manage member zones in catalog
  - `catalog group add/delete/list` - Manage groups in catalog
  - `catalog zone group add/delete` - Associate groups with member zones
- **API Endpoints**: REST API support for catalog zone management
  - `/api/v1/catalog` endpoint for all catalog operations
  - JSON-based request/response format
- **Configuration Validation**: Comprehensive validation of catalog zone configuration
  - Hard fail if catalog zone is configured but `catalog:` section is missing
  - Validation of group references (missing groups, insufficient group configuration)
  - Error state tracking for catalog zones with configuration issues
- **Integration**: Catalog zone processing integrated into refresh engine
  - Automatic parsing after catalog zone transfers
  - Callback system for applications to react to catalog zone updates
  - Support for multiple catalog zones per server

---

## DNS Transports

### RFC 7858 - Specification for DNS over Transport Layer Security (DoT)
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/dot.go`  
**Notes**: 
- Full DoT server and client support
- TLS 1.3 minimum version
- ALPN protocol negotiation ("dot")
- Supported in tdns-server, tdns-imr, and dog

### RFC 8484 - DNS Queries over HTTPS (DoH)
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/doh.go`  
**Notes**: 
- Full DoH server and client support
- GET and POST methods
- Base64 URL encoding for GET requests
- Supported in tdns-server, tdns-imr, and dog

### RFC 9250 - DNS over Dedicated QUIC Connections (DoQ)
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/doq.go`  
**Notes**: 
- Full DoQ server and client support
- QUIC stream handling
- TLS 1.3 with "doq" ALPN
- Supported in tdns-server, tdns-imr, and dog

---

## EDNS(0) Options

### RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
**Status**: ✅ Fully Supported  
**Implementation**: `tdns/edns0/` package  
**Notes**: 
- Base EDNS(0) support
- DO (DNSSEC OK) bit
- Custom EDNS(0) options:
  - OTS (Option Code 65001) - Transport Signaling
  - KeyState (Option Code 65002) - SIG(0) key state communication
  - Report (Option Code 65003) - Error reporting
  - PRIVACY (Option Code 65007) - transport privacy request (query) and
    status (response), one octet
  - ER (Option Code 18) - Error Reporting (RFC 9567)

---

## Experimental/Proprietary Features

### HSYNC / HSYNC2 Records
**Status**: ✅ Implemented (Experimental)  
**Implementation**: `tdns/core/rr_hsync.go`, `tdns/core/rr_hsync2.go`  
**Notes**: 
- Zone owner signaling for multi-provider setups
- Not yet standardized
- Used for expressing zone owner intent to DNS providers

### DELEG Record
**Status**: ✅ Partially Implemented (Experimental)  
**Implementation**: `tdns/core/rr_deleg.go`  
**Notes**: 
- Authoritative part of DELEG record
- Discussed in dd@ietf.org working group
- Used for delegation management

### TSYNC Record
**Status**: ✅ Implemented (Experimental)  
**Implementation**: `tdns/core/rr_tsync.go`  
**Notes**: 
- Transport signaling without using SVCB
- Alternative to SVCB for transport discovery

### KeyState EDNS(0) Option
**Status**: ✅ Implemented (Proprietary)  
**Implementation**: `tdns/edns0/edns0_keystate.go`  
**Notes**: 
- Custom EDNS(0) option for SIG(0) key state communication
- Enables child-to-parent key validation status exchange
- Used in key bootstrapping process

---

## Implementation Notes

### Completeness Levels

- **✅ Fully Supported**: Complete implementation of the RFC specification
- **✅ Mostly Supported**: Major features implemented, some edge cases may be incomplete
- **✅ Partially Supported**: Core functionality implemented, some features may be missing
- **✅ Supported**: Basic support for the feature, may need additional work for full compliance

### Areas for Future Enhancement

- **IXFR Support**: Currently only AXFR is supported
- **TSIG Support**: SIG(0) is supported, but TSIG is not yet implemented
- **Full Negative Response Handling**: Some edge cases in DNSSEC negative responses may need work
- **ALPN Signaling Caching**: Planned but not yet implemented in tdns-imr

---

## Last Updated

**Date**: 2025-01-16

This document was last updated based on codebase analysis. RFC support status should be verified against the actual implementation when making changes.

