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

This document was last updated based on codebase analysis. RFC support status should be verified against the actual implementation when making changes.

