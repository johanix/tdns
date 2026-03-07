# Agent Discovery DNS Queries Reference

**Date**: 2026-02-04
**Component**: Agent Discovery System
**Function**: `DiscoverAgent(ctx, imr, identity)`

## Overview

When discovering an agent with identity `agent.example.com`, the system sends the following DNS queries in order:

## Query Sequence

### API Transport Discovery

#### 1. API Endpoint URI Discovery
**Query**: `_https._tcp.agent.example.com. IN URI`
**Purpose**: Find the HTTPS API endpoint URI and port
**Example Response**:
```
_https._tcp.agent.example.com. 120 IN URI 10 1 "https://api.agent.example.com:8074/api/v1"
```
**Extracted**: Service name `api.agent.example.com`, port `8074`
**Stored In**: `result.APIUri`, `result.Port`

---

#### 2. API Service Address Discovery
**Query**: `api.agent.example.com. IN SVCB`
**Purpose**: Get IP addresses for API service from ipv4hint/ipv6hint
**Example Response**:
```
api.agent.example.com. 300 IN SVCB 1 . ipv4hint=10.4.0.4 ipv6hint=2001:db8::4
```
**Stored In**: `result.APIAddresses` (list of IPs from hints)

---

#### 3. API TLS Certificate Discovery
**Query**: `_8074._tcp.api.agent.example.com. IN TLSA` (port from step 1)
**Purpose**: DANE/TLSA certificate pinning for TLS verification
**Example Response**:
```
_8074._tcp.api.agent.example.com. 3600 IN TLSA 3 1 1 <sha256-hash>
```
**Stored In**: `result.TLSA`

---

### DNS Transport Discovery (Optional)

#### 4. DNS Endpoint URI Discovery
**Query**: `_dns._tcp.agent.example.com. IN URI`
**Purpose**: Find the DNS-based transport endpoint URI and port
**Example Response**:
```
_dns._tcp.agent.example.com. 120 IN URI 10 1 "dns://dns.agent.example.com:8998"
```
**Extracted**: Service name `dns.agent.example.com`, port `8998`
**Stored In**: `result.DNSUri`

---

#### 5. DNS Service Address Discovery
**Query**: `dns.agent.example.com. IN SVCB`
**Purpose**: Get IP addresses for DNS service from ipv4hint/ipv6hint
**Example Response**:
```
dns.agent.example.com. 300 IN SVCB 1 . ipv4hint=10.4.0.5 ipv6hint=2001:db8::5
```
**Stored In**: `result.DNSAddresses` (list of IPs from hints)

---

#### 6. JWK Public Key Discovery (Preferred)
**Query**: `dns.agent.example.com. IN JWK`
**Purpose**: Get JOSE/HPKE long-term public keys for payload encryption/signing
**Example Response**:
```
dns.agent.example.com. 3600 IN JWK "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImdQbU5KbWZHd0dJSFdIOFdhTmNxZFMyX1lSR2RoQWlyeG9VTDZwNTcwcFUiLCJ5IjoiQXVGTjg2aDN6cWoxR3pKOG9XOXVldVFMS01xaDlwUnJYelVaeFF1NXNxayJ9"
```
**Decoded JWK**:
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "gPmNJmfGwGIHWH8WaNcqdS2_YRGdhAirxoUL6p570pU",
  "y": "AuFN86h3zqj1GzJ8oW9ueuQLKMqh9pRrXzUZxQu5sqk"
}
```
**Stored In**: `result.JWKData` (base64url), `result.PublicKey` (decoded), `result.KeyAlgorithm` ("ES256")

---

#### 6b. KEY Record Fallback (Legacy)
**Query**: `dns.agent.example.com. IN KEY` (only if JWK not found)
**Purpose**: Legacy public key for SIG(0) DNS UPDATE authentication
**Example Response**:
```
dns.agent.example.com. 3600 IN KEY 256 3 15 <base64-ed25519-key>
```
**Stored In**: `result.LegacyKeyRR`

---

## Complete DNS Query Summary

For agent identity `agent.example.com`, these queries are sent:

**API Transport:**
1. `_https._tcp.agent.example.com. IN URI` → API endpoint URI and port
2. `api.agent.example.com. IN SVCB` → IP addresses (ipv4hint/ipv6hint)
3. `_8074._tcp.api.agent.example.com. IN TLSA` → TLS certificate (port from step 1)

**DNS Transport (optional):**
4. `_dns._tcp.agent.example.com. IN URI` → DNS endpoint URI and port
5. `dns.agent.example.com. IN SVCB` → IP addresses (ipv4hint/ipv6hint)
6. `dns.agent.example.com. IN JWK` → JOSE/HPKE public key (preferred)
7. `dns.agent.example.com. IN KEY` → SIG(0) public key (fallback if no JWK)

---

## Data Structure: AgentDiscoveryResult

After discovery, the following data is stored:

```go
type AgentDiscoveryResult struct {
    Identity      string           // "agent.example.com"
    APIUri        string           // "https://api.agent.example.com:8074/api/v1"
    DNSUri        string           // "dns://dns.agent.example.com:8998"
    JWKData       string           // Base64url-encoded JWK JSON
    PublicKey     crypto.PublicKey // Decoded ECDSA P-256 public key
    KeyAlgorithm  string           // "ES256"
    LegacyKeyRR   *dns.KEY         // Legacy KEY record (if used)
    TLSA          *dns.TLSA        // TLSA record for TLS verification
    APIAddresses  []string         // ["10.4.0.4", "2001:db8::4"] (from API SVCB)
    DNSAddresses  []string         // ["10.4.0.5", "2001:db8::5"] (from DNS SVCB)
    Port          uint16           // 8074 (from API URI)
    Error         error            // Any error during discovery
    Partial       bool             // True if some records missing
}
```

---

## Important Notes

### JWK vs KEY Records

- **JWK records**: Published at `dns.<identity>` for JOSE/HPKE payload crypto
- **KEY records**: Published at `dns.<identity>` for SIG(0) DNS UPDATE signing
- These are **separate key systems** for different purposes

### Query Locations

- **API transport**:
  - URI: `_https._tcp.<identity>`
  - SVCB (addresses): `api.<identity>`
  - TLSA (TLS cert): `_<port>._tcp.api.<identity>`
- **DNS transport**:
  - URI: `_dns._tcp.<identity>`
  - SVCB (addresses): `dns.<identity>`
  - JWK/KEY (public keys): `dns.<identity>`

### Key Design Principle

API and DNS services can be located at **different addresses**. The discovery process:
1. URI lookup → extract service name (api.<identity> or dns.<identity>) and port
2. SVCB query at service name → get IP addresses from ipv4hint/ipv6hint
3. Security record lookup → TLSA for API, JWK/KEY for DNS

### Discovery Minimum Requirements

Discovery succeeds if:
- At least one endpoint is found (APIUri OR DNSUri)

Discovery is marked `Partial` if:
- Some optional records are missing (TLSA, addresses, DNS URI)
- No public key found (neither JWK nor KEY)

---

## Example Discovery Log Output

```
AgentDiscovery: Starting discovery for agent agent.example.com
AgentDiscovery: Looking up API URI at _https._tcp.agent.example.com.
AgentDiscovery: Found API URI: https://api.agent.example.com:8074/api/v1 (host: api.agent.example.com, port: 8074)
AgentDiscovery: Looking up SVCB at api.agent.example.com.
AgentDiscovery: Found 2 address(es) for api.agent.example.com. from SVCB: [10.4.0.4 2001:db8::4]
AgentDiscovery: Looking up TLSA at _8074._tcp.api.agent.example.com.
AgentDiscovery: Found TLSA record at _8074._tcp.api.agent.example.com. (usage 3, selector 1, type 1)
AgentDiscovery: Found API endpoint https://api.agent.example.com:8074/api/v1 at api.agent.example.com
AgentDiscovery: Looking up DNS URI at _dns._tcp.agent.example.com.
AgentDiscovery: Found DNS URI: dns://dns.agent.example.com:8998 (host: dns.agent.example.com, port: 8998)
AgentDiscovery: Looking up SVCB at dns.agent.example.com.
AgentDiscovery: Found 2 address(es) for dns.agent.example.com. from SVCB: [10.4.0.5 2001:db8::5]
AgentDiscovery: Looking up JWK at dns.agent.example.com.
AgentDiscovery: Found JWK record at dns.agent.example.com. (algorithm: ES256)
AgentDiscovery: Found JWK record for agent.example.com. (algorithm: ES256)
AgentDiscovery: Found DNS endpoint dns://dns.agent.example.com:8998 at dns.agent.example.com:8998
AgentDiscovery: Discovery complete for agent.example.com. (API: https://api.agent.example.com:8074/api/v1, DNS: dns://dns.agent.example.com:8998)
AgentDiscovery: Successfully discovered and registered agent agent.example.com.
```
