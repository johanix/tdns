# TrustStore Analysis: SIG(0) Key Storage and Validation on Parent Side

**Date:** 2026-03-15
**Status:** Reference document
**Related:** `2026-03-15-parent-sync-end-to-end-plan.md` (Stage 2)

## Overview

The TrustStore manages SIG(0) key storage in a parent zone's trust database. When a child
sends a DNS UPDATE to add/remove its SIG(0) key, the parent validates, approves, and stores
the key through a multi-step pipeline. This document traces the complete flow.

## Architecture

### Files

| File | Role |
|------|------|
| `sig0_validate.go` | `ValidateUpdate()` — extract SIGs, locate keys, verify signatures; `TrustUpdate()` — evaluate trust status; `FindSig0KeyViaDNS()` — DNS-based key lookup |
| `truststore.go` | `Sig0TrustMgmt()` — database operations; `FindSig0TrustedKey()` — cache/DB lookup; `LoadSig0ChildKeys()` — startup loading |
| `updateresponder.go` | `ApproveTrustUpdate()` — policy checks for TRUSTSTORE-UPDATEs; KeyBootstrap enforcement |
| `zone_updater.go` | `ZoneUpdaterEngine` TRUSTSTORE-UPDATE case — processes KEY RRs, calls `Sig0TrustMgmt` |
| `keystate.go` | `GetKeyStatus()` — queries TrustStore to determine key state for KeyState EDNS(0) responses |
| `structs.go` | `UpdatePolicyConf`, `UpdatePolicy`, `UpdatePolicyDetail` definitions |
| `parseconfig.go` | Loading KeyBootstrap from config |

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS Sig0TrustStore (
    zonename           TEXT,
    keyid              INTEGER,
    validated          BOOLEAN,
    dnssecvalidated    BOOLEAN,
    trusted            BOOLEAN,
    source             TEXT,
    keyrr              TEXT
)
```

Cache key format: `"zonename::keyid"` (e.g., `"child.example.com.::12345"`)

---

## Update Flow: Step by Step

### Step 1: Validate Update (`sig0_validate.go: ValidateUpdate`)

Input: `r *dns.Msg` (DNS UPDATE), `us *UpdateStatus`

1. **Extract SIG(0) signatures** from `r.Extra` (Additional section)
   - Extract `signername` and `keyid` from each SIG

2. **Locate key** via four methods (priority order):
   - **(a) TrustStore**: `zd.FindSig0TrustedKey(signername, keyid)` — cache first, then DB
   - **(b) DNS lookup**: `zd.FindSig0KeyViaDNS(signername, keyid)` — queries child zone, DNSSEC-validates
   - **(c) Key in UPDATE** (self-signed): If `r.Ns` has exactly one RR and it's a KEY matching the SIG keyid+algorithm:
     - Set `Source = "child-key-upload"`
     - Set `us.Type = "TRUSTSTORE-UPDATE"`
     - Set `us.Data = "key"`
   - **(d) Fallback**: If only one RR and it's a KEY, extract directly

3. **Verify signature**: `sig.Verify(&keyrr, msgbuf)` + validity period check
   - On success: `us.Validated = true`

### Step 2: Trust Evaluation (`sig0_validate.go: TrustUpdate`)

Input: `r *dns.Msg`, `us *UpdateStatus` (with populated `Signers`)

Iterates over `us.Signers` and returns on first match:

| Condition | SignatureType | Result |
|-----------|--------------|--------|
| `key.Sig0Key.Trusted == true` | `"by-trusted"` | Approved, `ValidatedByTrustedKey = true` |
| `key.Sig0Key.DnssecValidated == true` | `"by-dnssec-validated"` | Approved |
| `key.Sig0Key.Source == "child-key-upload"` | `"self-signed"` | Approved as self-signed |
| None of the above | — | `RcodeBadKey` error |

### Step 3: Approval (`updateresponder.go: ApproveTrustUpdate`)

Policy guards using `zd.UpdatePolicy.Child.*`:

**If update is NOT signed by trusted key:**
1. Must be a KEY RR (not NS, A, AAAA, etc.) → reject otherwise
2. Must be ClassINET (not ClassNONE delete, not ClassANY) → reject otherwise
3. Must have `KeyUpload == "unvalidated"` → reject otherwise
4. Check `KeyBootstrap` policy array:
   - If any value == `"strict-manual"` → **REJECT** (prohibits unvalidated KEY uploads)
   - Otherwise → **APPROVE** unvalidated key upload (`unvalidatedKeyUpload = true`)

**Then:**
- Signature validation check: if `!Validated && !unvalidatedKeyUpload` → reject
- Trust status check: if `!ValidatedByTrustedKey && !unvalidatedKeyUpload` → reject
- Policy scope check: verify RR type allowed and name constraints (selfsub/self/sub)

Returns: `(approved bool, unvalidatedKeyUpload bool, error)`

### Step 4: Zone Updater Processing (`zone_updater.go`)

When `ur.Cmd == "TRUSTSTORE-UPDATE"`:

1. Begin transaction: `kdb.Begin("UpdaterEngine")`
2. For each RR in `ur.Actions`:
   - Determine subcommand from RR class: ClassINET→`"add"`, ClassNONE→`"delete"`, ClassANY→error
   - Extract KEY RR, build `TruststorePost`:
     ```
     SubCommand: "add" or "delete"
     Src:        "child-update"
     Keyname:    keyrr.Header().Name
     Keyid:      keyrr.KeyTag()
     KeyRR:      rr.String()
     Validated:  ur.Validated
     Trusted:    ur.Trusted
     ```
   - Call `kdb.Sig0TrustMgmt(tx, tppost)`
3. Commit transaction

### Step 5: TrustStore Storage (`truststore.go: Sig0TrustMgmt`)

**Add with `Src == "child-update"`:**
```sql
INSERT OR REPLACE INTO Sig0TrustStore
    (zonename, keyid, validated, dnssecvalidated, trusted, source, keyrr)
    VALUES (?, ?, ?, ?, ?, 'child-update', ?)
```
Cache invalidated via `kdb.TruststoreSig0Cache.Map.Remove(mapkey)`

**Delete:**
```sql
DELETE FROM Sig0TrustStore WHERE zonename=? AND keyid=?
```

---

## Decision Tree

```
DNS UPDATE with SIG(0) received
│
├─ ValidateUpdate()
│   ├─ Find key by: TrustStore → DNS → in-message → fallback
│   ├─ Verify signature → us.Validated = true
│   └─ If key from message → us.Type = "TRUSTSTORE-UPDATE"
│
├─ TrustUpdate()
│   ├─ Key.Trusted         → "by-trusted"         → approved
│   ├─ Key.DnssecValidated → "by-dnssec-validated" → approved
│   ├─ Key.Source == "child-key-upload" → "self-signed" → approved
│   └─ None                → RcodeBadKey           → rejected
│
├─ ApproveTrustUpdate()
│   └─ If NOT ValidatedByTrustedKey:
│       ├─ Not a KEY RR?              → REJECT
│       ├─ CLASS is NONE/ANY?         → REJECT
│       ├─ KeyUpload != "unvalidated"? → REJECT
│       └─ KeyUpload == "unvalidated":
│           ├─ "strict-manual" in KeyBootstrap? → REJECT
│           └─ else → APPROVE (unvalidatedKeyUpload=true)
│
└─ ZoneUpdater: TRUSTSTORE-UPDATE
    └─ Sig0TrustMgmt(add, "child-update", validated=false, trusted=false)
```

---

## KeyBootstrap Policy

Configured in YAML:
```yaml
zones:
  <zonename>:
    update-policy:
      child:
        type: selfsub
        rrtypes: [KEY, ...]
        keybootstrap: [manual, dnssec-validated, consistent-lookup, strict-manual]
        keyupload: unvalidated
```

| Policy Value | Effect |
|-------------|--------|
| `manual` | Allow unvalidated uploads; admin promotes to trusted manually |
| `dnssec-validated` | Allow DNSSEC-validated keys |
| `consistent-lookup` | Allow keys validated via consistent lookup |
| `strict-manual` | **Prohibit** all unvalidated KEY uploads entirely |

**Scenarios:**

1. `keybootstrap: [manual, dnssec-validated]` — Allow unvalidated KEY uploads. Key stored with
   `validated=false, trusted=false`. Admin promotes later.

2. `keybootstrap: [manual, strict-manual]` — Prohibit unvalidated uploads. Child must sign with
   a key already trusted or DNSSEC-validated.

3. `keyupload: validated-only` — Reject any key not already in TrustStore or DNSSEC-validated.

---

## Key Lookup After Storage

When the parent validates a future UPDATE from the same child:

1. `ValidateUpdate()` encounters SIG with keyid matching stored key
2. `FindSig0TrustedKey(zonename, keyid)`:
   - Check cache: `kdb.TruststoreSig0Cache.Map.Get(mapkey)`
   - Query DB: `SELECT ... FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
3. If `trusted=true` → validate UPDATE immediately (signature from established child)
4. If `trusted=false` → key exists but not trusted; needs promotion

### KeyState Query (`keystate.go: GetKeyStatus`)

1. Query TrustStore by `(zonename, keyid)`
2. If found and `key.Trusted == true` → return `KeyStateTrusted`
3. If `key.Validated == true` → send `KeyBootstrapperRequest`, return `KeyStateBootstrapAutoOngoing`
   or `KeyStateValidationFail`
4. Else → return `KeyStateInvalid`

---

## Three Paths to Key Acceptance

| Path | Key Source | Trusted | DNSSEC | Validated | Approval | Storage |
|------|-----------|---------|--------|-----------|----------|---------|
| A | TrustStore (already stored) | true | — | — | `"by-trusted"` APPROVE | No re-store |
| B | Child's zone (published KEY) | false | true | true | `"by-dnssec"` APPROVE | `dnssecvalidated=true` |
| C | In UPDATE msg (self-signed) | false | false | true | `"self-signed"` APPROVE (if no strict-manual) | `validated=false, trusted=false` |

### Promotion Flow (Path C → Path A)

Initial state after unvalidated upload:
```
validated=false, dnssecvalidated=false, trusted=false, source="child-update"
```

Admin action (CLI or API):
```
Sig0TrustMgmt(tx, TruststorePost{SubCommand: "trust", Keyname: "child.example.com.", Keyid: 12345})
```

Result:
```sql
UPDATE Sig0TrustStore SET trusted=true WHERE zonename=? AND keyid=?
```

Final state: `trusted=true` — key is now fully trusted for signing UPDATEs.

---

## Structs

```go
// structs.go
UpdatePolicyDetail {
    Type         string            // "selfsub" | "self" | "sub" | "none"
    RRtypes      map[uint16]bool   // Parsed from config strings
    KeyBootstrap []string          // ["manual", "dnssec-validated", ...]
    KeyUpload    string            // "unvalidated" | other
}

// truststore.go
Sig0Key {
    Name            string
    Keyid           int
    Validated       bool
    DnssecValidated bool
    Trusted         bool
    Source          string   // "file" | "keystore" | "child-update" | "dns"
    Keystr          string
    PublishedInDNS  bool
    Key             *dns.KEY
}

// Used in zone_updater.go
TruststorePost {
    SubCommand      string   // "add" | "delete" | "trust"
    Src             string   // "child-update" | "file" | "keystore" | "dns"
    Keyname         string   // Zone FQDN
    Keyid           int      // Key ID
    KeyRR           string   // RR as string
    Validated       bool
    DnssecValidated bool
    Trusted         bool
}
```

---

## Gaps Identified (see parent-sync-end-to-end-plan.md)

- **No automatic verification after TrustStore insertion**: Parent stores `trusted=false` but
  never triggers DNS lookup to verify the key is published (Gap 2 in parent sync plan)
- **ProcessKeyState auto-bootstrap TODO**: Not implemented (Gap 3)
- **No config for verification mechanisms**: Parent doesn't announce or configure which KEY
  verification mechanisms it supports (addressed in parent sync plan Stage 2a)
