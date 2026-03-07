# Security Review: tdns/v2

**Date**: 2026-03-07
**Scope**: All Go source files in `tdns/v2/` (~277 files)
**Method**: 15 focused sub-agents, each reviewing one subsystem with tight context
**Type**: Read-only review — no code changes

---

## Executive Summary

177 findings across 4 severity levels. The most concerning patterns are:

1. **Nil pointer dereferences** (~30 instances) — missing nil checks after map lookups, function returns, and type assertions
2. **Race conditions** (~12 instances) — unsynchronized global state, concurrent map access, unprotected struct field mutations
3. **Resource exhaustion** (~15 instances) — unbounded allocations from network input, unbounded cache/queue growth
4. **Missing error handling** (~20 instances) — ignored errors from JSON unmarshal, crypto ops, channel sends, DB ops
5. **Input validation gaps** (~15 instances) — missing bounds checks, unvalidated DNS names/algorithms
6. **Auth/crypto weaknesses** (~8 instances) — plaintext fallbacks, no nonce validation, confirmation spoofing

| Severity | Count |
|----------|-------|
| CRITICAL | 18 |
| HIGH | 48 |
| MEDIUM | 71 |
| LOW | 40 |

---

## CRITICAL FINDINGS

### C1. Unbounded buffer allocation in DoQ client response
- **File**: `core/dnsclient.go:318`
- **Category**: Resource Exhaustion
- **Description**: A malicious QUIC server can claim `respLen = 65535`, forcing 64KB buffer allocations per response. Repeated exploitation exhausts memory.
- **Fix**: Cap `respLen` and validate against actual stream data.

### C2. Unbounded HTTP response reading in DoH client
- **File**: `core/dnsclient.go:252`
- **Category**: Resource Exhaustion
- **Description**: `io.ReadAll(resp.Body)` reads entire response without size limits. A malicious HTTPS server can send gigabytes.
- **Fix**: Use `io.LimitReader(resp.Body, maxSize)`.

### C3. Unsafe type assertions and byte access in chunk parsing
- **File**: `core/rr_chunk.go:99-143`
- **Category**: Panic / Bounds
- **Description**: `dataBytes[0]` and `decoded[0]` accessed without length checks after base64 decode. Crafted input causes panic.
- **Fix**: Add `len(dataBytes) > 0` and `len(decoded) > 0` guards.

### C4. Race condition on ZoneData fields (KeyInventory, KeystateOK, RemoteDNSKEYs)
- **File**: `hsyncengine.go:115-135`, `combiner_msg_handler.go:333-342`
- **Category**: Race Condition
- **Description**: `zd.LastKeyInventory`, `zd.KeystateOK`, `zd.RemoteDNSKEYs` mutated from multiple goroutines without mutex protection.
- **Fix**: Protect with mutex or use atomic operations.

### C5. Unvalidated message routing and missing schema validation
- **File**: `combiner_msg_handler.go:103-112`, `combiner_chunk.go:114`
- **Category**: Input Validation
- **Description**: RFI type dispatched without validating message contains valid RFI data. `ParseAgentMsgNotify` unmarshals JSON without validating required nested fields. Malformed structures bypass validation.
- **Fix**: Validate required fields after unmarshal before dispatch.

### C6. Confirmation spoofing via DistributionID collision
- **File**: `reliable_message_queue.go:260-277`
- **Category**: Message Integrity
- **Description**: `MarkConfirmed()` uses only `distributionID + senderID` as key with no cryptographic signature/HMAC. An attacker sending a crafted CONFIRM NOTIFY with spoofed DistributionID can falsely mark messages as delivered.
- **Fix**: Add HMAC or nonce to confirmation protocol.

### C7-C8. Silently ignored JSON Unmarshal errors in database layer
- **File**: `db_hsync.go:734` (ListSyncOperations), `db_hsync.go:794` (ListSyncConfirmations)
- **Category**: Error Handling
- **Description**: `json.Unmarshal()` errors completely ignored. Malformed JSON results in silently corrupted/empty data returned to callers.
- **Fix**: Check and propagate unmarshal errors.

### C9. Nil pointer dereference in multisigner API handler
- **File**: `apihandler_multisigner.go:55`
- **Category**: Nil Pointer
- **Description**: `resp.RRset = *rrset` dereferences without nil check after `GetRRset()` returns. Causes panic and server crash.
- **Fix**: Check `rrset != nil` before dereference.

### C10. Nil pointer dereference in zone bump serial handler
- **File**: `apihandler_zone.go:52-57`
- **Category**: Nil Pointer
- **Description**: `br.OldSerial` and `br.NewSerial` accessed without nil check on `br` from `BumpSerial()`. Panic on error path.
- **Fix**: Check `br != nil`.

### C11. Nil pointer dereference on GetOwner apex
- **File**: `ops_dnskey.go:18,101`
- **Category**: Nil Pointer
- **Description**: `apex` from `GetOwner(zd.ZoneName)` used at line 101 (`apex.RRtypes.Set()`) without nil check.
- **Fix**: Add `if apex == nil { return err }` after error check.

### C12. Unbuffered channel send without timeout (CSYNC)
- **File**: `ops_csync.go:25,49`
- **Category**: Resource Exhaustion
- **Description**: Direct `zd.KeyDB.UpdateQ <- UpdateRequest{...}` with no select/timeout. Goroutine blocks indefinitely if receiver stalls.
- **Fix**: Wrap with `select` + `time.After`.

### C13. Ignored error from GetOwner (DSYNC)
- **File**: `ops_dsync.go:22`
- **Category**: Error Handling
- **Description**: `owner, _ := zd.GetOwner("_dsync." + zd.ZoneName)` explicitly discards error. Function continues with invalid state.
- **Fix**: Check and return error.

### C14-C15. Nil dereference on Conf.Catalog.GroupPrefixes
- **File**: `catalog.go:168-169,684-685`
- **Category**: Nil Pointer
- **Description**: Accessed without nil checks on `Conf.Catalog` or `GroupPrefixes`. Panic if catalog not configured.
- **Fix**: Add nil guards.

### C16. Nil dereference on ImrEngine
- **File**: `delegation_sync.go:29,34`
- **Category**: Nil Pointer
- **Description**: `conf.Internal.ImrEngine` used after early-return check but subsequent code lacks defensive nil guard.
- **Fix**: Add nil check.

### C17. Array index without bounds check
- **File**: `rfc3597.go:73-80`
- **Category**: Bounds
- **Description**: Assumes `RRset.RRs[0]` exists without explicit bounds check.
- **Fix**: Check `len(RRset.RRs) > 0`.

### C18. Unbounded growth of MemChunkPayloadStore
- **File**: `chunk_store.go:128-134`
- **Category**: Resource Exhaustion
- **Description**: `entries` and `chunkArrays` maps grow without proactive eviction. Long TTLs + frequent Sets exhaust memory.
- **Fix**: Add max-entry limit or LRU eviction.

---

## HIGH FINDINGS

### H1-H2. Missing bounds check on r.Question[0] (Do53, DoT)
- **Files**: `do53.go:189,331,400`, `dot.go:38`
- **Category**: Input Validation / Panic
- **Description**: `r.Question[0].Name` accessed without `len(r.Question)` check. Crafted DNS message with empty Question section causes panic (DoS).
- **Fix**: Add `len(r.Question) == 0` check (already fixed in DoH and DoQ per earlier coderabbit batch).

### H3. Shell command injection in xxxShellExec (disabled)
- **File**: `daemon_utils.go:22-40`
- **Category**: Command Injection
- **Description**: `strings.Fields(cmdline)` + `exec.Command(args[0], args[1:]...)` vulnerable to metacharacter injection. Currently disabled with `xxx` prefix.
- **Fix**: Remove or properly sanitize if ever enabled.

### H4. Missing error handling on DoH HTTP response write
- **File**: `doh.go:70`
- **Category**: Error Handling
- **Description**: `w.Write(buf.Bytes())` error completely ignored.
- **Fix**: Check and log error.

### H5. Error-string-based control flow
- **File**: `chunk_notify_handler.go:415,432`
- **Category**: Fragile Design
- **Description**: `strings.Contains(err.Error(), "no verification key for")` for control flow. Fragile if error message format changes.
- **Fix**: Use typed errors or error wrapping.

### H6. Unencrypted plaintext fallback on encryption failure
- **File**: `chunk_notify_handler.go:326-332`
- **Category**: Crypto Downgrade
- **Description**: When response encryption fails, code silently falls back to unencrypted JSON. Enables downgrade attack.
- **Fix**: Return error instead of falling back to plaintext.

### H7. Combiner key fallback enables sender identity spoofing
- **File**: `chunk_notify_handler.go:427-444`
- **Category**: Authentication Bypass
- **Description**: When decryption fails with sender's key, code falls back to combiner's key. Allows attacker to forge sender identity.
- **Fix**: Require explicit sender identification separate from key selection.

### H8. Authorization check after expensive crypto operations
- **File**: `chunk_notify_handler.go:375-448`
- **Category**: Denial of Service
- **Description**: Decryption + JSON parsing happen before router authorization middleware. Unauthorized peers trigger expensive crypto before rejection.
- **Fix**: Move authorization check before crypto operations.

### H9. Unchecked rand.Read() in generatePingNonce()
- **File**: `hsync_transport.go:31`
- **Category**: Crypto / Error Handling
- **Description**: If random number generation fails, a zero-filled nonce is silently returned, creating predictable/reusable nonces.
- **Fix**: Check error and return it.

### H10. Non-timing-safe comparison for DS digest
- **Files**: `dnssec_validate.go:154`, `cache/rrset_validate.go:474`
- **Category**: Timing Attack
- **Description**: `strings.EqualFold()` used for cryptographic DS digest comparison instead of `crypto/subtle.ConstantTimeCompare()`.
- **Fix**: Use constant-time comparison.

### H11. Weak PRNG for signature jitter
- **File**: `sign.go:19`
- **Category**: Cryptographic Weakness
- **Description**: `golang.org/x/exp/rand.Intn(61)` (pseudo-random) used for signature inception/expiration jitter. Predictable values.
- **Fix**: Use `crypto/rand` for security-relevant jitter.

### H12. Race condition in keybootstrapper verifications map
- **File**: `keybootstrapper.go:31-157`
- **Category**: Race Condition
- **Description**: `verifications` map accessed/modified without synchronization across goroutines. Concurrent map access can panic.
- **Fix**: Use sync.Map or mutex.

### H13. Unsafe nil dereference after zone lookup in API handler
- **File**: `apihandler_zone.go:41-52`
- **Category**: Nil Pointer
- **Description**: `zd` used without nil check for commands that should check `!exist`.
- **Fix**: Add nil check.

### H14. JSON decode error logged but execution continues
- **File**: `apihandler_combiner.go:22-25`
- **Category**: Error Handling
- **Description**: Partially/incorrectly decoded request processed without returning early.
- **Fix**: Return on decode error.

### H15. Race condition in Scanner.Jobs map
- **File**: `apihandler_funcs.go:381-410`
- **Category**: Concurrency
- **Description**: `Scanner.Jobs` map accessed with RLock but iterator pattern may have race window with concurrent modifications.
- **Fix**: Use proper mutex or sync.Map.

### H16. Unguarded channel sends to response channels
- **File**: `hsyncengine.go:334-340`, `combiner_msg_handler.go`
- **Category**: Channel Safety / Deadlock
- **Description**: Response channel may be nil or closed, causing panic. No default case or timeout.
- **Fix**: Add nil check and select with timeout.

### H17. Missing error propagation from database persist callbacks
- **Files**: `combiner_utils.go:162-165`, `combiner_msg_handler.go:131-135`
- **Category**: Error Handling
- **Description**: `PersistContributions` callback errors logged but not returned. In-memory state becomes inconsistent with persisted state.
- **Fix**: Propagate errors.

### H18. Nil pointer dereference in peer operations
- **Files**: `combiner_msg_handler.go:269-273`, `reliable_message_queue.go:381-396`
- **Category**: Nil Pointer
- **Description**: `peer` and `agent` used without nil checks after registry Get.
- **Fix**: Add nil checks.

### H19. Unbounded queue growth
- **File**: `reliable_message_queue.go:352-419`
- **Category**: Resource Exhaustion
- **Description**: Messages in AWAITING_CONFIRM state can sit for 24h. No per-message timeout for send operations.
- **Fix**: Add per-message expiry.

### H20. Race condition in PendingRemoteConfirms map
- **File**: `syncheddataengine.go:506-509,1237,1276`
- **Category**: Race Condition
- **Description**: Map accessed without synchronization from multiple goroutines.
- **Fix**: Use sync.Map or mutex.

### H21. Unbounded growth of SDE Tracking map
- **File**: `syncheddataengine.go:82,862-872`
- **Category**: Resource Exhaustion
- **Description**: Tracking map never removes entries for removed RRs. Malicious agent can exhaust memory.
- **Fix**: Evict stale entries.

### H22. No JWT expiration check in manifest verification
- **File**: `distrib/manifest_jwt.go:87-130,142-199`
- **Category**: JWT / Replay
- **Description**: JWT has `iat` but no `exp`. Old manifests can be replayed indefinitely.
- **Fix**: Add `exp` claim and validate it.

### H23. Distribution ID spoofing via untrusted OriginatingDistID
- **File**: `syncheddataengine.go:505-515`
- **Category**: Spoofing
- **Description**: `OriginatingDistID` from message used directly without validation. Malicious agent can forge this to trigger false confirmations.
- **Fix**: Validate or generate own correlation IDs.

### H24. String concatenation in SQL (DROP TABLE, PRAGMA)
- **Files**: `db.go:186`, `db.go:144`
- **Category**: SQL Injection (mitigated)
- **Description**: Table names concatenated into SQL. Currently only called with hardcoded `DefaultTables`, but unsafe pattern.
- **Fix**: Use allow-list validation.

### H25. String concatenation in LIMIT clause
- **File**: `db_hsync.go:706,769,823`
- **Category**: SQL Injection
- **Description**: `fmt.Sprintf(" LIMIT %d", limit)` bypasses parameterization. Integer type mitigates but no range validation.
- **Fix**: Validate range and use parameterized queries.

### H26. Template injection via fmt.Sprintf for zone file path
- **File**: `parseconfig.go:709`
- **Category**: Path Traversal / Template Injection
- **Description**: `fmt.Sprintf(tmpl.Zonefile, zconf.Name)` where `zconf.Name` is from config. Code comment says "XXX: We should do some sanity checking."
- **Fix**: Validate zone names and sanitize paths.

### H27. Unvalidated file path for log file
- **File**: `logging.go:38`
- **Category**: Path Traversal
- **Description**: Log file path from config passed to lumberjack without validation.
- **Fix**: Validate path stays within expected directory.

### H28. Path traversal in config file includes
- **File**: `parseconfig.go:499`
- **Category**: Path Traversal
- **Description**: Include file paths joined with base directory but no check that result stays within base directory. `../../etc/passwd` escapes.
- **Fix**: Resolve symlinks and validate against base directory.

### H29. Missing bounds check on uint16 length in JSON manifest Unpack
- **File**: `core/rr_jsonmanifest.go:93`
- **Category**: Integer Validation / Bounds
- **Description**: No check that `off+jsonLen` doesn't exceed DNS message size limits.
- **Fix**: Add bounds check.

### H30. Integer overflow potential in DELEG bounds check
- **File**: `core/rr_deleg.go:356-357`
- **Category**: Integer Overflow
- **Description**: `off+int(length) > len(msg)` could bypass check if `off` is very large and addition wraps.
- **Fix**: Check for overflow: `if length > len(msg)-off`.

### H31. Unchecked buffer write in JSONChunk Pack()
- **File**: `core/rr_jsonchunk.go:76-77`
- **Category**: Buffer Overflow
- **Description**: `buf[off]` and `buf[off+1]` written without initial bounds check.
- **Fix**: Check `off+2 <= len(buf)`.

### H32. Panic on uninitialized ConcurrentMap
- **File**: `core/concurrent_map.go:247`
- **Category**: Error Handling
- **Description**: `snapshot()` panics explicitly if shards empty. Should return error instead.
- **Fix**: Return `(nil, error)` instead of panic.

### H33. Unbuffered channel send in PublishDsyncRRs
- **File**: `ops_dsync.go:209`
- **Category**: Resource Exhaustion
- **Description**: Direct channel send without timeout.
- **Fix**: Wrap with select + timeout.

### H34. pem.Decode error ignored, no block type validation
- **File**: `ops_tlsa.go:63`
- **Category**: Input Validation
- **Description**: Error from `pem.Decode` discarded. No validation that PEM block type is "CERTIFICATE".
- **Fix**: Check error and validate block type.

### H35-H36. Array bounds on sak.Keys[0]
- **File**: `ops_key.go:208,359,381,392,401`
- **Category**: Array Bounds
- **Description**: Multiple locations access `sak.Keys[0]` without bounds checking, far from initial length check.
- **Fix**: Re-validate length before access.

### H37. Zone names from catalog not validated as DNS names
- **File**: `catalog.go:268-292`
- **Category**: Input Validation
- **Description**: Zone names from `member.MetaGroup` used directly in configuration without DNS name validation.
- **Fix**: Validate as FQDN.

### H38. Nil dereference in IMR cache access
- **File**: `rfc3597.go:90-104`
- **Category**: Nil Pointer
- **Description**: `imr.Cache.Get()` may return nil; `negRRset.RRs` accessed assuming populated without bounds check.
- **Fix**: Add nil check.

### H39. Unbounded cache growth, cache poisoning with 0-TTL records
- **File**: `rrset_cache.go:122-145`
- **Category**: Resource Exhaustion / Cache DoS
- **Description**: No maximum entry limit. No LRU eviction.
- **Fix**: Add max entries and LRU eviction.

### H40. Time-based fallback for job ID on crypto/rand failure
- **File**: `scanner.go:86-93`
- **Category**: Cryptographic Weakness
- **Description**: Falls back to `time.Now().UnixNano()` when `crypto/rand` fails. Predictable IDs.
- **Fix**: Return error instead of falling back.

### H41. Silent data loss for unhandled types in sanitize
- **File**: `sanitize_data.go:56-73`
- **Category**: Type Safety
- **Description**: Only handles one specific ConcurrentMap type; other types silently converted to empty map.
- **Fix**: Return error for unhandled types.

### H42. Nil dereference on RR Header() in loop
- **File**: `delegation_utils.go:208-227`
- **Category**: Nil Pointer
- **Description**: `arr.Header().Name` called without nil check on individual RR objects.
- **Fix**: Add nil check.

### H43. Unvalidated algorithm string to enum conversion
- **File**: `keystore.go:931`
- **Category**: Input Validation
- **Description**: `dns.StringToAlgorithm[algorithm]` returns 0 on invalid string without error check. Creates keys with invalid algorithm.
- **Fix**: Check `ok` from map lookup.

### H44. Nil pointer dereference after GetOwner in signing
- **File**: `sign.go:410,424`
- **Category**: Nil Pointer
- **Description**: `owner` from `GetOwner(name)` used without nil check.
- **Fix**: Add nil check.

### H45. Race condition in key cache iteration
- **File**: `keystore.go:471-473`
- **Category**: Race Condition
- **Description**: `KeystoreDnskeyCache` iterated and deleted without synchronization during "clear" subcommand.
- **Fix**: Add mutex.

### H46. Authorization bypass via empty zone string
- **File**: `agent_authorization.go:52-67`
- **Category**: Authorization Bypass
- **Description**: Empty zone triggers `isInHSYNCAnyZone()` instead of zone-specific check. Could incorrectly grant authorization.
- **Fix**: Reject empty zone strings explicitly.

### H47. Missing timestamp validation in key state transitions
- **File**: `key_state_worker.go:112-146`
- **Category**: State Machine
- **Description**: Keys can transition without proper timestamps. No validation against future timestamps.
- **Fix**: Validate timestamps.

### H48. Private keys not encrypted at rest in database
- **File**: `keystore.go:54-56,293-295`
- **Category**: Confidentiality
- **Description**: Private keys stored as plaintext PEM in database.
- **Fix**: Encrypt at rest using key-wrapping.

---

## MEDIUM FINDINGS

### M1. Missing error handling on DoQ stream close
- **File**: `doq.go:107,120,127`

### M2. Format string injection in logging
- **File**: `daemon_utils.go:34`, `queryresponder.go:320`

### M3. Missing timeout on dns.Exchange()
- **File**: `notifier.go:109`

### M4. No DNS message size validation in DoQ
- **File**: `doq.go:110`

### M5. Missing TLS 1.3 enforcement in DoH
- **File**: `doh.go:85`

### M6. No explicit cipher suite configuration
- **Files**: `dot.go:24-34`, `doq.go:24-28`

### M7. Weak API key validation (no rate limiting, no timing-safe compare)
- **File**: `apirouters.go:75`

### M8. Information disclosure via error messages
- **Files**: `apihandler_agent_distrib.go:413,556`

### M9. Format string from user input in RR construction
- **File**: `apihandler_catalog.go:141`

### M10. Job IDs in HTTP error responses
- **Files**: `apihandler_funcs.go:725,767`

### M11. JSON unmarshaling without size limits
- **Files**: `chunk_notify_handler.go:246,499`, `handlers.go:28,376,417`

### M12. Inconsistent nil checks on ResponseWriter
- **File**: `chunk_notify_handler.go:287-289,302-304`

### M13. Race condition in pendingConfirmations map
- **File**: `dns.go:857-875`

### M14. Silent message drop when channel full
- **File**: `handlers.go:639-643`

### M15. Format byte not validated before decryption decision
- **File**: `dns.go:956-961`

### M16. Empty senderID accepted in EDNS0 mode
- **File**: `chunk_notify_handler.go:119-122`

### M17. Deprecated UnwrapIncomingTryAllPeers still callable
- **File**: `crypto.go:435-475`

### M18. No rate limiting on DoS counters
- **File**: `chunk_notify_handler.go:73-75,369-371`

### M19. Inconsistent nil checks on ctx.Data
- **File**: `handlers.go:35,53,67,151`

### M20. Missing zone validation in authorization
- **File**: `chunk_notify_handler.go:489-504`

### M21. JSON field name inconsistency allows injection
- **File**: `chunk_notify_handler.go:237-245,453-490`

### M22. Insufficient bounds checking in ParseChunkOption()
- **File**: `edns0/edns0_chunk.go:193-248`

### M23. Unchecked buffer size in PackDomainName
- **File**: `edns0/edns0_er.go:68`

### M24. No total EDNS0 option size validation
- **File**: `edns0/edns0_reporter.go:28-29`

### M25. Panic on crypto backend registration conflict
- **File**: `crypto/registry.go:27-29`

### M26. Missing validation of recipient public key format
- **File**: `hpke/hpke_wrapper.go:29-31`

### M27. Silent verification flow fallthrough
- **File**: `sig0_validate.go:146-151`

### M28. Missing error propagation from database persist
- **Files**: `combiner_utils.go:162-165`, `combiner_msg_handler.go:131-135`

### M29. Nil pointer dereference in zone state access
- **File**: `combiner_msg_handler.go:252-256`

### M30. KEYSTATE inventory cached without expiration
- **Files**: `hsync_utils.go:293-301`, `hsyncengine.go:120-126`

### M31. No signature verification on signer KEYSTATE messages
- **File**: `signer_msg_handler.go:161-223`

### M32. Missing bounds check in conference operations
- **File**: `combiner_msg_handler.go:234-237`

### M33. Unchecked errors in EvaluateUpdate
- **File**: `agent_policy.go:77,81`

### M34. State regression without synchronization guarantee
- **File**: `syncheddataengine.go:1007-1009,1051`

### M35. No nonce validation in confirmation protocol
- **File**: `confirmation.go:23-24`

### M36. Missing validation of Source field in confirmations
- **File**: `syncheddataengine.go:1096-1098,1115-1130`

### M37. Partial write atomicity in state transitions
- **File**: `syncheddataengine.go:1195-1201`

### M38. No size limits on operation records
- **File**: `agent_policy.go:23-44`

### M39. Algorithm confusion in JWT processing
- **File**: `distrib/manifest_jwt.go:113,172-177`

### M40. Redundant condition / logic error
- **File**: `db_hsync.go:514-519`

### M41. Schema-code mismatch: correlation_id vs distribution_id
- **File**: `db_schema_hsync.go:106`

### M42. Incomplete path traversal protection
- **File**: `parseconfig.go:386-387`

### M43. Mutable global state without synchronization
- **Files**: `config.go:17`, `global.go:40,47`

### M44. API keys stored as plain strings
- **File**: `config.go:208,220`

### M45. Partial config on reload failure
- **File**: `parseconfig.go:550-554`

### M46. Weak zone name validation
- **File**: `parseconfig.go:439-443`

### M47. Global mutable logger state without synchronization
- **File**: `logging.go:26,43,72`

### M48. Incomplete JSON validation in manifest creation
- **File**: `core/chunk_utilities.go:38-47`

### M49. Silent data loss on malformed input in chunk Parse()
- **File**: `core/rr_chunk.go:203-206`

### M50. Debug logging leaks sensitive query details
- **File**: `core/dnsclient.go:166-169`

### M51. Unsafe type conversion for X25519 public key
- **File**: `core/jwk_helpers.go:189`

### M52. Missing UpdateQ nil checks (ops_a_aaaa)
- **File**: `ops_a_aaaa.go:46-75`

### M53. Inconsistent owner normalization
- **File**: `ops_uri.go:81-82`

### M54. Unsafe type assertion (JWK)
- **File**: `ops_jwk.go:72-80`

### M55. Hardcoded placeholder in anti-record
- **File**: `ops_key.go:51`

### M56. Hardcoded port 443 in UnpublishTlsaRR
- **File**: `ops_tlsa.go:80`

### M57. No type validation on stored DNSKEY RR string
- **File**: `ops_dnskey.go:64-68`

### M58. Missing error context in Zones.Get()
- **File**: `catalog.go:250-254`

### M59. CutSuffix result not validated as DNS name
- **File**: `dsync_lookup.go:113-115`

### M60. GetOwner() errors inconsistently checked
- **File**: `auth_utils.go:24`

### M61. AuthQuery error indistinguishable from empty response
- **File**: `rrset_utils.go:46-48`

### M62. Append before eviction can temporarily exceed maxCount
- **File**: `error_journal.go:62-64`

### M63. Race between nil check and lock on global Conf
- **File**: `registration.go:66-75`

### M64. Globals accessed without nil check
- **File**: `childsync_utils.go:22-24`

### M65. TOCTOU race in private key file creation
- **File**: `cli/keys_generate_cmds.go:75-76`

### M66. Private key material in memory as plain string
- **File**: `cli/keys_generate_cmds.go:119,124`

### M67-M69. File reading without symlink validation
- **Files**: `cli/keystore_cmds.go:330-335,436-442`, `cli/truststore_cmds.go:161`, `cli/jwt_cmds.go:476-489`

### M70. Insecure /tmp usage for binary update
- **File**: `cli/daemon_cmds.go:169`

### M71. Insufficient RR validation in combiner
- **Files**: `combiner_chunk.go:199-237`, `combiner_utils.go:285-319`

---

## LOW FINDINGS

### L1. Race condition in HTTP handler closure (set once at startup)
- **File**: `doh.go:26-71`

### L2. No certificate validity check at startup
- **File**: `do53.go:109-117`

### L3. Incomplete error checking in shutdown
- **Files**: `do53.go:89`, `dot.go:74`, `doh.go:101`, `doq.go:68`

### L4. No rate limiting on NOTIFY messages
- **File**: `notifyresponder.go:78-238`

### L5. Rejected LEGACY agent gets SERVFAIL without informative error
- **File**: `handlers.go:197-203`

### L6. No timeout on pending confirmations
- **File**: `dns.go:857-875`

### L7. No domain name length limit in UnpackDomainName
- **File**: `edns0/edns0.go:66`

### L8. Manual JWS splitting without validation
- **File**: `agent/transport/crypto.go:289`

### L9. No TSIG key validation
- **File**: `tsig_utils.go:10-29`

### L10. Missing overflow check in UnixToTimestamp
- **File**: `hpke/utils.go:40`

### L11. Uses log.Printf instead of structured logging
- **File**: `edns0/edns0_chunk.go:323`

### L12. Temporary keys written to /tmp
- **File**: `sig0_utils.go:220`

### L13. No key size validation in Backend interface
- **File**: `crypto/backend.go:16-95`

### L14. Nil ZoneData dereference possible
- **File**: `agent_authorization.go:44-50`

### L15. SIG(0) TTL hardcoded to 300
- **File**: `sign.go:41,117`

### L16. Empty RRset signed without content validation
- **File**: `sign.go:81-83`

### L17. Inconsistent algorithm validation across codebase
- **Files**: `readkey.go:430` vs `keystore.go:931`

### L18. Private keys not encrypted at rest
- **File**: `keystore.go:54-56,293-295`

### L19. Race condition in agent state transitions
- **Files**: `hsync_beat.go:96-137`, `hsync_hello.go:209-236`

### L20. Inefficient O(n) map iteration per tick
- **File**: `reliable_message_queue.go:352-419`

### L21. Logging of sensitive data patterns
- **Files**: `hsync_utils.go:368-370`, `combiner_msg_handler.go:243`

### L22. Hardcoded timeouts not configurable
- **Files**: `hsync_hello.go:68`, `combiner_msg_handler.go:293`, `signer_msg_handler.go:209`

### L23. Missing input sanitization on RR content
- **File**: `agent_policy.go:34-37`

### L24. Unvalidated zone parameter (but parameterized)
- **File**: `db_combiner_edits.go:437`

### L25. Schema migration silently ignores errors
- **File**: `db.go:117-139`

### L26. Nil deref race in Zones.Get result
- **File**: `config.go:558-568`

### L27. Certificate validation TOCTOU
- **File**: `config_validate.go:131-183`

### L28. FindAgent returns nil without guards
- **File**: `config.go:103-111`

### L29. Silent panic recovery masks bugs
- **File**: `core/rrset_utils.go:290-303`

### L30. InsecureSkipVerify enabled by default in DoQ client
- **File**: `core/dnsclient.go:141-143`

### L31. Debug dump.P() left in production code
- **File**: `ops_key.go:274`

### L32. Deprecated function not removed
- **File**: `catalog.go:450-455`

### L33. Hardcoded index access on Fields() result
- **File**: `rr_print.go:89-92`

### L34. Silent error handling in GetOnlyRRSet
- **File**: `rrtypestore.go:26-27`

### L35. NewAuthServer returns nil without error
- **File**: `cache/authserver.go:55-76`

### L36. stty command execution errors ignored
- **File**: `cli/interactive.go:109-112`

### L37. Minimal validation of server/port input
- **File**: `cli/update.go:339-341`

### L38. Error messages may leak infrastructure details
- **File**: `cli/notify_cmds.go:86-89`

### L39. Database file created with 0644 permissions
- **File**: `cli/db_cmds.go:42`

### L40. Closure variable capture concern
- **File**: `ops_dsync.go:35-56`

---

## Top Recommendations (Priority Order)

1. **Add missing bounds checks on `r.Question[0]`** in `do53.go` and `dot.go` (DoS via crafted DNS messages — already fixed in DoH/DoQ)
2. **Fix plaintext fallback** in `chunk_notify_handler.go` — return error on encryption failure, never fall back
3. **Add `io.LimitReader` / size caps** to all `io.ReadAll` calls on network input (`core/dnsclient.go`, transport handlers)
4. **Protect shared state with mutexes** — ZoneData fields, PendingRemoteConfirms, verifications map, keystore cache, global Conf
5. **Check all JSON unmarshal errors** — especially in `db_hsync.go` where corrupted data silently propagates
6. **Add JWT expiration** (`exp` claim) to manifests and validate on receipt
7. **Validate confirmation protocol** — add nonce, HMAC, and Source validation to prevent spoofing
8. **Fix nil pointer dereferences** — add nil checks after GetOwner, BumpSerial, GetRRset, Zones.Get calls
9. **Add timeouts to channel sends** — wrap all `UpdateQ <-` sends with `select` + `time.After`
10. **Use constant-time comparison** for cryptographic values (DS digests, API keys)
