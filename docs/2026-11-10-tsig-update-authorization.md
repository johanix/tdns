# TSIG-authorized RFC 2136 UPDATE

**Date:** 2026-11-10
**Status:** AS BUILT (branch `feat/tsig-update-authorization`).
**Lifts** the non-goal "TSIG as UPDATE authorization" in
`2026-08-10-ddns-cli-and-api-updates.md` (F9, §13). That document stays as it was;
this one takes over for TSIG.
**Builds on** the direction sketched in `2026-07-25-ddns-cli-and-api-updates.md` §7: an
explicit opt-in per key, and no key gaining update rights just because it is configured.
**Related:** `2026-08-12-identity-aware-update-policy.md` (BIND-style rules for any
principal; design only). The TSIG grants here have the same shape and can be folded
into those rules later.

---

## 1. Why

Before this change, tdns authorized UPDATE by SIG(0) only. A TSIG on an UPDATE was
verified at the transport and then ignored. The SIG(0) validator found no SIG RR and
answered BADKEY. That shuts out the clients that only speak TSIG. The common case is
ACME DNS-01: lego's and certbot's RFC 2136 plugins sign with TSIG and nothing else, and
so do many home-grown dynamic-DNS updaters written against BIND.

## 2. Configuration

Two parts: an admission switch, and per-key grants.

```yaml
zones:
  - name: dyn.example.
    type: primary
    options: [ allow-tsig-updates ]
    updatepolicy:
      zone:
        type: none                 # SIG(0) policy: unchanged and independent
        ttl: 60                    # applies to TSIG updates as to SIG(0) ones
        tsig:
          - key: ddns-updater.     # anything in the zone, ordinary data
            nametype: zonesub
            rrtypes: [ ANY ]
          - key: acme.             # ACME challenges only
            nametype: subdomain
            name: _acme-challenge.dyn.example.
            rrtypes: [ TXT ]
          - key: host1.dyn.example. # its own name only
            nametype: self
            rrtypes: [ A, AAAA, TXT ]
          - key: signer.           # one exact name, named DNSSEC types
            nametype: name
            name: dyn.example.
            rrtypes: [ DNSKEY, CDS, CDNSKEY ]
```

- **`allow-tsig-updates`** turns TSIG-authorized UPDATE on, separately from
  `allow-updates` (SIG(0)) and `allow-api-updates` (the management API). This follows the
  precedent of `allow-api-updates` (08-10 F1). It is an origination option: a secondary
  that may not originate content has it normalized away, just as it has
  `allow-updates` removed.
- **`updatepolicy.zone.tsig`** is the list of grants. A key gets update rights only from
  a grant that names it. Keys are server-wide, in the TSIG keystore; grants are per zone,
  so one key can be granted different things in different zones.

| nametype | The owner may be | `name` |
|---|---|---|
| `zonesub` | anywhere in the zone | — |
| `subdomain` | `name` or below; `name` must be in the zone | required |
| `name` | exactly `name` | required |
| `self` | exactly the key's own name; the key name must be in the zone | — |

A record may be changed when some grant names the key, covers the owner and covers the
type. Names compare as DNS names: case-insensitively, and on label boundaries.

- **No wildcard key.** `key: "*"` is refused. BIND's `grant * self * A TXT` becomes one
  `self` grant per key. A key configured for transfers or NOTIFY must never become an
  update key by accident.
- **No deny rules.** Grants only add, so their order does not matter.
- **Narrow ANY.** `ANY` in `rrtypes` covers every type except SOA, DNSKEY, RRSIG, NSEC,
  NSEC3, NSEC3PARAM, CDS, CDNSKEY, CSYNC and ZONEMD. Those are the zone's serial, its
  DNSSEC, the signals that change its delegation at the parent, and its digest, and they
  have to be listed by name. BIND's ANY covers all but NSEC and NSEC3. A key handed out
  for host addresses or ACME challenges should not be able to replace the zone's DNSKEY
  or move its DS. An UPDATE that deletes everything at a name (TYPE ANY, RFC 2136
  §2.5.3) needs a grant of `ANY`, and then deletes only the types the key may change.
- **Refused at load:** a grant with no key, `*`, an unknown or missing nametype, a
  missing, superfluous or out-of-zone `name`, a `self` key outside the zone, no rrtypes,
  or an unknown rrtype. A silently dropped type would refuse updates the operator
  believes are allowed.
- **Warned about at load:** grants without `allow-tsig-updates`, and
  `allow-tsig-updates` without grants. Each half alone accepts nothing.

## 3. The update path

`UpdateResponder` first does what every update gets: zone lookup, the NOTZONE check, and
then (§5) the prerequisite check. After that it splits by mechanism:

1. **TSIG** applies when the message carries a TSIG and no SIG RR. A message carrying
   SIG(0) takes the SIG(0) path exactly as before, whether or not it also has a TSIG.
2. **The MAC must have verified.** On Do53 and DoT, `TsigSigningHandler` has already
   answered NOTAUTH for a bad MAC, an unknown key, the wrong algorithm or a bad time, so
   the update path is never reached. The responder still requires
   `w.TsigStatus() == nil`, because DoH and DoQ cannot verify a TSIG and report so.
3. **No delegation data.** Delegation data for a child, and child key material, stay
   SIG(0): those updates cross an administrative boundary, where asymmetric keys are the
   right tool. TSIG on them is REFUSED. The message's classification is not enough on its
   own: a zone section naming a name inside the zone skips the delegation classifier,
   and an update mixing zone data with a child's records is classified as an update of
   the zone's own data. So every record is checked as well. An NS or DS anywhere below
   the apex, or any record at or below an existing delegation point, refuses the
   message.
4. **Admission** reads `allow-tsig-updates` instead of `allow-updates`.
5. **The grants** are checked against every record. The first refusal refuses the whole
   message.
6. **The rest is shared:** the ZoneUpdater, the delta journal, the TTL from
   `updatepolicy.zone.ttl`, and the answer sent once the change has been applied,
   persisted and published (08-10 §10).

`UpdateRequest` carries an `Authz` (mechanism, key, the zone's grants). The applier's
per-type checks ask it, through `typeAllowed`, instead of the SIG(0) type list. Without
an `Authz` they are unchanged. The ZoneUpdater's admission backstop accepts a TSIG
request on `allow-tsig-updates`.

## 4. Responses

Every response to a request whose TSIG verified is TSIG-signed, refusals included.

| Case | rcode | TSIG error / EDE |
|---|---|---|
| Unknown key, wrong algorithm | NOTAUTH | TSIG error BADKEY, unsigned |
| Bad MAC | NOTAUTH | BADSIG, unsigned |
| Time outside the fudge | NOTAUTH | BADTIME; signed with the request's key (RFC 8945 §5.2.3) once #1024 is in |
| TSIG on DoH/DoQ (cannot be verified) | REFUSED | EDE Other |
| Zone without `allow-tsig-updates` | REFUSED | `EDEZoneUpdatesNotAllowed` |
| Key verified, but no grant for it in the zone | REFUSED | `EDEZoneUpdatesNotAllowed` |
| A grant for the key, but none covers the owner | REFUSED | `EDEZoneUpdateOwnerOutsidePolicy` |
| Owner covered, type not | REFUSED | `EDEZoneUpdateRRtypeNotAllowed` |
| TSIG on child delegation data or key material | REFUSED | `EDEZoneUpdatesNotAllowed` |
| Prerequisites present (§5) | NOTIMP | EDE 21 Not Supported |
| Applied, or failed to apply | NOERROR / SERVFAIL | as for SIG(0) |

The split between an unknown key (NOTAUTH/BADKEY) and a known key without rights
(REFUSED) is RFC 8945's and RFC 2136's, and it is what BIND does.

## 5. Prerequisites are refused, on both paths

tdns did not evaluate the RFC 2136 prerequisite section; it ignored it. A client relying
on a prerequisite got an unconditional apply and a NOERROR, so its compare-and-swap
became a plain write. An UPDATE with a prerequisite section is now answered NOTIMP with
EDE 21 (Not Supported), for SIG(0) as well as TSIG. No sender in tdns uses
prerequisites. Evaluating them properly is possible future work. Refusing is the
fail-closed answer until then.

## 6. What does not change

- **SIG(0) UPDATE:** validation, trust and approval are untouched. With no `Authz`, the
  applier's type checks are the old lookup. `allow-updates`, and its forcing to off on
  `type: none`, are unchanged.
- **Child delegation updates, the truststore, KeyState:** SIG(0) only. KeyState is not
  on the UPDATE path.
- **The management API:** `allow-api-updates` and `PreAuthorized` are untouched.
- **Internal publishers** (CSYNC, CDS, KEY, DNSKEY) bypass both mechanisms, as before.
- **TSIG for transfers and NOTIFY:** the same keystore, unchanged. A key gets no update
  rights unless a grant names it.

## 7. Not in this change

- Grants for API-provisioned zones through the management API or CLI. Grants are
  config only.
- hmac-md5. The keystore accepts hmac-sha1 to hmac-sha512 only.
- `*` grants, deny rules, and BIND's other name types (`wildcard`, `selfsub` for TSIG,
  `selfwild`, `krb5-*`, `ms-*`).
- Evaluating prerequisites.
