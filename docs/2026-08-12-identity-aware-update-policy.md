# Identity-aware update policy: granting a principal authority over names that are not its own

**Date:** 2026-08-12
**Status:** DESIGN. Nothing built.
**Branch:** `feature/update-policy-rules`, off `feature/dsync-api-scheme`.
**Prerequisite for:** the statusd migration onto the DSYNC API path
(`2026-08-11-dsync-api-scheme.md` §18). **Not** a prerequisite for the DSYNC API
scheme itself, which works today for the case it was built for.

---

## 1. The problem

`updatepolicy` cannot name an identity. It says, for either scope:

```yaml
updatepolicy:
   child:
      type:    selfsub
      rrtypes: [ A, AAAA, NS, DS ]
```

which means "for whichever principal authenticated, permit names at or below
**that principal**, of these types". The permitted name is *derived from* the
asker. `self` and `selfsub` are the only two answers, and both tie the name to
the identity.

That is exactly right for the case it was written for — a child managing its own
delegation — and cannot express anything else.

### The case it cannot express

statusd manages delegations in three parent zones: `dnslab.`,
`10.in-addr.arpa.` and `e.f.f.3.ip6.arpa.` (the eleven zones in
`services.zonemgr.zones` include eight more, but those are parents of
*infrastructure* zones and have no student children).

To grant statusd authority over `dnslab.` today, its principal must **be**
`dnslab.`. A second parent then needs a second principal, and since the
principal defaults to the username, a second username. Johan, 2026-08-12:

> We cannot have unique usernames per parent zone, that's a broken model.

He is right, and the reason is worth stating precisely: **this conflates
identity with authorization.** statusd is one thing. What it may do is three
things. A model that forces the identity to multiply in order to express the
authorization has the two glued together.

---

## 2. What BIND does

From `named.conf(5)`, BIND 9.20:

```
update-policy { ( deny | grant ) <string>
                ( name | subdomain | zonesub | self | selfsub | selfwild
                | wildcard | external | tcp-self | 6to4-self | krb5-* | ms-* )
                [ <string> ] <rrtypelist>; ... };
```

The structural answer is in the field list, and it is one idea:

**Identity and name are separate fields.** `self`, `selfsub` and `selfwild`
derive the permitted name from the identity — tdns's entire current model.
`name`, `subdomain`, `zonesub` and `wildcard` state the name **independently of
who is asking**. That decoupling is the thing tdns is missing.

Two supporting properties:

- It is a **list** of rules per zone, so one identity can hold several grants.
- Each rule carries **its own rrtype list**, so types are scoped per rule rather
  than per zone.

BIND writes the statusd case, in dnslab's zone, as:

```
update-policy {
    grant statusd zonesub NS DS A AAAA;    # this identity, anywhere in this zone
    grant *       selfsub NS DS A AAAA;    # every child, its own subtree
};
```

One identity, granted separately in each parent zone — because the policy lives
with the **zone**, not with the credential.

---

## 3. Design

### 3.1 The rule list

`UpdatePolicyDetail` gains `Rules`, so both `updatepolicy.child` and
`updatepolicy.zone` get this for free — they are the same type.

```yaml
zones:
   - name: dnslab.
     updatepolicy:
        child:
           rules:
              - grant:    statusd.
                nametype: zonesub
                rrtypes:  [ NS, DS, A, AAAA ]
              - grant:    "*"
                nametype: selfsub
                rrtypes:  [ NS, DS, A, AAAA ]
```

| Field | Meaning |
|---|---|
| `grant` | the identity: a principal name, or `*` for any authenticated principal |
| `nametype` | how the permitted name is determined (§3.2) |
| `name` | the name the nametype needs, where it needs one |
| `rrtypes` | the types this rule permits |

### 3.2 Nametypes

Deliberately a subset of BIND's, named identically so the concept transfers.
Only what is needed, plus the one obvious neighbour:

| nametype | Permitted name | `name` field |
|---|---|---|
| `self` | exactly the identity | — |
| `selfsub` | the identity or below | — |
| `zonesub` | anywhere in this zone | — |
| `subdomain` | the given name or below | required |

`zonesub` alone solves statusd. `subdomain` is included because "this identity
manages one branch of the zone" is the obvious next request and costs nothing
once `name` exists.

**Deferred, with no known need:** `name` (exact, unrelated to identity),
`wildcard`, `selfwild`, and everything Kerberos/MS. Also `deny` rules — see
§3.5.

### 3.3 One evaluator: the shorthand desugars

The existing `type:`/`rrtypes:` shorthand is **not** a parallel mechanism. It
desugars into a single trailing rule:

```yaml
type:    selfsub
rrtypes: [ A, AAAA, NS, DS ]
```
becomes
```yaml
- grant: "*", nametype: selfsub, rrtypes: [ A, AAAA, NS, DS ]
```

So there is one evaluation path, over one ordered rule list, and every existing
config behaves identically because it produces exactly the rule it always meant.
`type: none` and an unset type desugar to *no* rule, which under §3.4 denies
everything — again the existing behaviour.

This matters more than it looks: yesterday's consolidation of the policy check
into `evalUpdatePolicyRR` (`2026-08-11-dsync-api-scheme.md` §6.3) is what makes
this a contained change. There is one place to put the loop.

### 3.4 Matching, and default deny

A rule matches when **all three** hold:

1. the identity matches (`*`, or a case-insensitive DNS-name comparison);
2. the owner name satisfies the nametype;
3. the rrtype is in the rule's list.

Rules are checked **in order; the first match grants**. If no rule matches, the
update is **refused** — default deny, as today.

Including the rrtype in the match (rather than checking it after selecting a
rule) is what lets one identity hold different name scopes for different types:

```yaml
- grant: statusd.,        nametype: zonesub,  rrtypes: [ NS, DS, A, AAAA ]
- grant: registrar.dnslab., nametype: subdomain, name: se.dnslab., rrtypes: [ DS ]
```

**Diagnostics.** With a three-way match, a refusal no longer says *why*, and the
DSYNC API's 403 reason and the DDNS path's EDE both depend on knowing (§7.3 of
the DSYNC API doc). So on the failure path only, a second pass asks: did any
rule match identity and name but not type? If so the answer is
`EDEZoneUpdateRRtypeNotAllowed`; otherwise `EDEZoneUpdateOwnerOutsidePolicy`;
and with no rules at all, `EDEZoneUpdatesNotAllowed`. Cheap, because it runs
only when the answer is already "no".

### 3.5 No `deny`, for now

BIND has `deny` rules and they are useful for carve-outs. Grant-only with
default-deny covers every case we have, and ordered grant+deny is a second thing
to reason about in a security-relevant evaluator.

Adding `deny` later is a strictly additive change to an already-ordered list, so
nothing here forecloses it. Left out on the KISS principle rather than on a
judgement that it is wrong.

### 3.6 The combination to warn about

`grant: "*"` with a nametype that does **not** tie the name to the identity —
`zonesub` or `subdomain` — grants *every* authenticated principal authority over
names that are not theirs. In a zone with per-child credentials that means any
child can rewrite any other child's delegation.

There is no legitimate use of it that we know of, and it is one character away
from a correct config. Config validation should **warn loudly** at startup on
that combination, naming the zone and the rule. Not refuse — an operator who
means it can have it — but never silent.

---

## 4. The credential model must change with it

`DsyncApiCredential` is currently `UNIQUE(parentzone, username)`, and
`VerifyDsyncApiCredential(parentZone, username, key)` refuses a credential
issued for a different parent. That scoping was right when authorization was
derived from the principal name; with rules carrying the scoping it is
redundant, and it **relocates the problem rather than solving it**: statusd
would keep one username and still need a separate row per parent, hence a
separate *key* per parent.

So credentials become server-global identities:

```
DsyncApiCredential(id, username, principal, keyhash, created, expires, disabled, comment)
UNIQUE(username)
```

and `VerifyDsyncApiCredential(username, key)` authenticates without reference to
a zone. What the resulting principal may do in a given zone is decided entirely
by that zone's rules, default-deny — an identity no zone grants anything to can
do nothing anywhere.

This is BIND's model exactly: a TSIG key is server-global; each zone's
`update-policy` says what it may do *there*.

**Migration cost is near zero today and rises fast.** The table is one day old,
nothing depends on it, and the only databases containing it are two test rigs on
foffe. `CREATE TABLE IF NOT EXISTS` will not alter an existing UNIQUE
constraint, so those two test databases need recreating — which is the honest
answer while the count is two. Once cpt has credentials in it, this becomes a
real migration.

---

## 5. What does not change

- The DSYNC API listener, its endpoints, TLS handling and discovery.
- The five zone-update statements and both zone-content channels.
- `self`/`selfsub` semantics, including yesterday's label-aligned,
  case-insensitive name comparison.
- **Every existing config**, via §3.3.

---

## 6. This is not only about the API path

`updatepolicy.child` is shared by both transports, so the same limitation
applies to RFC 2136 today: a SIG(0) identity cannot be granted a subtree that is
not its own. An operator wanting one key to manage several children's
delegations has the same non-answer, and has had it all along.

The rules list fixes both at once. That is an argument for doing it properly
rather than adding a narrow "statusd may do this" special case.

---

## 7. PR plan

| PR | Scope | Notes |
|----|-------|-------|
| **1** | Rule types, config, desugaring, and the evaluator loop — with only `self`/`selfsub`, i.e. **no behaviour change** | Same technique as the §6.3 extraction: a verbatim replica of the current evaluator, run against the new one over a table, with an explicit empty divergence list |
| **2** | `zonesub` and `subdomain`, identity matching, the `*` wildcard, the §3.6 warning | The feature |
| **3** | Credentials become server-global (§4) | Small, and cheapest now |
| **4** | statusd: one identity, `zonesub` in three parent zones | labstuff, separate repo |

PR 1 alone again, for the same reason as last time: it is the only part that can
break something that works today, and the DDNS path runs through it.

---

## 8. Open questions

1. **Identity spelling.** Principals are normalised as domain names, so the rule
   would read `grant: statusd.` with the trailing dot. Correct and consistent,
   but it looks odd for an identity that is not a zone. Accept both spellings
   and normalise (the plan), or require the dot?
2. **Does `zone` scope need rules too?** It gets them for free — same struct —
   but there is no request for it. Ship it or gate it?
3. **statusd's grant breadth.** `zonesub` gives statusd authority over every
   delegation in the zone. That is what its job requires, and it is a large step
   down from the operator API key it holds today, but it is worth stating in the
   config rather than discovering later. A `subdomain`-per-course-group model
   would be narrower and much more config; not proposed.
