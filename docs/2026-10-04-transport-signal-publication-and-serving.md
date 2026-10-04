# The transport signal on the authoritative side: what a server publishes, what it injects

**Date:** 2026-10-04. **Status:** design, agreed; implementation follows in the
publish-gate follow-up PR (Refs #653) together with Amendment 5 of
`2026-09-17-publish-gate-and-transactions.md`. Amendment 1 (the server-wide
option) is at the end.

The transport signal is the SVCB (RFC 9460, RFC 9461) or TSYNC RRset under the
`_dns.` label of a nameserver's name, telling a resolver which transports that
nameserver offers. The resolver side (how tdns-imr asks for, caches and refreshes
the signal) is in `2026-09-26-imr-refresh-engine.md`. This document is the
authoritative side: which signals a tdns-auth server publishes into the zones
it serves, which it injects into its responses, and which it leaves alone. The
code is `v2/tsignal.go` (the start-up pass) and the responder's
`collectSignalRRsets` (injection). Nothing here changes the wire format.

## 1. The rule

**A server speaks only about itself.** It publishes and injects a signal for a
nameserver name exactly when it can know that the name is one of its own:

- the name's A and AAAA records in the zone are this server's listener
  addresses; or
- the name is one of the server's configured identities; or
- the name is the target of an operator-authored alias and the server hosts the
  target's zone.

It never guesses, and it never asks anyone: **no recursive query is ever made
to find a signal.** What the server does not have, it does not inject; the
resolver chases what it is handed.

**Zone content is signed by whoever signs the zone, and a secondary serves
what it received.** A server stores a synthesized signal as a real owner RRset
in a zone only when it may originate content in that zone (a primary, or an
inline-signing secondary: `2026-07-25-secondary-zones-immutable.md`) and
either signs the zone itself (then the signal is signed before it is staged,
and the resigner keeps it fresh) or the zone is unsigned. Any other server
stores nothing into the zone: a secondary that may not originate would serve
content that differs from upstream's at upstream's serial, and an unsigned
owner under a signed apex is bogus to a validating resolver, with the
signer's NSEC chain denying the name. Such a server keeps at most an unsigned
fallback beside its snapshot, which is injected into the additional section
and is never zone content, never transferred, and never an answer to a direct
query. For that reason `add-transport-signal` is not an origination option:
on a secondary that may not originate it means "serve a signal for this
zone's NS names", and the option normalizer no longer strips it there
(Amendment 1 of the 2026-07-25 design).

## 2. The cases

Names are examples. `example.com` is the hosted zone; `provider.example` is a
provider whose nameserver is `ns.provider.example`.

| # | The server is | What it publishes | What it injects |
|---|---|---|---|
| 1 | the primary of `example.com`, and `ns1.example.com` (in bailiwick) resolves to its addresses | `_dns.ns1.example.com` ServiceMode, stored; signed if it signs the zone, unsigned if the zone is unsigned | the stored RRset |
| 1b | as 1, but its NS name is out of bailiwick (`ns.provider.example`) | nothing into `example.com`: the signal's home is `provider.example`. Co-hosted: it lives there. Not hosted, and the name is one of this server's identities: an unsigned fallback beside the snapshot | the co-hosted zone's signed RRset, or the fallback |
| 2 | a hidden primary | nothing: no NS name resolves to its addresses. The zone should not carry `add-transport-signal`; if it does, the pass logs a warning once at start-up | nothing |
| 3 | a signing secondary (`inline-signing`) | as 1, signed with its keys; a refresh carries the stored owners and their signatures across both an IXFR and a full replacement | the stored RRset |
| 4 | a non-signing secondary of a zone signed elsewhere | **nothing into the zone** (section 1). At most the unsigned fallback | the fallback, or nothing |
| 5 | a non-signing secondary of an unsigned zone | **nothing into the zone either**: it may not originate content (section 1). The unsigned fallback | the fallback |
| 6 | one server with several NS names (`ns1` and `ns2.example.com`, two addresses) | one signal per name, each with that name's own addresses | all of them |
| 7 | a nameserver reached through a vanity name (`ns2.example.com` is really `ns.provider.example`) | nothing synthesized at the vanity name when the operator has placed an alias there (section 3); without one, a ServiceMode signal under the vanity name, which is also correct | section 4 |

A primary that feeds a bump-on-the-wire signer is not a case: it never serves
the zone.

## 3. The vanity name: an operator's alias

The server cannot know what a vanity name stands for, so the alias is the
operator's to write, as ordinary zone content, signed by whoever signs the zone:

```
_dns.ns2.example.com.     IN SVCB 0 _dns.ns.provider.example.
```

The provider's own record is the provider's zone's business and is what that
zone synthesizes or carries anyway:

```
_dns.ns.provider.example. IN SVCB 1 . ...
```

**The target carries the `_dns.` label.** RFC 9460 section 3, step 2: a client
that receives an AliasMode record sets its query name "to its TargetName
(without additional prefixes)". tdns chases the target literally too. (Today's
chaser prepends the label; that is the non-compliance this design removes.)

**An AliasMode RRset holds one record and nothing else.** RFC 9460 section
2.4.1: all RRs of an SVCB RRset should have the same mode, and "if an RRset
contains a record in AliasMode, the recipient MUST ignore any ServiceMode
records in the set". tdns refuses a mixed RRset at zone load and in an update
that would create one, rather than serve records a client discards. An
AliasMode record's SvcParams are ignored by recipients (section 2.4.2); tdns
does not refuse them, it just never adds any.

The start-up pass leaves an operator alias untouched and goes on to the next NS
name: an alias at one name says nothing about the server's other names.

## 4. Serving: direct queries and injection

**A direct query** for `_dns.<ns>` is answered from zone content like any other
name: a stored signal, an operator alias, or the zone's denial. The fallback of
section 1 is never an answer to a direct query.

**Injection** adds signals to the additional section of the responses that
carry the zone's NS set. The responder walks the apex NS set and, per name:

1. a stored ServiceMode signal is injected (it is there only if the pass
   decided the name is the server's own);
2. an operator alias is injected when the server can know it is about itself,
   in either of two ways: (a) it hosts the target's zone, and then the target's
   signal is injected with it, signed there; or (b) the vanity name's own A and
   AAAA are this server's listener addresses, and then the alias goes alone and
   the resolver chases it. Neither: the alias is not injected (it still answers
   direct queries);
3. a target is chased literally (no label added), to a depth of three, each
   owner once, and only from what the server holds: a co-hosted zone's
   snapshot, or the fallback of section 1. An alias target that is one of this
   server's identities, whose zone is not hosted, gets the same fallback an
   out-of-bailiwick NS name gets.

Three NS names and a server that is two of them therefore yields up to three
records: the alias at the vanity name, the record at its target if hosted, and
the ServiceMode record of the other name.

## 5. Publishing: the start-up pass

`CreateTransportSignalRRs` runs once per zone with `add-transport-signal`,
after every zone has finished its first load. It walks **every** NS name of the
apex, never returning early, and per name does one of:

- an operator alias at `_dns.<ns>`: leave it;
- the name's addresses are this server's listeners: build the ServiceMode
  signal from the server's transport configuration and the name's addresses;
  sign it if this server signs the zone; refuse to store it if the zone is
  signed and this server does not sign it (section 1), keeping at most the
  fallback; stage it otherwise;
- an out-of-bailiwick name that is one of this server's identities: nothing
  stored if its zone is co-hosted, else the fallback;
- anything else: skip.

If the walk stored nothing and the zone carries the option, the pass logs a
warning: either a hidden primary with a stray option or an NS set that does not
name this server.

The pass publishes what it staged. With the publish gate
(`2026-09-17-publish-gate-and-transactions.md`, Amendment 5) the serial-less
publish it has always used is allowed only when the working set it found was
bare, that is, seeded by the pass itself from the served snapshot; when another
writer's change is pending in the working set, the pass stages its signal and
asks the gate, and the signal rides with that change's publish and serial.

A refresh preserves stored signal owners and their signatures across a
replacement (`CollectDynamicRRs`), so a secondary keeps its signals between
start-ups.

## 6. What changes in the code

| Today | This design |
|---|---|
| the pass returns after the first NS name it handles (a stored signal or an operator alias) | the pass walks every NS name |
| `dak == nil` is read as "the zone is unsigned", so a non-signing secondary stores an unsigned owner into a signed zone | a server stores into a zone only if it may originate content there and either signs it or the zone is unsigned; otherwise at most the fallback |
| `add-transport-signal` is an origination option, stripped from every non-inline-signing secondary on tdns-auth, so such a secondary never runs the pass and injects nothing | the option stays on a secondary and means "serve"; the storing is gated in the pass; the three readers of the option go through one helper (`addsTransportSignal`), where a server-wide default can be resolved later |
| the chaser prepends `_dns.` to an alias target | the target is chased literally (RFC 9460 section 3) |
| a mixed AliasMode/ServiceMode RRset is accepted | refused at load and by an update (RFC 9460 section 2.4.1) |
| an operator alias is injected unconditionally | injected only when it is about this server (section 4, two ways) |
| no fallback for an alias target that is this server's identity | the same fallback as for an out-of-bailiwick NS name |
| no warning for the option on a zone that does not name this server | one warning at start-up |

## 7. Tests

- one server, two NS names: two stored signals, both injected;
- an operator alias at one name and the server's own name after it: the alias
  kept, the own signal stored;
- a non-signing secondary of a signed zone: nothing stored, the zone's
  signatures untouched, the fallback injected; a real tdns-auth secondary of
  an unsigned zone, its options through the normalizer: the option kept,
  nothing stored, the fallback injected;
- a signing secondary: stored signed, kept across a full replacement;
- alias chasing: target used literally; a target with a prepended label is not
  looked up;
- a mixed RRset refused at load and by an update; a single AliasMode record
  accepted;
- injection: alias with hosted target → both; alias with the vanity name's
  addresses ours → alias alone; neither → nothing injected, direct query still
  answered;
- the option on a zone that names none of the server's addresses → warning,
  nothing stored.

## 8. Out of scope, named

- **Signer-authored signals for the whole NS set.** For an in-bailiwick NS name
  served by a non-signing secondary, the only signed signal can come from the
  zone's author: the primary publishing a signal for every NS whose transports
  it knows (configured per NS, or exchanged between the servers). That solves
  case 4 properly and covers secondaries running other software. Its own design
  round; it changes who authors what.
- **TSYNC is not covered by this round.** Its pass keeps the earlier
  behaviour (it stops at the first name it stores and has neither the
  signed-elsewhere rule nor the alias handling); the TSYNC signal is to be
  removed in its own PR rather than brought up to these rules.

## Amendment 1, 2026-10-04: the server-wide option

Everything above stands. It speaks of "a zone with `add-transport-signal`";
since this amendment a zone has the option when it sets it itself **or** when
the server sets it for every zone, in `authengine: options:` of tdns-auth.

- **Where it is resolved.** `zd.addsTransportSignal()`, the single reader of
  the option, and `zd.transportSignalSource()` beside it, which says where the
  value comes from: `zone` (the zone's own option, possibly via its template),
  `global` (the server's), or empty when it is off. A zone that sets the option
  itself reports `zone` even when the server sets it too. The server's value is
  read from the KeyDB at the point of use and never written into
  `zd.Options`: the option finalization sites are many, and `zd.Options` is
  persisted with dynamic zones, which would turn a server default into each
  zone's own setting.
- **No per-zone opt-out.** A zone under the server-wide option cannot turn it
  off.
- **A wildcard listener names this host, not every address.** Section 1's
  "the name's A and AAAA records are this server's listener addresses" used to
  hold for any address when the server listened on `0.0.0.0` or `[::]`, so
  such a server took every in-bailiwick NS name as its own and, in a zone
  shared with another provider, published its transports under the other
  provider's name. The server-wide option would have done that in every
  zone. A wildcard listener now matches the host's interface addresses, read
  at most once a minute (the responder asks per response); when they cannot
  be read, it matches nothing.
- **The rules of sections 1 to 5 apply unchanged.** The server still speaks
  only about itself, and stores into a zone only where it may originate
  content and signs the zone or the zone is unsigned. A secondary under the
  server-wide option therefore gets the injection and at most the unsigned
  fallback, as under its own option.
- **The start-up warning of section 5** ("no NS name of the zone is this
  server") is for an option the zone set itself: a stray option, say on a
  hidden primary. Under the server-wide option such a zone is ordinary, and
  the pass says so at debug level instead of warning once per zone.
- **tdns-agent refuses it.** The agent shares the `authengine` block, but the
  safeguards that keep a secondary serving what it received are tdns-auth's;
  on the agent every zone may originate content, so the server-wide option
  would publish into every secondary it serves. `ParseConfig` refuses the
  option, any value, before the options reach the KeyDB, at a start and at a
  reload alike.
- **Listing.** The zone listing carries the source
  (`ZoneConf.AddTransportSignalSource`), and `zone list` shows a server-wide
  option as `add-transport-signal(global)` among the zone's options.
- **A reload.** A reload that turns the server-wide option on or off reaches
  injection at once. Stored signals follow at the next run of the pass, which
  runs after a zone's first load: the next start, or a zone added later. A
  zone option changed by a reload waits for the same run.
