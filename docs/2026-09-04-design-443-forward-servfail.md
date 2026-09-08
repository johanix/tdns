# #443 - forwarding resolver stops resolving, silently

Not committed. Written 2026-09-04, rewritten the same evening after Johan
supplied the mechanism and the lab refuted my follow-up prediction.

## Current position: probably already fixed. Do not fix it again - test it.

Johan's read, which is better than any of the four hypotheses I had:

> The symptoms are the same as what we saw when we fixed the issue of an imr
> never re-priming. Sooner or later "." would expire from the cache and from
> then onwards there was no recovery. Now we automatically re-prime "." 60s
> before it expires.

That explains every symptom in the report, including the one none of my
hypotheses touched: **`. NS` itself returned SERVFAIL**. A resolver that has
lost the root delegation and cannot recover it answers exactly as reported -
cached names fine, everything else SERVFAIL, nothing logged, healthy upstream,
restart cures it.

The issue was observed on `b4fa3582`, which predates the re-primer.

## The forwarder objection, and why it did not hold

Johan's caveat was that #443 is a *forwarder*, so slightly different. I went
looking and thought I had confirmed a real gap:

`RefreshRoot` is documented as refreshing "AGAINST THE LIVE ROOTS, not from the
hints file" (`v2/imr_root_refresh.go:51`), and `rootNSQuery` (`:129`) calls
`IterativeDNSQuery` with the cached root ServerMap - the iterative resolver,
not the forward path. On a forward-only resolver whose upstream works but whose
actual root servers are unreachable, that should fail every time, and once the
root NS RRset expired the fallback would re-prime from hints into the same
unreachable addresses.

**The lab says otherwise.** `imr.golf` is exactly that topology:

- forward-only, `zone: .` to 172.16.0.7
- the lab roots (172.16.0.17, 172.16.1.17, 172.16.2.17) are blocked from that
  host by the group NPF policy, which permits the IMR only 172.16.0.5 and
  172.16.0.7. Verified this afternoon: priming from hints failed with i/o
  timeout to all three roots
- lab root NS TTL is 900s

It has been running since 19:24 and the log shows:

```
20:34:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=20:49:05
20:48:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=21:03:05
21:02:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=21:17:05
21:16:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=21:31:05
21:30:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=21:45:05
21:44:05 RefreshRoot: root NS refreshed from the live roots servers=3 expiration=21:59:05
```

Nine-plus consecutive refreshes, each 60s before expiry, and a fresh
(non-cached) name still resolves NOERROR after two and a half hours.

**Mechanism, now chased down: the re-primer is already forwarder-aware, because
the routing is inside `IterativeDNSQuery` rather than above it.**
`v2/dnslookup.go:1310`:

```go
	// Forwarding: when qname falls under a configured forward zone, hand the
	// ... forward zone outranks whatever zone cut the caller had found.
	if fz := imr.forwardZoneFor(qname); fz != nil {
```

`rootNSQuery` asks for `. NS`; `.` falls under the configured forward zone `.`;
the query goes to the forwarder and never touches the blocked roots. There is
matching handling for a forwarded root at prime time (`v2/imrengine.go:303`,
`if imr.forwardZoneFor(".") != nil`), which is why adding a forward made
`imr.golf` start this afternoon after priming from hints had failed.

**So there is nothing to make forwarder-aware - it already is.** A change aimed
at that would be a no-op at best.

My prediction was wrong. Recording it because the reasoning looked sound and was
not: I read which function `rootNSQuery` calls and inferred what it does,
without reading the function. The forward routing was two levels below where I
stopped.

One genuine leftover: the comment at `v2/imr_root_refresh.go:51` says
`RefreshRoot` refreshes "AGAINST THE LIVE ROOTS, not from the hints file". With
a forward zone for `.` that is not what happens - it refreshes via the
forwarder. The behaviour is right; the comment now misleads, and it misled me.
Worth a one-line correction while someone is in the file.

## Soak result, 2026-09-05: clean under sustained load

The one gap I named last night was that the negative was uncontrolled AND
unloaded - golf had only my occasional digs, while the original report described
"many queries answered, including through its DoT/DoH/DoQ listeners". That gap
is now closed on the load side.

Soak on `pri.golf` against the forward-only `imr.golf`, roots blocked by NPF:

| | |
|---|---|
| Duration | 8h 38m (lab time 22:18:08 -> 06:56:08) |
| Rounds | 14 800 |
| Queries | ~74 000, of which ~29 600 were unique names forcing real resolution |
| Per round | 2 unique names, plus `dnslab SOA`, `. NS`, `golf.dnslab NS` |
| Root NS refreshes | 49, still on schedule at 06:50 (next expiry 07:05) |
| Root TTL cycles survived | ~34 |
| **Failures** | **0** |

`. NS` and `dnslab SOA` were queried every round - those are precisely the two
that failed in the original report - and neither ever returned anything but
NOERROR.

Four lines in the IMR log match "failed"; none is this issue:

- one pre-forward priming failure from before the `forward:` block existed
  (the NPF-blocked hints prime, expected)
- one QUIC receive-buffer INFO, cosmetic
- two `forward zone: all upstreams failed` for `<zone> DS`, where the cause is
  recorded in the line itself: `upstream 172.16.0.7:53/do53 answered SERVFAIL`.
  The upstream's verdict, propagated correctly. Once each, resolver unaffected

So: 8.5 hours under continuous load, ~3.5x the original failure timescale, with
the root delegation expiring and being re-primed 34 times, and no reproduction.

**Side observation, not #443:** the lab resolver at 172.16.0.7 answers SERVFAIL
for `DS` queries of lab zones. That is consistent with yesterday's finding that
it sets AD on nothing, and is worth its own look - a resolver that SERVFAILs DS
queries will break any student exercise that chases a chain by hand.

## POSITIVE CONTROL: reproduced on demand, 2026-09-05

Control build: current main (d833c683) with the root re-primer disabled at its
call site (`go imr.RefreshRoot(...)` in `v2/imrengine.go`), so exactly one
variable differs from the build golf is running. Built on godev101, run on
`imr.foxtrot` as a second forward-only IMR on 10.6.0.2:5353, same upstream
(172.16.0.7), same NPF blocking of the roots, alongside the existing daemon
(own port, own config and log under /var/tmp - nothing in /etc touched).

| | Control (re-primer OFF) | Fixed build (golf) |
|---|---|---|
| Daemon start | ~07:17 | 19:24 |
| Soak start | 07:22:35 | 22:18:08 |
| First failure | **07:32:32** | none |
| Elapsed to failure | **~900s = exactly one root NS TTL** | n/a |
| Duration survived | - | 8h 38m, ~34 TTL cycles |
| Failures | 81 and climbing | **0** |

First failure, verbatim:

```
2026-09-05T07:32:32Z round 285: . NS -> status: SERVFAIL
2026-09-05T07:32:38Z round 288: s2210266736-288.foxtrot.dnslab A -> status: SERVFAIL
2026-09-05T07:32:38Z round 288: s2210266736-288.golf.dnslab A -> status: SERVFAIL
2026-09-05T07:32:38Z round 288: . NS -> status: SERVFAIL
2026-09-05T07:32:38Z round 288: foxtrot.dnslab NS -> status: SERVFAIL
```

Note what is NOT in that list: `dnslab SOA`, which kept answering from cache.
That is the original report's signature - "Only the cached name answered, which
is what makes it look like the resolver rather than the network" - reproduced
exactly, and the first casualty is `. NS`, the root delegation itself.

Onset lands on root NS expiry: the control daemon primed at ~07:17, the lab
root NS TTL is 900s, and the first SERVFAIL is at 07:32:32.

**Both halves of the test now hold.** The test detects the bug (control fails
within one TTL) and the current build passes it (34 TTL cycles, zero failures).
That is what was missing last night.

## The hard test case

Johan: "I still need a hard test case that shows the problem before I believe it
is still there." Agreed - and the harder requirement is a **positive control**.
A test that passes against both the fixed and the broken build proves nothing,
and everything above is currently an uncontrolled negative.

**Test: forward-only resolver, sustained past several root NS expiries.**

Setup (the lab already provides it, so this is nearly free):

- tdns-imr, `forward: zone: .` to a reachable upstream
- the resolver's own path to the real root servers blocked
- root NS TTL short enough to cycle quickly - 900s in the lab

Procedure:

1. Start. Query name A - expect NOERROR. Confirm A is now cached.
2. Wait past `2 x root NS TTL` at minimum; longer is better. The original
   report said about an hour.
3. Query name B, never seen before - **expect NOERROR**.
4. Query `. NS` - **expect NOERROR**. This is the discriminator: it is what
   failed in the original report and what a lost root delegation cannot answer.
5. Query name A - expect NOERROR (a cached hit proves the process is alive and
   distinguishes this from a dead listener).

**The positive control, which is the part that matters.** Run the same
procedure against a build with the re-primer disabled - either `b4fa3582`, or
current main with `RefreshRoot` stubbed out. Steps 3 and 4 must FAIL there. If
they do not, the test is not exercising the mechanism and its passing tells us
nothing about the fix.

Automate it as a soak test rather than a unit test: the bug is a function of
cache expiry over wall-clock time, and a unit test that fakes the clock will not
exercise the interaction between the refresher, the cache and the forward path,
which is where the doubt lives.

## Recommendation

1. DONE - both halves. **Close #443** citing the re-primer, and say in the closing comment
   that the forwarder case is covered by the forward routing inside
   `IterativeDNSQuery` - that is the part Johan flagged as unverified, it is now
   understood rather than merely observed, and it is what a future reader will
   want.

   **No code change is proposed for #443.** The re-primer covers both the
   iterative and the forwarding case. The only edit worth making in these files
   is the stale comment noted above.
2. If the control does not fail, the test is wrong before the code is - fix the
   test first.

## Worth keeping from the original draft, independent of all this

Two observability gaps are real regardless of whether #443 is fixed, and both
are cheap:

- **Log upstream state transitions.** `recordSuccess`, `recordFailure` and
  `recordSliceTimeout` already compute `was := up.failing` and know the state
  changed. A single info line at the moment service degrades would have settled
  this issue on the day rather than three weeks later.
- **Expose live forward state over the API.** `queries`, `failures`,
  `sliceTimeouts`, `lastSuccess`, `lastErrMsg`, `lastErrTime`, `failing`,
  `quarantined` all already exist on `ForwardUpstream` and are unreachable from
  outside. Today the only remedy for a stuck resolver is a restart, which
  destroys the evidence. That is why this issue took a month and still needs a
  test to close.

Neither is a fix for #443. Both are why #443 was expensive.
