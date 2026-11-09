# Zone files parse from the zone's name; a doubled suffix is refused

| | |
|---|---|
| **Issue** | #1009 |
| **PR** | #1012 |
| **Status** | Implemented; external review Merge at `e83cfeac`, changes below |

## The problem

The zone parser started with an empty origin. A zone file written the
ordinary way, with `@` and names relative to the zone, did not load. A
relative NS target missing its trailing dot was refused only as a side
effect. Parse errors quoted the line from the main file even when the error
was in an `$INCLUDE`d one.

## The decisions

- **The origin starts at the zone's name,** as in BIND, NSD and Knot. An
  `$INCLUDE` without an origin of its own inherits the one in effect. A fully
  relative file loads as whichever zone it is configured for.
- **A doubled suffix is refused on purpose.** A name that ends in the same
  label sequence twice, where that sequence is the zone's name or a name under
  it, is almost always a name written out in full whose trailing dot is
  missing: `ns1.sub.example.test.example.test.`. The check covers the owner and
  every domain-name field in the RDATA, found by the `domain-name` and
  `cdomain-name` struct tags. A name that only contains the zone's name, such
  as a CDN target, is not refused. The root zone is exempt.
- **The opt-out is `allow-doubled-suffix`,** a zone option, off by default.
  The check runs on parsed names, where a name written with its trailing dot
  and one completed by the origin look the same, so in zone `test.` a
  deliberate `test.test.` is refused too. A zone that means such names sets
  the option (Johan, 2026-11-08: the opt-out, since it is cheap).
- **`tdns-cli config check` applies the same rule and the same option,**
  template included, so it never passes a file the server refuses.
- **A parse error quotes the line from the file the parser named,** taken from
  the parser's error text. No change to the `johanix/dns` fork.

## Changes from review (2026-11-09)

- **Labels fold A-Z only.** `doubledZoneSuffix` compared labels with
  `strings.EqualFold`, which folds Unicode. It read a label holding U+017F
  (long s) as one holding `s`, and refused a name that is not a doubled
  suffix under DNS rules. It now uses `core.EqualNames`, which folds A-Z
  only, as DNS does.
- **The option is tested through `checkZones`,** set on the zone, set on its
  template, and absent. The earlier test passed the boolean straight to the
  parser.
- **Declined, and accepted by the project owner on 2026-11-09:** restricting
  which files `$INCLUDE` may name. A zone file is operator-written
  configuration, as trusted as the config that names it, and BIND and NSD put
  no limit on `$INCLUDE` either.
- **One refusal lists every doubled name** (Johan, 2026-11-09: "can we say
  anything about exactly which record is failing?"). The loader collects
  them through the whole parse and refuses once, listing up to 20 and saying
  how many more. The parser can't say which file or line a record came from,
  so each entry quotes the record and the name as it most likely appears in
  the file: written out in full, without its trailing dot (`look for
  "ns1.customer.mp.axfr.net" without a trailing dot`). A plain search of the
  zone file and its includes finds it. `config check` lists them the same
  way.
