# The IXFR / journal integration rig

A `tdns-auth` primary and a **real BIND9 secondary**, driven through the
scenarios that a single-process Go test cannot reach: that a journalled change
actually arrives at a secondary, that it arrives *incrementally*, and that a
restart or a reload which reconciles a replaced zone file does not strand that
secondary or move a serial backwards.

This is a snapshot of a rig that was built by hand while working on the delta
journal (#348), zone-file reconciliation (#353) and the reload path (#362 /
#363). It is committed because its assertions are statements about tdns's
behaviour, and they have twice needed to change in step with that behaviour —
section G was written for #353, section H for #363. A rig that lives only on a
test host cannot be reviewed alongside the change it is evidence for.

## Relative to tdns-debug

It lives here because it shares `tdns-debug`'s purpose — aggressive correctness
testing of a *running* server — and differs only in what it can reach and how it
is written.

`tdns-debug` drives one live server hard and checks every observation against a
ledger of states a correct server could be in. This rig does something the
framework cannot do yet: it **stops and starts the primary**, edits its zone
file behind its back, and watches a **second, independent implementation** decide
whether to follow. Restart, reload and the file-versus-journal reconciliation are
lifecycle properties, and interoperability is a second opinion; neither is
expressible as load against a server that stays up.

It is shell because that is what could stop a daemon, rewrite a file and restart
it in an afternoon, while the bug being chased was live. The scenarios are the
durable part — `test reconcile` and `test lifecycle` families on the `tdns-debug`
engine would be a better home for them, once that engine can provision, restart
and observe a foreign secondary. Until then this runs, and it has caught real
defects.

## What it covers

| | |
|---|---|
| A | baseline: both sides answer and agree |
| B | an API update reaches the secondary **incrementally** (asserted from named's own log, which is the only honest source for IXFR-vs-AXFR) |
| C | `sync` folds the journal into the zone file |
| D | a restart replays the journal and the secondary re-converges |
| E | `freeze` refuses updates, `thaw` restores them |
| F | the `journal: active: false` kill-switch: applied but not durable, and a secondary that does not follow the primary backwards |
| G | reconciliation across a **restart**: an edited file does not cost the journal; db-wins; the `.rejected` artefact; the serial floor |
| G2–G3 | the artefact replays back; an unedited file does not merge twice |
| G4–G5 | reload takes the same path as startup; `on-conflict-zonefile-wins` reverses the outcome |
| H1–H8 | reconciliation across a **reload**: an edit with no serial bump; a file whose serial jumped ahead; no-op reloads; reordering is not a change; a dirty zone may still reload; the zone file is not rewritten; conflicts and artefacts; a plain replay afterwards |

## Running it

The rig needs a working directory. **It currently assumes `/var/tmp/ixfrtest`**
— `R=` at the top of the script, and absolute paths inside `named/named.conf`
and `tdns-auth.yaml`. Making it relocatable is deliberately left as a follow-up;
what is committed here is what has been run, not a tidied version of it.

```sh
mkdir -p /var/tmp/ixfrtest/{named,zones,log}
cd cmdv2/debug/rig
cp tdns-auth.yaml tdns-cli.yaml /var/tmp/ixfrtest/
cp named/named.conf /var/tmp/ixfrtest/named/
cp zones/rig.example /var/tmp/ixfrtest/zones/
cp run-ixfr-tests.sh reseed.sh /var/tmp/ixfrtest/

SRC=/path/to/a/built/tdns/worktree /var/tmp/ixfrtest/run-ixfr-tests.sh
```

`SRC` must name a worktree whose `cmdv2/auth` and `cmdv2/cli` have been built
with `make` — the rig runs those binaries, not anything on `$PATH`. It also
expects `dig` and `named` from pkgsrc (`/usr/pkg/{bin,sbin}`) and the API
certificate named in `tdns-auth.yaml`.

`reseed.sh` puts the working directory back to a clean start: the zone seed
below, no database, no journal, no secondary state. Run it as a **file**, never
inlined into an `ssh` command — a `pkill -f` pattern typed on a command line
matches the shell running it and kills the session.

### A/B against another commit

A green run means nothing on its own; what makes it evidence is that the same
rig **fails** on the tree the change was cut from. `SRC` exists for that:

```sh
git -C /src/git/tdns worktree add --detach /src/git/tdns.ctl <commit>
# copy cmdv2/algs-env.mk and each app's {algs-libs.mk,*_algs.go} across, make,
SRC=/src/git/tdns.ctl /var/tmp/ixfrtest/run-ixfr-tests.sh
```

Section H was written that way: **88/88 on #363, 15 failures on the commit it
was cut from**, including both symptoms from #362 verbatim.

## What is here, and what is not

Committed: the script, the two tdns configs, `named.conf`, the zone seed, and
the reseed helper. About 40 KB of text.

Not committed, and not wanted: the SQLite database, logs, captured AXFRs, the
secondary's zone copy and journal, `.rejected` artefacts, and the zone file as
the rig leaves it — the runs mutate `zones/rig.example` heavily, so the seed
here is a reconstruction of the original skeleton, verified by a full 88/88 run
from a pristine working directory.

The derived configs the script mentions — `tdns-auth-nojournal.yaml`,
`tdns-auth-zfwins.yaml` — are generated by the script at run time from
`tdns-auth.yaml`, so they are not committed either.

## Known rough edges

- `R` is hardcoded, as are the pkgsrc paths for `dig` and `named`.
- Every run appends fresh records to the zone under `$RUN`-suffixed names, so
  the working copy of the zone file grows. `reseed.sh` is how that gets reset.
- The rig assumes it is the only thing using ports 5400 / 8400 / 5401.
