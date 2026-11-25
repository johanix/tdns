# tests/appowner: an application client that exercises API ownership

`appowner` uses tdns-auth's management API the way an application client
does, a provisioning daemon for example: over TCP, with its own client
certificate, the daemon verified by its pin, through the tdns v2 client
library (`tdns.NewClientWithOptions`). It checks the API ownership model of
`docs/2026-11-23-tdns-api-ownership-design.md`: what an application should
be able to do works, what it should not is refused, and a refusal leaves the
state as it was.

```
tests/appowner/run.sh [TDNS_AUTH [TDNS_NCLI]]
```

The binaries default to what `make` builds in `cmdv2/auth` and `cmdv2/ncli`
of this tree. `run.sh` needs `make` and Go (it builds `appowner` into its
temporary directory). Runs on macOS and on a test host alike.

## What run.sh sets up

Everything lives in one `mktemp -d` directory, and the daemon listens on
ports the kernel hands out on 127.0.0.1. Nothing is left running. A passing
run removes the directory (`APPOWNER_KEEP=1` keeps it); a failing run keeps
it and says where, with `log/transcript.log` (every request and reply) and
`log/tdns-auth.log`.

- A tdns-auth config with its own DNS port, TCP API port (TLS, a certificate
  made with `tdns-ncli cert`), local admin socket, access file and
  `apiserver.app-clients: [ app1, app2 ]`. Dynamic zones may be secondaries
  or primaries (template `app-primary`).
- Static zones: `s1.test.` (granted with `api-owner: cert:app1`), `s2.test.`
  (no grant), `signed.test.` (no grant, signed here), catalog zones
  `cat1.test.` (granted to app1) and `cat2.test.` (no grant).
- Three certificate clients, all read-write: app1 and app2 (application
  clients) and op (an operator). Each pair is made with
  `tdns-ncli client init --name N --cert F --key F` and enrolled with
  `tdns-ncli auth client add N --cert F --role read-write`, as in section 5
  of the design. The daemon starts with the access file named but absent,
  and the first `client add` creates it and reloads.

The operator's steps (`zone setowner`, deletes with `--keep-keys`, re-adds,
`client keyauth off`, `config check`) go through tdns-ncli on the local
socket. The checks read state through the socket too (the audit view), so
that every refusal is checked against what the daemon holds afterwards.

## Output

One line per check: `PASS` or `FAIL`, the check's number and name, a short
reason. A FAIL adds the daemon's own words, indented. `NOTE` lines record
what the daemon did in a case the design does not decide (questions below);
they are not counted. Then a summary. Exit status 0 when every check
passed, 1 on any FAIL, 2 when the rig could not be set up.

## The checks

| group | what | design | API (route, command) |
|---|---|---|---|
| S | who is who; op's, the operator's and app2's zones and keys | 4.1 | `/ping`; `/zone add`; tdns-ncli `zone add` |
| 1 | app1 adds a secondary with an inline TSIG key: zone and key are `cert:app1` | 4.3, 4.4 | `/zone add` (`TsigName`, `TsigSecret`) |
| 2 | app1 sees its own zones only; reads of other zones refused; list-algorithms and list-policies open | 4.5, 4.6 | `/zone list-zones`, `list-dynamic`, `get-name`, `show-nsec-chain`; `GET /rollover/status`; `/keystore list-algorithms`, `list-policies` |
| 3 | writes: own zone yes; RR outside the zone, static delete, other owners' zones no; however the name is spelt | 4.3, 4.5, R1 | `/zone modify`, `update`, `delete`, `bump`, `add`; `/delegation`; `/rollover/asap` |
| 4 | catalog: adding a member needs member and catalog zone both own | 4.5 | `/catalog zone-add`, `zone-list`, `create`, `delete`, `group-add`, `zone-group-add` |
| 5 | whole-server commands refused | 4.5 | `/config reload`, `/scanner/poll on`, `/imr imr-flush` |
| 6 | TSIG keys: own only, no secret in lists, conflicts refused, identical key a no-op, in-use and foreign deletes refused, new keys always the caller's; another owner's key refused inline on zone add and modify, even identical | 4.4, 4.6, 4.7, ruling Q4 | `/keystore tsig-mgmt list`, `add`, `delete`, `export`, `setowner`, `purge`, `generate`, `import`, `bulk-import`; `/zone add`, `modify` (`TsigName`) |
| 7 | DNSSEC and SIG(0): own zone yes (private key export included), others no; bulk-export filtered; clear, policy-cleanup, check, truststore refused; exports logged | 4.4, 4.6, decision 3, R1, R9 | `/keystore dnssec-mgmt` and `sig0-mgmt` `generate`, `export`, `bulk-export`, `setstate`, `clear`, `policy-cleanup`, `check`; `/truststore` |
| 8 | zone delete takes the keys; `--keep-keys` refused to apps; kept keys block an app's re-add, not the operator's | 4.10, decisions 4, 7 | `/zone delete` (`KeepKeys`); tdns-ncli `zone delete --keep-keys`, `zone add`, `zone setowner` |
| 9 | app2 sees nothing of app1's; `zone setowner` hands Z1 over; the catalog zone's owner removes the member it no longer owns | 4.5, 4.8, ruling Q3 | `/zone`, `/keystore`, `/catalog zone-group-delete`, `zone-delete`, `zone-add`; tdns-ncli `zone setowner` |
| 10 | op stays unscoped, the keystore still admin-only | 4.8 | `/zone`, `/keystore`, `/config status` |
| 11 | the API key: unscoped, and `config check` warns while keyauth is on | 4.9, R5 | X-API-Key; tdns-ncli `config check`, `client keyauth off` |

## Findings at the first run (2026-11-24, branch head 030dfe5a of api-owner-c)

- **3.16, design 4.5:** `delegation export` of an application's own zone is
  refused ("not available to application clients"); the design lists it as
  own zone only. The code refuses it on purpose: export writes a file at a
  path the caller names, on the server (`apiAppScopes` in `v2/api_app.go`).
  The design or the code should change.
- **7.21, design 4.5 and R1:** `dnssec-mgmt setstate` is checked on
  `Keyname`, but after the commit `APIkeystore` republishes and re-signs the
  zone in `Zone`. app1, changing its own key and naming `signed.test.` in
  `Zone`, makes the daemon re-sign `signed.test.`. `add` republishes `Zone`
  the same way, checked on the key's owner name.
- **8.12, design 4.10:** a dynamic primary deleted right after its add,
  while it still loads, is reported deleted but comes back: in list-zones and
  list-dynamic, answering SERVFAIL, and written to the dynamic config at the
  next rewrite. Its keys are gone, its API owner kept. Not specific to
  application clients. `setErrorLocked` and `clearErrorLocked`
  (`v2/enums.go`) put the zone back in `Zones` unconditionally, where
  `SetStatus` checks that it is still the live entry.

Since then (2026-11-24, api-owner-c f27b4075): 7.21 is fixed by bf69f00b (an
application's key command acts only on a `Zone` it owns) and 8.12 by
8a136d9b (an error-state change no longer re-registers a deleted zone). With
the rulings below (api-owner-c 67cbfccb) the run has 146 checks, 145 PASS
and one FAIL, 3.16, which waits for a ruling.

## Rulings (Johan, 2026-11-24)

- **Q3, "catalog owner may remove any member":** an application that owns a
  catalog zone may remove any member (`zone-delete`, `zone-group-delete`)
  without owning it; the member zone stays. Adding still needs both. Checks
  9.11 to 9.14 (and 4.9, 4.10, which give Z1 a group first).
- **Q4, "refuse an inline tsig key that someone else owns":** an
  application's `zone add` or `modify` whose inline key exists under another
  API owner is refused, even when identical; its own identical key is fine.
  Checks 6.20 to 6.26.
- **Q2:** nested zones with another owner are allowed. NOTE Q2 stays while
  the case below is open.

## Open questions

- **Q1:** design 4.6 gives application clients `list-dnskey` (own keys),
  section 2 keeps the truststore admin. In the code `list-dnskey` is a
  truststore command (the DNSKEY cache of other zones) and is refused. The
  suite expects the refusal (7.18). Which is meant?
- **Q2, what is left of it:** should a nested zone that the parent does not
  delegate (no NS at the cut, as `sub.s2.test.` inside `s2.test.` here) be
  refused? It answers for those names instead of the operator's records
  (NOTE Q2).
- **3.16:** delegation export, above.
