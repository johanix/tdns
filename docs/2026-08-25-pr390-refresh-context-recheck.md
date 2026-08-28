# Recheck: #390 refresh-context threading

**Date:** 2026-08-25 (third pass)
**Update:** `f76c5d3b` closes the godoc nit below, and also restores
`FetchFromUpstream`'s godoc (orphaned onto `shouldDiscardUnchangedTransfer`
in the opening commit). All findings from this series are closed.
**Prior:** [`2026-08-25-pr390-refresh-context-rereview.md`](2026-08-25-pr390-refresh-context-rereview.md) (against `710ba934`)
**PR:** [#390](https://github.com/johanix/tdns/pull/390)
**Branch:** `feature/refresh-context-threading` @ `f76c5d3b`
**Lens:** the three leftovers from the second pass, plus anything the
fix commit introduced.

New commit: `180a91c8` — close the three leftovers.

---

## Verdict

**Approve.** The three leftovers are closed, and the behaviour matches the
comments. The godoc nit from this pass is closed in `f76c5d3b`
(`noteRefreshFailure` / `initialLoadZone` split; `ZoneTransferIn` still
correct; `FetchFromUpstream` godoc restored from
`shouldDiscardUnchangedTransfer`).

| Leftover from second pass | Now |
|---------------------------|-----|
| `FetchFromFile` first post-parse gate does not `forgetZoneFileStat` | **Closed.** Both gates forget. |
| `dialTransferConn` uses `Dial` / `tls.DialWithDialer` | **Closed.** `DialContext` and `tls.Dialer`. Comment matches. |
| `RefreshError` skip only on the `RefreshZoneCh` goroutine | **Closed.** `noteRefreshFailure` at all five refresh-failure sites. `GetSOA` left alone on purpose (no `ctx`). Pinned by `TestNoteRefreshFailureIgnoresCancellation` (bare and wrapped `Canceled`). |

---

## The godoc nit — closed in `f76c5d3b`

`noteRefreshFailure` had been inserted under `initialLoadZone`'s godoc.
The follow-up audited every function this PR adds or moves and restored
three orphans:

- `initialLoadZone` / `noteRefreshFailure` (reported)
- `ZoneTransferIn` / `drainTransferEnvelopes` (already fixed; still correct)
- `FetchFromUpstream` / `shouldDiscardUnchangedTransfer` (found by the audit)

Verified at `f76c5d3b`: each comment sits on the function it names.

The unused `bool` return is fine: the test uses it, and the `zr.Wait`
path correctly still delivers an error on cancel (otherwise a waiter
would hang at shutdown).

---

## Confirmed closed

- Both `FetchFromFile` cancel-after-parse gates call `forgetZoneFileStat`
  before restoring `prevStatus`.
- `dialTransferConn` derives `ctx` from the caller, uses it for
  `pickTransferSrc`, then `d.DialContext` / `tls.Dialer.DialContext`. An
  IP-literal upstream no longer ignores cancel during the 2s connect.
- Five `noteRefreshFailure` sites: two `initialLoadZone` callers, the
  `RefreshZoneCh` goroutine, the ticker `Refresh`, the initial-load
  retry. Cancellation is logged, not stored as `RefreshError`.
