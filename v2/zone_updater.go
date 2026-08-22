/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

type UpdateRequest struct {
	Cmd            string
	UpdateType     string // "DSYNC", "KEY", ...
	ZoneName       string
	Adds           []dns.RR
	Removes        []dns.RR
	Actions        []dns.RR // The Update section from the dns.Msg
	Validated      bool     // Signature over update msg is validated
	Trusted        bool     // Content of update is trusted (via validation or policy)
	InternalUpdate bool     // Internal update, not a DNS UPDATE from the outside
	// PreAuthorized marks a request whose authorization was already settled by
	// the management API handler (the X-API-Key is the credential) and which
	// therefore bypasses update-policy, exactly as InternalUpdate does. It is
	// set in ONE place -- the API zone-update handler, after that handler has
	// checked allow-api-updates -- and nowhere else. Nothing on the DNS
	// UPDATE path may ever set it: a wire request that arrived with this flag
	// would be an unauthenticated update.
	//
	// Deliberately a third boolean rather than folding wire/internal/api into
	// one Origin enum. The enum is the better model and worth doing, but it
	// touches every InternalUpdate site in the tree and that is a separate
	// change from adding a channel.
	PreAuthorized bool
	// Replay marks the re-application of already-persisted deltas over a
	// freshly loaded zone file. It suppresses persistence for that apply:
	// these changes are already in the ZoneDelta table, and recording them
	// again would double the stored history on every restart.
	Replay bool
	// Resp, when non-nil, receives the outcome once the update has been
	// applied, persisted and published -- or once it has been refused. It
	// exists so a caller can answer its own client only after the change is
	// durable, which is what RFC 2136 means by a NOERROR response: a promise
	// the server has already kept, not one it intends to.
	//
	// Buffered by the sender and written with a non-blocking send, so the
	// updater is never held up by a caller that has given up waiting, and a
	// double send (belt-and-braces responses on several exit paths) is
	// harmless.
	Resp         chan ZoneUpdateResult
	Status       *UpdateStatus
	Description  string
	PreCondition func() bool
	Action       func() error
}

// ZoneUpdateResult is the outcome of one update, delivered on UpdateRequest.Resp.
// Applied is false both for a refused update and for one that changed nothing.
type ZoneUpdateResult struct {
	Applied bool
	Err     error
}

// respond delivers the outcome to a waiting caller, if there is one.
//
// Non-blocking: a caller that timed out and walked away must never wedge the
// single ZoneUpdater goroutine, which serves every zone. Safe to call more than
// once for the same request, so exit paths can each report without having to
// reason about which one got there first.
func (ur *UpdateRequest) respond(applied bool, err error) {
	if ur.Resp == nil {
		return
	}
	select {
	case ur.Resp <- ZoneUpdateResult{Applied: applied, Err: err}:
	default:
	}
}

// apexRetainedOnDelname reports whether an rrtype survives a DELNAME aimed at
// the zone apex.
//
// RFC 2136 §3.4.2.3 requires only SOA and NS to be retained. The rest are kept
// because DELNAME is a WHOLESALE statement -- "delete everything at this name"
// -- and nobody issuing it at the apex means "and also dismantle DNSSEC and
// stop every rollover signal mid-flight". Deleting the apex DNSKEY RRset on a
// zone whose DS is published at the parent does not make the zone insecure, it
// makes it BOGUS: resolvers stop answering for the whole zone. There is no
// legitimate use of DELNAME that wants that, and an operator who genuinely
// means it can still say "delrrset --type DNSKEY", which is unambiguous.
//
// This is a deliberate deviation from a strict reading of §3.4.2.3, in the
// conservative direction: it deletes less than the RFC permits, never more.
func apexRetainedOnDelname(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeSOA, dns.TypeNS: // RFC 2136 §3.4.2.3
		return true
	case dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeCSYNC:
		return true // DNSSEC and delegation-maintenance signalling
	}
	return false
}

// updaterCmdMutatesZoneContent reports whether a ZoneUpdater command writes
// ZONE CONTENT (as opposed to some side store), and is therefore subject to the
// origination gate at the head of the updater loop.
//
// Only these two write the zone. TRUSTSTORE-UPDATE writes the keystore via
// TruststorePost and must pass through untouched even on a zone that may not
// originate — gating it would break SIG(0) key management on secondaries.
// DEFERRED-UPDATE is rejected by the loop as a wrong-queue error, and PING is
// handled before the zone is even resolved.
func updaterCmdMutatesZoneContent(cmd string) bool {
	return cmd == "ZONE-UPDATE" || cmd == "CHILD-UPDATE"
}

func SprintUpdates(actions []dns.RR) string {
	var buf string
	for _, rr := range actions {
		switch rr.Header().Class {
		case dns.ClassNONE:
			buf += fmt.Sprintf("DELETE:       %s\n", rr.String())
		case dns.ClassANY:
			buf += fmt.Sprintf("DELETE RRset: %s\n", rr.String())
		case dns.ClassINET:
			buf += fmt.Sprintf("ADD:   %s\n", rr.String())
		default:
			buf += fmt.Sprintf("UNKNOWN CLASS %s\n", rr.String())
		}
	}
	return buf
}

// logUpdateActions logs each RR in an update at Info level with
// ADDED/DELETED prefix based on the RR class.
func logUpdateActions(updateType string, actions []dns.RR) {
	for _, rr := range actions {
		rrcopy := dns.Copy(rr)
		rrcopy.Header().Class = dns.ClassINET
		switch rr.Header().Class {
		case dns.ClassINET:
			lg.Info(fmt.Sprintf("%s ADDED: %s", updateType, rrcopy.String()))
		case dns.ClassNONE:
			lg.Info(fmt.Sprintf("%s DELETED: %s", updateType, rrcopy.String()))
		case dns.ClassANY:
			lg.Info(fmt.Sprintf("%s DELETED[rrset]: %s %s", updateType,
				rr.Header().Name, dns.TypeToString[rr.Header().Rrtype]))
		}
	}
}

func (kdb *KeyDB) ZoneUpdaterEngine(ctx context.Context) error {
	updateq := kdb.UpdateQ

	lg.Info("ZoneUpdater starting")
	for {
		select {
		case <-ctx.Done():
			lg.Info("ZoneUpdater: context cancelled")
			lg.Info("ZoneUpdater: terminating")
			return nil
		case ur, ok := <-updateq:
			if !ok {
				lg.Info("ZoneUpdater: updateq closed")
				lg.Info("ZoneUpdater: terminating")
				return nil
			}
			lg.Debug("ZoneUpdater received update request")
			if ur.Cmd == "PING" {
				lg.Debug("ZoneUpdater: PING received, PONG!")
				continue
			}
			zd, ok := Zones.Get(ur.ZoneName)
			if !ok {
				lg.Warn("ZoneUpdater: unknown zone in update request, ignoring", "cmd", ur.Cmd, "zone", ur.ZoneName)
				lg.Debug("ZoneUpdater: known zones", "zones", Zones.Keys())
				ur.respond(false, fmt.Errorf("unknown zone %s", ur.ZoneName))
				continue
			}

			// Fail-closed origination gate (Fix D). The per-command checks
			// below gate ZONE-UPDATE on allow-updates OR ur.InternalUpdate --
			// and EVERY ops_* publisher sets InternalUpdate, so allow-updates
			// is a call-site convention rather than an applier gate. Any
			// publisher that does not check the option at its own call site
			// therefore walks straight through and mutates the zone.
			//
			// This is the chokepoint that makes the invariant structural
			// rather than a promise kept by N call sites: a tdns-auth zone
			// that may not originate content never has zone content applied,
			// whatever flags the request carries.
			//
			// Scoped to the two zone-content commands. TRUSTSTORE-UPDATE must
			// pass through untouched -- it writes the keystore, never zone
			// content. DEFERRED-UPDATE errors out below; PING returned above.
			//
			// Logged at ERROR as an invariant violation, matching the existing
			// precedent for the child-updates case a few lines down: once the
			// origination options are normalized off, nothing should ever
			// reach this gate, so a hit means some path bypassed the option
			// system -- a code bug worth shouting about. Deliberately not
			// recorded in the zone's error registry, so it cannot collide with
			// the operator-facing config warning.
			if updaterCmdMutatesZoneContent(ur.Cmd) && !zoneMayOriginateContent(zd) {
				lg.Error("ZoneUpdater: refusing zone mutation on a secondary that may not originate content (invariant violation)",
					"cmd", ur.Cmd, "zone", ur.ZoneName, "internal", ur.InternalUpdate,
					"description", ur.Description, "actions", len(ur.Actions))
				ur.respond(false, fmt.Errorf(
					"zone %s may not originate content", ur.ZoneName))
				continue
			}

			switch ur.Cmd {
			case "DEFERRED-UPDATE":
				lg.Error("ZoneUpdater: received deferred update on wrong queue", "description", ur.Description)
				continue

			case "CHILD-UPDATE":
				// Child delegation data update: dispatch to the configured DelegationBackend.
				// Config validation guarantees that any zone with
				// OptAllowChildUpdates has a non-nil DelegationBackend, so
				// there is no fallback path. If the invariant is violated
				// (which would indicate a code bug, not a config bug),
				// drop the update loudly rather than silently mutating
				// in-memory zone state behind the scanner's back.
				lg.Debug("ZoneUpdater: CHILD-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: CHILD-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				// Snapshot the two fields parseconfig.go mutates under
				// zd.mu during config reload (Options + DelegationBackend).
				// Reading them independently without the lock would let a
				// concurrent reload flip one between checks, producing a
				// spurious "invariant violation" ERROR.
				zd.mu.Lock()
				allowChildUpdates := zd.Options[OptAllowChildUpdates]
				backend := zd.DelegationBackend
				zd.mu.Unlock()

				if !allowChildUpdates {
					lg.Warn("ZoneUpdater: zone does not allow child updates, dropping CHILD-UPDATE", "zone", ur.ZoneName)
					continue
				}
				if backend == nil {
					lg.Error("ZoneUpdater: zone allows child updates but has no DelegationBackend, dropping CHILD-UPDATE (invariant violation)", "zone", ur.ZoneName)
					continue
				}
				if err := backend.ApplyChildUpdate(ur.ZoneName, ur); err != nil {
					lg.Error("ZoneUpdater: DelegationBackend.ApplyChildUpdate failed",
						"backend", backend.Name(), "error", err)
				} else {
					lg.Info("ZoneUpdater: CHILD-UPDATE applied",
						"zone", ur.ZoneName, "backend", backend.Name())
					// OptDirty is managed by the backend: 'direct' sets
					// then clears it via WriteZone after persisting; DB-
					// and zonefile-backends don't touch in-memory zone
					// data so OptDirty stays as it was.
					logUpdateActions("CHILD-UPDATE", ur.Actions)
				}

			case "ZONE-UPDATE":
				// This is the case where a DNS UPDATE contains updates to authoritative data in the zone
				// (i.e. not child delegation information).
				lg.Info("ZoneUpdater: ZONE-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: ZONE-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				// Admission: the DDNS channel is gated by allow-updates, the
				// management-API channel by allow-api-updates (checked again
				// in the handler, which is where PreAuthorized is set -- this
				// is the backstop, not the only gate), and internal content
				// changes bypass both.
				//
				// Snapshot both options together under zd.mu: config reload
				// mutates the map under that lock, so an unlocked read is a
				// data race and two independent reads could straddle a reload.
				// Same treatment the CHILD-UPDATE case above gives its options.
				zd.mu.Lock()
				allowUpdates := zd.Options[OptAllowUpdates]
				allowApiUpdates := zd.Options[OptAllowApiUpdates]
				zd.mu.Unlock()

				if allowUpdates || ur.InternalUpdate ||
					(ur.PreAuthorized && allowApiUpdates) {
					// Compute delegation sync status before apply (needs pre-state),
					// but only enqueue after successful apply.
					var dss DelegationSyncStatus
					if !ur.InternalUpdate {
						var err error
						dss, err = zd.ZoneUpdateChangesDelegationDataNG(ur)
						if err != nil {
							lg.Error("ZoneUpdateChangesDelegationData failed", "error", err)
						}
						lg.Debug("ZoneUpdater: delegation sync status", "inSync", dss.InSync)
					}

					var updated bool
					var err error

					switch zd.ZoneType {
					case Primary:
						updated, err = zd.ApplyZoneUpdateToZoneData(ur, kdb)
						if err != nil {
							lg.Error("ZoneUpdater: ApplyZoneUpdateToZoneData failed", "error", err)
						}

					case Secondary:
						err := kdb.ApplyZoneUpdateToDB(ur)
						if err != nil {
							lg.Error("ZoneUpdater: ApplyZoneUpdateToDB failed", "error", err)
						} else {
							updated = true
						}
					}
					// The change is now durable AND visible, or it failed. This is
					// the earliest point at which a caller may honestly answer
					// its own client, so release any waiter here rather than at
					// the end of the case: the remaining work below (zonefile
					// write-back for API-managed primaries, delegation sync) is
					// follow-up, not part of the promise.
					ur.respond(updated, err)

					if updated && !ur.InternalUpdate {
						lg.Debug("ZoneUpdater: zone updated, setting dirty flag", "zone", zd.ZoneName)
						zd.SetOption(OptDirty, true)
						logUpdateActions("ZONE-UPDATE", ur.Actions)
					}

					// API-managed primaries persist updated content
					// immediately (the mirror of the CHILD-UPDATE 'direct'
					// backend persist): without this, updated content lives
					// only in RAM until a freeze/manual write and is lost on
					// restart. Internal updates (CSYNC/KEY publication etc.)
					// are included — they change zone data too but never set
					// OptDirty, so they need force. WriteZone clears OptDirty
					// on success, which also un-blocks the dirty-primary
					// reload refusal. The persistence decision reads a
					// zd.mu-protected snapshot (RefreshEngine mutates these
					// fields under that lock on reload); the lock is NOT held
					// across WriteZone, which reacquires it.
					if updated {
						zd.mu.Lock()
						apiPrimary := zd.ZoneType == Primary && zd.Options[OptApiManagedZone]
						zonefile := zd.Zonefile
						zd.mu.Unlock()
						if apiPrimary && zonefile != "" {
							if _, werr := zd.WriteZone(true, ur.InternalUpdate); werr != nil {
								// The client response is long gone (async queue),
								// so surface the persistence failure durably:
								// visible in zone list, deliberately NOT
								// service-impacting (memory state is good).
								lg.Warn("ZoneUpdater: failed to persist API-managed primary after ZONE-UPDATE (updated content is in memory only until the next successful write)", "zone", zd.ZoneName, "file", zonefile, "error", werr)
								zd.SetError(RefreshError, "failed to persist zone after update: %v", werr)
								zd.LatestError = time.Now()
							} else {
								// A successful persist is the primary-zone
								// analogue of a successful refresh (both are
								// file I/O): clear RefreshError, same as the
								// refresh paths do.
								zd.ClearError(RefreshError)
								lg.Debug("ZoneUpdater: persisted API-managed primary after ZONE-UPDATE", "zone", zd.ZoneName, "file", zonefile, "internal", ur.InternalUpdate)
							}
						}
					}

					// Enqueue delegation sync after successful apply
					if updated && !ur.InternalUpdate && zd.Options[OptDelSyncChild] && !dss.InSync {
						lg.Debug("ZoneUpdater: delegation out of sync, sending SYNC-DELEGATION", "zone", zd.ZoneName, "queueLen", len(zd.DelegationSyncQ))
						zd.DelegationSyncQ <- DelegationSyncRequest{
							Command:    "SYNC-DELEGATION",
							ZoneName:   zd.ZoneName,
							ZoneData:   zd,
							SyncStatus: dss,
						}
						if err := zd.PublishCsyncRR(); err != nil {
							lg.Error("ZoneUpdater: error publishing CSYNC", "zone", zd.ZoneName, "err", err)
						} else {
							lg.Debug("ZoneUpdater: published CSYNC proactively", "zone", zd.ZoneName)
						}
					}
				} else {
					lg.Warn("ZoneUpdater: updates disallowed for zone, dropping ZONE-UPDATE", "zone", zd.ZoneName)
					ur.respond(false, fmt.Errorf(
						"zone %s does not allow updates on this channel", zd.ZoneName))
				}
				lg.Debug("ZoneUpdater: ZONE-UPDATE done")

			case "TRUSTSTORE-UPDATE":
				lg.Debug("ZoneUpdater: TRUSTSTORE-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: TRUSTSTORE-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				tx, err := kdb.Begin("UpdaterEngine")
				if err != nil {
					lg.Error("kdb.Begin failed", "error", err)
				}
				type pendingVerification struct {
					childZone string
					keyid     uint16
					keyRR     string
				}
				var toVerify []pendingVerification

				// If this is a self-signed bootstrap ceremony carrying a
				// DEL-ANY-KEY, defer the DEL: register a pending key-replacement
				// so that once the newly-added (untrusted) key is validated and
				// promoted to trusted, the child's other keys are removed. The
				// DEL itself is not applied now (the class-ANY case below skips
				// it), so an un-validated bootstrap never evicts a trusted key.
				// Noted here, REGISTERED after the commit below succeeds. A
				// marker written for a key that then failed to store would
				// outlive the failure and could complete a cleanup for a key
				// this update never actually added.
				ceremonyKey, ceremonyDeferred := (*dns.KEY)(nil), false
				if addKey, hasDel, ok := bootstrapCeremony(ur.Actions); ok && hasDel && !ur.Trusted {
					ceremonyKey, ceremonyDeferred = addKey, true
				}

				for _, rr := range ur.Actions {
					var subcommand string
					switch rr.Header().Class {
					case dns.ClassINET:
						subcommand = "add"
					case dns.ClassNONE:
						subcommand = "delete"
					case dns.ClassANY:
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: class ANY (delete RRset) not supported, ignoring")
						continue
					default:
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: unknown class, ignoring", "rr", rr.String())
						continue
					}

					if keyrr, ok := rr.(*dns.KEY); ok {
						tppost := TruststorePost{
							SubCommand: subcommand,
							Src:        "child-update",
							Keyname:    keyrr.Header().Name,
							Keyid:      int(keyrr.KeyTag()),
							KeyRR:      rr.String(),
							Validated:  ur.Validated,
							Trusted:    ur.Trusted,
						}

						_, err := kdb.Sig0TrustMgmt(tx, tppost)
						if err != nil {
							lg.Error("kdb.Sig0TrustMgmt failed", "error", err)
						}

						// Queue untrusted child-update adds for async verification.
						if subcommand == "add" && !ur.Trusted {
							toVerify = append(toVerify, pendingVerification{
								childZone: keyrr.Header().Name,
								keyid:     uint16(keyrr.KeyTag()),
								keyRR:     rr.String(),
							})
						}
					} else {
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: not a KEY RR", "rr", rr.String())
					}
				}
				err = tx.Commit()
				if err != nil {
					lg.Error("tx.Commit failed", "error", err)
				}
				logUpdateActions("TRUSTSTORE-UPDATE", ur.Actions)

				// The deferred half of a bootstrap DEL-ANY-KEY: the new key is
				// stored, so once it is validated and promoted to trusted the
				// child's superseded keys may be removed. Registered only now,
				// because the key had to actually land first.
				if ceremonyDeferred && err == nil {
					registerPendingKeyReplacement(ceremonyKey.Header().Name, ceremonyKey.KeyTag())
					lg.Info("ZoneUpdater: deferring DEL-ANY-KEY from self-signed bootstrap until new key is trusted",
						"child", ceremonyKey.Header().Name, "keyid", ceremonyKey.KeyTag())
				}

				// Trigger async DNS verification for newly stored untrusted child keys.
				for _, pv := range toVerify {
					lg.Info("ZoneUpdater: triggering child key verification",
						"zone", pv.childZone, "keyid", pv.keyid)
					kdb.TriggerChildKeyVerification(ctx, pv.childZone, pv.keyid, pv.keyRR)
				}
			default:
				lg.Error("ZoneUpdater: unknown command, ignoring", "cmd", ur.Cmd)
			}
			lg.Info("ZoneUpdater: update request completed", "type", ur.Cmd)
		}
	}
}

// 1. Sort actions so that all removes come first.
// 2. To delete an RRset, only owner + rrtype is needed
// 3. To delete an exact RR we need owner, rrtype and the rr.String(). Problem is if
//    the TTL is not correct. Therefore we should always store RRs with TTL=0

func (kdb *KeyDB) ApplyChildUpdateToDB(ur UpdateRequest) error {
	const (
		addkeysql = `
INSERT OR REPLACE INTO ChildSig0Keys (owner, keyid, validated, trusted, keyrr) VALUES (?, ?, ?, ?)`
		adddelsql = `
INSERT OR REPLACE INTO ChildDelegationData (owner, rrtype, rr) VALUES (?, ?, ?)`
		// delkeyrrsql    = `DELETE FROM ChildSig0Keys WHERE owner=? AND keyid=? AND rr=?`
		deldelrrsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=? AND rr=?`
		// delkeyrrsetsql = `DELETE FROM ChildSig0Keys WHERE owner=? AND rrtype=?`
		deldelrrsetsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=?`
	)

	tx, err := kdb.Begin("ApplyChildUpdateToDB")
	if err != nil {
		return err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Commit failed", "error", err1)
			}
		} else {
			lg.Error("ApplyChildUpdateToDB: rolling back", "error", err)
			err1 := tx.Rollback()
			if err1 != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Rollback failed", "error", err1)
			}
		}
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		owner := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 0
		rrcopy.Header().Class = dns.ClassINET

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			lg.Debug("ApplyChildUpdateToDB: Remove RR", "owner", owner, "rrtype", rrtypestr, "rr", rrcopy.String())
			_, err := tx.Exec(deldelrrsql, owner, rrtypestr, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", deldelrrsql, "owner", owner, "error", err)
				return err
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			lg.Debug("ApplyChildUpdateToDB: Remove RRset", "rr", rr.String())
			_, err := tx.Exec(deldelrrsetsql, owner, rrtypestr)
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", deldelrrsetsql, "owner", owner, "rrtype", rrtypestr, "error", err)
				return err
			}
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.

		default:
			lg.Error("ApplyChildUpdateToDB: unknown class", "rr", rr.String())
			continue
		}

		sqlcmd := adddelsql
		if rrtype == dns.TypeKEY {
			sqlcmd = addkeysql
		}

		switch rrtype {
		case dns.TypeKEY:
			key := rr.(*dns.KEY)
			keyid := key.KeyTag()
			lg.Debug("ApplyChildUpdateToDB: Add KEY", "keyid", keyid)
			_, err := tx.Exec(sqlcmd, owner, keyid, ur.Validated, ur.Trusted, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", sqlcmd, "error", err)
				return err
			}
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
			lg.Debug("ApplyChildUpdateToDB: Add RR", "rrtype", rrtypestr, "rr", rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtype, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", sqlcmd, "error", err)
				return err
			}
		default:
			lg.Error("ApplyChildUpdateToDB: unsupported RR type for add", "rrtype", rrtypestr)
		}
	}

	return nil
}

// The return values are NAMED deliberately. The deferred block below sets
// updated=false when the change could not be persisted, and with unnamed
// results that assignment lands on a local the caller never sees: `return
// updated, nil` copies the value into the result slot BEFORE deferred
// functions run. A child update whose persist failed would then be reported as
// applied -- and on the DSYNC API path, answered 200, which is precisely the
// promise this persistence work exists to keep. ApplyZoneUpdateToZoneData has
// named results for the same reason; this one did not, and that asymmetry was
// the bug.
func (zd *ZoneData) ApplyChildUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (updated bool, err error) {

	lg.Debug("ApplyChildUpdateToZoneData", "request", fmt.Sprintf("%+v", ur))

	// If this zone is signed, fetch active keys up front so we can re-sign
	// modified delegation RRsets (notably DS, which is authoritative parent
	// data and MUST carry a fresh RRSIG).
	var dak *DnssecKeys
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		var err error
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil || dak == nil || len(dak.ZSKs) == 0 {
			dak, err = zd.EnsureActiveDnssecKeys(kdb, false)
			if err != nil {
				lg.Error("ApplyChildUpdateToZoneData: failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "error", err)
				return false, err
			}
			if dak == nil || len(dak.ZSKs) == 0 {
				return false, fmt.Errorf("zone %s has no active ZSKs and signing is enabled. child update is rejected", zd.ZoneName)
			}
		}
	}

	zd.mu.Lock()
	defer func() {
		if updated {
			// Phase 2: delegation records written by a CHILD-UPDATE are zone
			// content like any other -- they are staged into the working set
			// and published from here. Without this they would be served but
			// not recorded, and would silently roll back at the next restart
			// while every other kind of change survived.
			zd.wsPersistDelta = !ur.Replay
			zd.publishLocked(zd.generation.Load())
			if zd.wsPersistErr != nil {
				lg.Error("child update not applied: could not persist the change",
					"zone", zd.ZoneName, "error", zd.wsPersistErr)
				zd.wsPersistErr = nil
				updated = false
			}
		}
		zd.mu.Unlock()
	}()
	zd.ensureWorkingSet()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = zd.UpdatePolicy.Child.TTL
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		if _, ok := zd.UpdatePolicy.Child.RRtypes[rrtype]; !ok {
			lg.Error("ApplyChildUpdateToZoneData: RR type denied by policy", "rrtype", rrtypestr)
			continue
		}

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner := zd.stagedOwner(ownerName)
		if owner == nil {
			if class == dns.ClassNONE || class == dns.ClassANY {
				lg.Warn("ApplyChildUpdateToZoneData: unknown owner name", "owner", ownerName)
				continue
			}
			owner = zd.getOrCreateWorkingOwner(ownerName)
			updated = true
		}

		rrset, exists := owner.RRtypes.Get(rrtype)
		if !exists {
			lg.Warn("ApplyChildUpdateToZoneData: no RRset for owner", "owner", ownerName, "rrtype", rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				// If this is a delete then it is ok that the RRset doesn't exist.
				continue
			}
			rrset = core.RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			lg.Debug("ApplyChildUpdateToZoneData: Remove RR", "owner", ownerName, "rrtype", rrtypestr, "rr", rrcopy.String())
			rrset.RemoveRR(rrcopy, Globals.Verbose, Globals.Debug) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				zd.stageDeleteLocked(ownerName, rrtype)
			} else {
				// RFC 4035 §2.2: at a delegation point, only DS is
				// authoritative parent data and gets an RRSIG. NS and
				// glue (A/AAAA) MUST NOT be signed at the parent.
				if dak != nil && rrtype == dns.TypeDS {
					_, err := zd.SignRRset(&rrset, ownerName, dak, true, nil)
					if err != nil {
						lg.Error("ApplyChildUpdateToZoneData: signing failed after RR removal", "rrtype", rrtypestr, "owner", ownerName, "error", err)
					}
				}
				zd.stageRRsetLocked(ownerName, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyChildUpdateToZoneData: Remove RR done", "owner", ownerName, "rrtype", rrtypestr)
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			lg.Debug("ApplyChildUpdateToZoneData: Remove RRset", "rr", rr.String())
			zd.stageDeleteLocked(ownerName, rrtype)
			updated = true
			// zd.Options["dirty"] = true
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.
		default:
			lg.Error("ApplyChildUpdateToZoneData: unknown class", "rr", rr.String())
			continue
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				lg.Debug("ApplyChildUpdateToZoneData: not adding duplicate", "rrtype", rrtypestr, "rr", rrcopy.String())
				dup = true
				break
			}
		}
		if !dup {
			lg.Debug("ApplyChildUpdateToZoneData: adding RR", "rrtype", rrtypestr, "rr", rrcopy.String())
			rrset.RRs = append(rrset.RRs, rrcopy)
			rrset.RRSIGs = []dns.RR{}
			// RFC 4035 §2.2: only DS gets an RRSIG at a delegation
			// point. NS and glue (A/AAAA) MUST NOT be signed at the
			// parent.
			if dak != nil && rrtype == dns.TypeDS {
				_, err := zd.SignRRset(&rrset, ownerName, dak, true, nil)
				if err != nil {
					lg.Error("ApplyChildUpdateToZoneData: signing failed after RR add", "rrtype", rrtypestr, "owner", ownerName, "error", err)
				}
			}
			zd.stageRRsetLocked(ownerName, rrset)
			updated = true
			zd.Options[OptDirty] = true
		}
		continue
	}

	lg.Debug("ApplyChildUpdateToZoneData done", "updated", updated)

	return updated, nil
}

// ApplyZoneUpdateToZoneData applies one update's actions to the zone.
//
// The returns are named because the deferred publish below can fail: a change
// whose delta cannot be persisted is refused rather than served (see
// publishWorkingSetLocked), and that has to surface as an error here rather
// than as a successful-looking (true, nil).
func (zd *ZoneData) ApplyZoneUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (updated bool, err error) {

	// dump.P(ur)
	// log.Printf("**** ApplyZoneUpdateToZoneData: ur=%+v", ur)

	var dak *DnssecKeys
	dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	// Resolve keys (generating if needed) BEFORE taking zd.mu below — including
	// the (nil,nil) "no error, no keys" case. Otherwise SignRRset is later called
	// under zd.mu with a nil dak, reaches PublishDnskeyRRs, and self-deadlocks
	// re-locking zd.mu.
	if (zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]) && (err != nil || dak == nil || len(dak.KSKs) == 0) {
		lg.Debug("ApplyZoneUpdateToZoneData: GetDnssecKeys failed, attempting to ensure keys exist", "zone", zd.ZoneName)
		// Try to ensure active keys exist (will generate if needed)
		dak, err = zd.EnsureActiveDnssecKeys(kdb, false)
		if err != nil {
			lg.Error("ApplyZoneUpdateToZoneData: failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "error", err)
			return false, err
		}
		if dak == nil || len(dak.KSKs) == 0 {
			lg.Error("ApplyZoneUpdateToZoneData: still no active KSKs after EnsureActiveDnssecKeys", "zone", zd.ZoneName)
			return false, fmt.Errorf("zone %s has no active KSKs and online-signing is enabled. zone update is rejected", zd.ZoneName)
		}
	}

	zd.mu.Lock()
	defer func() {
		if updated {
			// Phase 2: the publish writes the delta durably BEFORE making the
			// change visible, and refuses the publish if that write fails --
			// see publishWorkingSetLocked. Report such a failure as an error:
			// nothing was published, so returning success would claim a change
			// the zone is not serving and will not remember.
			zd.wsPersistDelta = !ur.Replay
			zd.publishLocked(zd.generation.Load())
			if zd.wsPersistErr != nil {
				err = fmt.Errorf("zone %s: update not applied: could not persist the change: %w",
					zd.ZoneName, zd.wsPersistErr)
				zd.wsPersistErr = nil
				updated = false
			}
		}
		zd.mu.Unlock()
	}()
	zd.ensureWorkingSet()

	lg.Debug("ApplyZoneUpdateToZoneData: processing actions", "zone", zd.ZoneName, "count", len(ur.Actions))
	for actionIdx, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		// CDS-publication observability: trace the apex CDS RRset's
		// lifecycle through the update path so we can see whether the
		// engine's queued publish is landing on disk and surviving.
		if rrtype == dns.TypeCDS {
			before := 0
			if owner := zd.stagedOwner(ownerName); owner != nil {
				if rs, ok := owner.RRtypes.Get(dns.TypeCDS); ok {
					before = len(rs.RRs)
				}
			}
			lgRollover.Debug("zone-update CDS action received",
				"zone", zd.ZoneName, "owner", ownerName,
				"class", dns.ClassToString[class],
				"apex_cds_rrs_before", before,
				"internal_update", ur.InternalUpdate)
		}

		// DELNAME (RFC 2136 §2.5.3): CLASS=ANY with TYPE=ANY deletes every
		// RRset at the owner name. It has to be handled here, above the
		// per-rrtype policy gate below, because TypeANY is never a key in
		// UpdatePolicy.Zone.RRtypes -- the gate would take the "denied"
		// branch and `continue`, which is why DELNAME has always been a
		// silent no-op. That gap was not specific to our own CLI; bind9
		// nsupdate's "update delete <name>" hit it too.
		//
		// Two deliberate restrictions:
		//
		//   - At the apex, SOA and NS are retained (RFC 2136 §3.4.2.3).
		//     Deleting them would dismantle the zone rather than a name in it.
		//
		//   - Each rrtype is still checked against the update policy. Hoisting
		//     the whole statement above the gate would otherwise turn DELNAME
		//     into a privilege escalation: a requestor permitted to touch only
		//     TXT could erase every type at the name in one statement. Types
		//     the policy denies are skipped, so a DELNAME under a restrictive
		//     policy deletes what that requestor could have deleted one
		//     statement at a time, and nothing more.
		if class == dns.ClassANY && rrtype == dns.TypeANY {
			owner := zd.stagedOwner(ownerName)
			if owner == nil {
				lg.Warn("ApplyZoneUpdateToZoneData: DELNAME for unknown owner", "owner", ownerName)
				continue
			}
			isApex := strings.EqualFold(ownerName, zd.ZoneName)
			var deleted, denied, retained int
			for _, t := range owner.RRtypes.Keys() {
				if isApex && apexRetainedOnDelname(t) {
					retained++
					continue
				}
				if _, allowed := zd.UpdatePolicy.Zone.RRtypes[t]; !allowed &&
					!ur.InternalUpdate && !ur.PreAuthorized {
					denied++
					continue
				}
				zd.stageDeleteLocked(ownerName, t)
				deleted++
				updated = true
			}
			lg.Debug("ApplyZoneUpdateToZoneData: DELNAME", "owner", ownerName,
				"apex", isApex, "deleted", deleted, "denied_by_policy", denied,
				"retained_apex_rrsets", retained)
			continue
		}

		rrcopy := dns.Copy(rr)
		// update-policy dictates the TTL for records arriving over DDNS: a
		// wire client does not get to choose how long the zone caches what it
		// just added. It has no business rewriting the TTL on the other two
		// channels. An operator using the API said 3600 deliberately, and an
		// internal publisher (CSYNC/CDS/KEY) picks TTLs that matter to the
		// signalling it is driving -- a rollover wanting a short TTL would
		// silently get the policy's instead.
		if !ur.InternalUpdate && !ur.PreAuthorized {
			rrcopy.Header().Ttl = zd.UpdatePolicy.Zone.TTL
		}
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		// update-policy governs the DDNS channel. Internal changes and
		// API-channel requests bypass it: the API's authorization is the API
		// key, already checked by the handler that set PreAuthorized. Zone
		// self-service therefore stays on DDNS, where the policy applies.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate && !ur.PreAuthorized {
			lg.Error("ApplyZoneUpdateToZoneData: RR type denied by policy", "rrtype", rrtypestr)
			continue
		}

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner := zd.stagedOwner(ownerName)
		if owner == nil {
			if class == dns.ClassNONE || class == dns.ClassANY {
				lg.Warn("ApplyZoneUpdateToZoneData: unknown owner name", "owner", ownerName)
				continue
			}
			owner = zd.getOrCreateWorkingOwner(ownerName)
			updated = true
		}

		rrset, exists := owner.RRtypes.Get(rrtype)
		if !exists {
			lg.Warn("ApplyZoneUpdateToZoneData: no RRset for owner", "owner", ownerName, "rrtype", rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				continue
			}
			rrset = core.RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		} else {
			// Get returns an RRset whose RRs/RRSIGs slices alias the published
			// snapshot's backing arrays (cloneOwner shares them). The in-place
			// RemoveRR / append / SignRRset below would otherwise tear the live
			// view for concurrent readers — clone before mutating.
			rrset = cloneRRset(rrset)
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			rrset.RemoveRR(rrcopy, Globals.Verbose, Globals.Debug) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				zd.stageDeleteLocked(ownerName, rrtype)
			} else {
				_, err := zd.SignRRset(&rrset, ownerName, dak, true, nil)
				if err != nil {
					lg.Error("ApplyZoneUpdateToZoneData: signing failed after RR removal", "rrtype", rrtypestr, "owner", ownerName, "error", err)
					// Continue anyway - the record is still added, just not signed
				}
				zd.stageRRsetLocked(ownerName, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyZoneUpdateToZoneData: Remove RR", "owner", ownerName, "rrtype", rrtypestr, "rr", rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset.
			//
			// Refuse the two RRsets that constitute the zone itself. The CLI
			// builder already declines these, but actions can also be built
			// locally, and a zone whose apex SOA or NS RRset has been deleted
			// is not a zone -- the apex guard in publishWorkingSetLocked would
			// then refuse the whole publish, discarding every other change in
			// the same update along with it.
			//
			// Only SOA and NS, deliberately. DNSKEY and the signalling RRsets
			// are protected against wholesale DELNAME (see
			// apexRetainedOnDelname), but an explicit "delrrset --type DNSKEY"
			// is unambiguous intent and stays possible.
			//
			// UNLESS the same update replaces it. A replacerrset is a
			// ClassANY delete followed by the new records in one action list,
			// so the zone ends the update WITH an apex NS RRset and the
			// guard's concern does not apply. Without this exception the
			// delete is dropped and the additions still run, so
			// "replacerrset" on the apex NS silently APPENDS to the existing
			// RRset instead of replacing it -- the operator asks to move to a
			// new set of nameservers and gets the union of old and new.
			//
			// SOA has no such exception: tdns owns the serial, and the
			// builder refuses replacerrset for it outright so the failure is
			// loud and at the client rather than silent here.
			if strings.EqualFold(ownerName, zd.ZoneName) &&
				(rrtype == dns.TypeSOA || rrtype == dns.TypeNS) {
				if rrtype == dns.TypeNS &&
					updateReplacesRRset(ur.Actions[actionIdx+1:], ownerName, rrtype) {
					lg.Debug("ApplyZoneUpdateToZoneData: apex NS delete is part of a replacement, allowing",
						"zone", zd.ZoneName)
				} else {
					lg.Warn("ApplyZoneUpdateToZoneData: refusing to delete an apex RRset the zone cannot exist without",
						"zone", zd.ZoneName, "rrtype", rrtypestr)
					continue
				}
			}
			zd.stageDeleteLocked(ownerName, rrtype)
			// XXX: As long as we don't maintain any NSEC chain removing a complete RRset should not require any resigning.
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyZoneUpdateToZoneData: Remove RRset", "rr", rr.String())
			if rrtype == dns.TypeCDS {
				lgRollover.Debug("zone-update CDS RRset deleted (ClassANY)",
					"zone", zd.ZoneName, "owner", ownerName)
			}
			continue

		case dns.ClassINET:
		default:
			lg.Error("ApplyZoneUpdateToZoneData: unknown class", "rr", rr.String())
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				lg.Debug("ApplyZoneUpdateToZoneData: not adding duplicate", "rrtype", rrtypestr, "rr", rrcopy.String())
				dup = true
				break
			}
		}

		if !dup {
			lg.Debug("ApplyZoneUpdateToZoneData: adding RR", "rrtype", rrtypestr, "rr", rrcopy.String())
			rrset.RRs = append(rrset.RRs, rrcopy)
			// rrset.RRSIGs = []dns.RR{} // XXX: The RRset changed, so any old RRSIGs are now invalid.
			_, err = zd.SignRRset(&rrset, ownerName, dak, true, nil)
			if err != nil {
				lg.Error("ApplyZoneUpdateToZoneData: signing failed after RR add", "rrtype", rrtypestr, "owner", ownerName, "error", err)
				// Continue anyway - the record is still added, just not signed
			}
			zd.stageRRsetLocked(ownerName, rrset)
			updated = true
			if rrtype == dns.TypeCDS {
				lgRollover.Debug("zone-update CDS add committed",
					"zone", zd.ZoneName, "owner", ownerName,
					"apex_cds_rrs_after", len(rrset.RRs),
					"rrsigs", len(rrset.RRSIGs))
			}
		}
		continue
	}

	lg.Debug("ApplyZoneUpdateToZoneData done", "updated", updated)

	return updated, nil
}

func (kdb *KeyDB) ApplyZoneUpdateToDB(ur UpdateRequest) error {
	return nil // placeholder
}

// ZoneUpdateChangesDelegationDataNG: the list of actions in ddata.Actions
// is the complete set of actions that should be sent to the parent.

func (zd *ZoneData) ZoneUpdateChangesDelegationDataNG(ur UpdateRequest) (DelegationSyncStatus, error) {
	// log.Printf("*** Enter ZUCDDNGNG(). ur:\n%+v", ur)
	var dss = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Time:     time.Now(),
		InSync:   true,
	}

	defer func() {
		// log.Printf("********* ZUCDDNGNG: returning")
	}()

	ddata, err := zd.DelegationData()
	if err != nil {
		return dss, err
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return dss, err
	}
	bns, err := BailiwickNS(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	if err != nil {
		return dss, err
	}

	// We must sort the ur.Actions to ensure that any NS actions come first (so that possible glue actions
	// have an NS to refer to.

	var new_bns []string

	var actions []dns.RR
	for _, rr := range ur.Actions {
		if rr.Header().Rrtype == dns.TypeNS {
			actions = append(actions, rr)
			if rr.Header().Name == zd.ZoneName {
				new_bns = append(new_bns, rr.Header().Name)
			}
		}
	}
	for _, rr := range ur.Actions {
		if rr.Header().Rrtype != dns.TypeNS {
			actions = append(actions, rr)
		}
	}

	for _, rr := range actions {
		// log.Printf("ZUCDDNG: checking action: %s", rr.String())
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		if rrtype != dns.TypeNS && rrtype != dns.TypeA && rrtype != dns.TypeAAAA && rrtype != dns.TypeDNSKEY {
			//log.Printf("ZUCDDNG: Update does not affect delegation data: %s", rrtypestr)
			continue
		}

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		// Why did we modify the class here?
		// rrcopy.Header().Class = dns.ClassINET

		// XXX: This is the wrong place for this check. These things should be already sorted out during the approval phase.
		// XXX: But we keep it here until the approval code is updated.
		// First check whether this update is allowed by the update-policy.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate {
			// log.Printf("ZUCDDNG: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

		if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
			dss.InSync = false
			// return dss, nil
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			//log.Printf("ZUCDDNG: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())

			// Is this a change to the NS RRset?
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsRemoves = append(dss.NsRemoves, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
				ddata.RemovedNS.RRs = append(ddata.RemovedNS.RRs, rrcopy)
				//log.Printf("ZUCDDNG: Removed NS: %s; now we need to remove any glue", rrcopy.String())
				if nsrr, ok := rr.(*dns.NS); ok {
					nsowner, err := zd.GetOwner(nsrr.Ns)
					if err != nil {
						lg.Error("ZUCDDNG: NS owner has no RRs", "nsname", nsrr.Ns, "ns", nsrr.String())
					} else if nsowner != nil { // nsowner != nil if the NS is in bailiwick
						if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
							for _, rr := range a_rrset.RRs {
								rr.Header().Class = dns.ClassNONE
								dss.ARemoves = append(dss.ARemoves, rr)
								ddata.Actions = append(ddata.Actions, rr)
							}
						}
						if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
							for _, rr := range aaaa_rrset.RRs {
								rr.Header().Class = dns.ClassNONE
								dss.AAAARemoves = append(dss.AAAARemoves, rr)
								ddata.Actions = append(ddata.Actions, rr)
							}
						}
					}
				}
			}
			// Is this a change to glue for a nameserver?
			for _, nsname := range ddata.BailiwickNS {
				if nsname == ownerName {
					if rrtype == dns.TypeA {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					} else if rrtype == dns.TypeAAAA {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}
			}
			// Is this a KSK DNSKEY removal?
			if ownerName == zd.ZoneName && rrtype == dns.TypeDNSKEY {
				if dk, ok := rr.(*dns.DNSKEY); ok {
					if dk.Flags&dns.SEP != 0 {
						dss.InSync = false
						dss.DNSKEYRemoves = append(dss.DNSKEYRemoves, rrcopy)
					}
				}
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset.
			//log.Printf("ZUCDDNG: Remove RRset: %s", rr.String())
			switch rrtype {
			case dns.TypeNS:
				if ownerName == zd.ZoneName {
					// A standalone delete of the apex NS RRset is refused by
					// the applier and correctly ignored here.
					//
					// A delete that is one half of a REPLACEMENT is applied,
					// though, and then this has to report it: otherwise the
					// local zone drops the old nameservers while the parent is
					// only ever told about the new ones, and ends up serving
					// the union -- the same append-instead-of-replace bug the
					// applier fix closed, one hop further out.
					//
					// Only the records the replacement does not re-add are
					// reported gone. A remove+add of the same record would be
					// churn at best, and on the delta path -- where the parent
					// applies the list in order -- an add reordered before its
					// own remove would lose the record.
					newNS := apexNSReplacementRecords(ur.Actions, zd.ZoneName)
					// No replacement records means this is a standalone
					// delete, which the applier refuses -- so nothing was
					// removed and nothing may be reported. Without this the
					// loop below finds none of the current records in an empty
					// replacement set and reports the whole RRset gone, telling
					// the parent to drop nameservers the child still serves.
					if len(newNS) == 0 {
						break
					}
					for _, cur := range apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
						if rrPresentIn(newNS, cur) {
							continue
						}
						gone := dns.Copy(cur)
						gone.Header().Ttl = 3600
						dss.InSync = false
						dss.NsRemoves = append(dss.NsRemoves, gone)
						ddata.Actions = append(ddata.Actions, gone)
					}
				}

			case dns.TypeA:
				for _, nsname := range bns {
					if nsname == ownerName {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}

			case dns.TypeAAAA:
				for _, nsname := range bns {
					if nsname == ownerName {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}

			case dns.TypeDNSKEY:
				if ownerName == zd.ZoneName {
					// Removing entire DNSKEY RRset — record all KSK removals
					dss.InSync = false
					apex, apexErr := zd.GetOwner(zd.ZoneName)
					if apexErr == nil && apex != nil {
						if dkRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY); exists {
							for _, dkrr := range dkRRset.RRs {
								if dk, ok := dkrr.(*dns.DNSKEY); ok && dk.Flags&dns.SEP != 0 {
									dss.DNSKEYRemoves = append(dss.DNSKEYRemoves, dns.Copy(dkrr))
								}
							}
						}
					}
					dss.NewDS = nil
				}
			}
			continue

		case dns.ClassINET:
		default:
			//log.Printf("ZUCDDNG: Error: unknown class: %s", rr.String())
			continue
		}

		// Here we know that the actions has class == ClassINET
		//log.Printf("ZUCDDNG: Class is INET, this is an ADD: %s", rr.String())

		dup := false
		switch rrtype {
		case dns.TypeNS:
			if ownerName == zd.ZoneName {
				for _, rr := range ddata.CurrentNS.RRs {
					if dns.IsDuplicate(rr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.NsAdds = append(dss.NsAdds, rrcopy)
					ddata.AddedNS.RRs = append(ddata.AddedNS.RRs, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
					// XXX: This is a new NS. Now we must locate any existing address RRs for this name.
					if nsrr, ok := rr.(*dns.NS); ok {
						//log.Printf("ZUCDDNG: fetching owner for NS: %+v", nsrr.Ns)
						nsowner, err := zd.GetOwner(nsrr.Ns)
						if err != nil || nsowner == nil {
							// log.Printf("ZUCDDNG: Error: owner %s of NS %s is unknown", nsrr.Ns, nsrr.String())
						} else {
							// log.Printf("ZUCDDNG: nsowner: %+v", nsowner)
							if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
								for _, rr := range a_rrset.RRs {
									dss.AAdds = append(dss.AAdds, rr)
									ddata.Actions = append(ddata.Actions, rr)
								}
							}
							if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
								for _, rr := range aaaa_rrset.RRs {
									dss.AAAAAdds = append(dss.AAAAAdds, rr)
									ddata.Actions = append(ddata.Actions, rr)
								}
							}
						}
						// It is also possible that glue for the new NS is present later in the update.
						for _, action := range actions {
							if action.Header().Name == nsrr.Ns {
								if action.Header().Rrtype == dns.TypeA {
									// log.Printf("ZUCDDNG: adding glue for new NS %s from later in the update: %s", nsrr.Ns, action.String())
									dss.AAdds = append(dss.AAdds, action)
									ddata.Actions = append(ddata.Actions, action)
								} else if action.Header().Rrtype == dns.TypeAAAA {
									// log.Printf("ZUCDDNG: adding glue for new NS %s from later in the update: %s", nsrr.Ns, action.String())
									dss.AAAAAdds = append(dss.AAAAAdds, action)
									ddata.Actions = append(ddata.Actions, action)
								}
							}
						}
					}
				}
			} else {
				// log.Printf("ZUCDDNG: Error: zone update tries to modify child delegation.")
			}

		case dns.TypeA:
			// XXX: There are two cases: adding a new A to a current or new NS and adding an A to an NS
			// that is being removed. Only the first case modifies the delegation.
			if oldglue, exist := ddata.A_glue[ownerName]; exist {
				for _, arr := range oldglue.RRs {
					if dns.IsDuplicate(arr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.AAdds = append(dss.AAdds, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
				}
			} else if slices.Contains(new_bns, ownerName) {
				// This is glue for a new NS that is being added.
				dss.InSync = false
				dss.AAdds = append(dss.AAdds, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
			}

		case dns.TypeAAAA:
			// XXX: There are two cases: adding a new A to a current or new NS and adding an A to an NS
			// that is being removed. Only the first case modifies the delegation.
			if oldglue, exist := ddata.AAAA_glue[ownerName]; exist {
				for _, aaaa_rr := range oldglue.RRs {
					if dns.IsDuplicate(aaaa_rr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.AAAAAdds = append(dss.AAAAAdds, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
				}
			} else if slices.Contains(new_bns, ownerName) {
				// This is glue for a new NS that is being added.
				dss.InSync = false
				dss.AAAAAdds = append(dss.AAAAAdds, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
			}

		case dns.TypeDNSKEY:
			if ownerName == zd.ZoneName {
				if dk, ok := rr.(*dns.DNSKEY); ok {
					if dk.Flags&dns.SEP != 0 {
						dss.InSync = false
						dss.DNSKEYAdds = append(dss.DNSKEYAdds, rrcopy)
					}
				}
			}

		default:
			lg.Error("ZUCDDNG: unexpected RR type", "rrtype", rrtypestr, "rr", rr.String())
		}
	}

	lg.Debug("ZUCDDNG delegation data", "zone", zd.ZoneName, "ddata", fmt.Sprintf("%+v", ddata))
	lg.Debug("ZUCDDNG delegation actions", "zone", zd.ZoneName, "actions", SprintUpdates(ddata.Actions))

	computeNewNSFromCurrent(&dss, ddata.CurrentNS.RRs)
	err = computeNewGlue(&dss, zd.ZoneName, ddata)
	if err != nil {
		return dss, err
	}
	computeNewDS(&dss, zd)

	return dss, nil
}

// computeNewNSFromCurrent computes the complete new NS RRset for replace
// mode by starting from the current NS RRset and applying the adds/removes
// from dss.
func computeNewNSFromCurrent(dss *DelegationSyncStatus, currentNS []dns.RR) {
	dss.NewNS = make([]dns.RR, 0, len(currentNS))
	for _, rr := range currentNS {
		dss.NewNS = append(dss.NewNS, dns.Copy(rr))
	}

	for _, remove := range dss.NsRemoves {
		for i := len(dss.NewNS) - 1; i >= 0; i-- {
			if dns.IsDuplicate(dss.NewNS[i], remove) {
				dss.NewNS = append(dss.NewNS[:i], dss.NewNS[i+1:]...)
				break
			}
		}
	}

	for _, add := range dss.NsAdds {
		dup := false
		for _, existing := range dss.NewNS {
			if dns.IsDuplicate(existing, add) {
				dup = true
				break
			}
		}
		if !dup {
			rrcopy := dns.Copy(add)
			rrcopy.Header().Ttl = 3600
			rrcopy.Header().Class = dns.ClassINET
			dss.NewNS = append(dss.NewNS, rrcopy)
		}
	}
}

// computeNewGlue computes the complete new A and AAAA glue records for
// replace mode. It builds maps of current glue, applies adds/removes,
// and collects glue for in-bailiwick NS names from the new NS RRset.
func computeNewGlue(dss *DelegationSyncStatus, zoneName string, ddata *DelegationData) error {
	new_bailiwick_ns, err := BailiwickNS(zoneName, dss.NewNS)
	if err != nil {
		lg.Error("computeNewGlue: failed to compute bailiwick NS", "error", err)
		return err
	}

	current_a_glue := make(map[string][]dns.RR)
	current_aaaa_glue := make(map[string][]dns.RR)
	for nsname, rrset := range ddata.A_glue {
		current_a_glue[nsname] = make([]dns.RR, len(rrset.RRs))
		for i, rr := range rrset.RRs {
			current_a_glue[nsname][i] = dns.Copy(rr)
		}
	}
	for nsname, rrset := range ddata.AAAA_glue {
		current_aaaa_glue[nsname] = make([]dns.RR, len(rrset.RRs))
		for i, rr := range rrset.RRs {
			current_aaaa_glue[nsname][i] = dns.Copy(rr)
		}
	}

	// Apply removes to current glue
	for _, remove := range dss.ARemoves {
		nsname := remove.Header().Name
		if glue, exists := current_a_glue[nsname]; exists {
			for i := len(glue) - 1; i >= 0; i-- {
				if dns.IsDuplicate(glue[i], remove) {
					glue = append(glue[:i], glue[i+1:]...)
					current_a_glue[nsname] = glue
					break
				}
			}
		}
	}
	for _, remove := range dss.AAAARemoves {
		nsname := remove.Header().Name
		if glue, exists := current_aaaa_glue[nsname]; exists {
			for i := len(glue) - 1; i >= 0; i-- {
				if dns.IsDuplicate(glue[i], remove) {
					glue = append(glue[:i], glue[i+1:]...)
					current_aaaa_glue[nsname] = glue
					break
				}
			}
		}
	}

	// Apply adds to current glue
	for _, add := range dss.AAdds {
		nsname := add.Header().Name
		if slices.Contains(new_bailiwick_ns, nsname) {
			if glue, exists := current_a_glue[nsname]; exists {
				dup := false
				for _, existing := range glue {
					if dns.IsDuplicate(existing, add) {
						dup = true
						break
					}
				}
				if !dup {
					rrcopy := dns.Copy(add)
					rrcopy.Header().Ttl = 3600
					rrcopy.Header().Class = dns.ClassINET
					current_a_glue[nsname] = append(current_a_glue[nsname], rrcopy)
				}
			} else {
				rrcopy := dns.Copy(add)
				rrcopy.Header().Ttl = 3600
				rrcopy.Header().Class = dns.ClassINET
				current_a_glue[nsname] = []dns.RR{rrcopy}
			}
		}
	}
	for _, add := range dss.AAAAAdds {
		nsname := add.Header().Name
		if slices.Contains(new_bailiwick_ns, nsname) {
			if glue, exists := current_aaaa_glue[nsname]; exists {
				dup := false
				for _, existing := range glue {
					if dns.IsDuplicate(existing, add) {
						dup = true
						break
					}
				}
				if !dup {
					rrcopy := dns.Copy(add)
					rrcopy.Header().Ttl = 3600
					rrcopy.Header().Class = dns.ClassINET
					current_aaaa_glue[nsname] = append(current_aaaa_glue[nsname], rrcopy)
				}
			} else {
				rrcopy := dns.Copy(add)
				rrcopy.Header().Ttl = 3600
				rrcopy.Header().Class = dns.ClassINET
				current_aaaa_glue[nsname] = []dns.RR{rrcopy}
			}
		}
	}

	// Collect all glue records for the new bailiwick NS
	dss.NewA = []dns.RR{}
	dss.NewAAAA = []dns.RR{}
	for _, nsname := range new_bailiwick_ns {
		if glue, exists := current_a_glue[nsname]; exists {
			for _, rr := range glue {
				dss.NewA = append(dss.NewA, dns.Copy(rr))
			}
		}
		if glue, exists := current_aaaa_glue[nsname]; exists {
			for _, rr := range glue {
				dss.NewAAAA = append(dss.NewAAAA, dns.Copy(rr))
			}
		}
	}

	return nil
}

// computeNewDS computes the complete new DS RRset for replace mode
// by deriving DS records from the current KSK DNSKEYs in the zone.
func computeNewDS(dss *DelegationSyncStatus, zd *ZoneData) {
	if len(dss.DNSKEYAdds) == 0 && len(dss.DNSKEYRemoves) == 0 {
		return
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return
	}

	// Build the effective post-update DNSKEY set:
	// start from current, remove DNSKEYRemoves, add DNSKEYAdds.
	effective := make(map[uint16]*dns.DNSKEY)
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		if dk, ok := rr.(*dns.DNSKEY); ok {
			if dk.Flags&dns.SEP != 0 {
				effective[dk.KeyTag()] = dk
			}
		}
	}
	for _, rr := range dss.DNSKEYRemoves {
		if dk, ok := rr.(*dns.DNSKEY); ok {
			delete(effective, dk.KeyTag())
		}
	}
	for _, rr := range dss.DNSKEYAdds {
		if dk, ok := rr.(*dns.DNSKEY); ok {
			if dk.Flags&dns.SEP != 0 {
				effective[dk.KeyTag()] = dk
			}
		}
	}

	var newDS []dns.RR
	for _, dk := range effective {
		if ds := dk.ToDS(dns.SHA256); ds != nil {
			newDS = append(newDS, ds)
		}
	}
	dss.NewDS = newDS
}

// updateReplacesRRset reports whether actions contain at least one record to
// ADD for owner/rrtype, i.e. whether a ClassANY delete of that RRset in the
// same update is one half of an atomic replacement rather than a removal.
//
// Callers pass the actions AFTER the delete, never the whole list. RFC 2136
// §3.4.2.6 processes the update section in order, so an add that comes BEFORE
// the delete is not a replacement -- it is a record the delete then removes.
// Scanning the whole list would read
//
//	[ add NS ns9, delete-RRset NS ]
//
// as a replacement, permit the delete, and leave the apex with no NS RRset at
// all: exactly the state the guard exists to prevent, reached through the
// exception meant to be safe. Actions built here always come delete-first, but
// the Ns section of a DNS UPDATE arrives in whatever order the client sent.
//
// BuildZoneUpdateActions emits replacerrset as exactly that pair, and the
// applier walks the whole list in one pass under one zd.mu and publishes once,
// so the empty intermediate RRset is never observable. That is what makes it
// safe to let a replacement delete an apex RRset the zone cannot be served
// without: by the end of the same pass, it has one again.
func updateReplacesRRset(actions []dns.RR, owner string, rrtype uint16) bool {
	for _, rr := range actions {
		if rr.Header().Class != dns.ClassINET {
			continue
		}
		if rr.Header().Rrtype == rrtype && strings.EqualFold(rr.Header().Name, owner) {
			return true
		}
	}
	return false
}

// apexNSReplacementRecords returns the apex NS records an update adds AFTER a
// ClassANY delete of that RRset, i.e. the set an apex-NS replacement replaces
// the old one with. Empty when the update is not such a replacement.
//
// Walks in wire order, and deliberately shares that rule with the applier's
// updateReplacesRRset: the two must agree about what counts as a replacement,
// or the zone and the delegation report drift apart.
func apexNSReplacementRecords(actions []dns.RR, zone string) []dns.RR {
	for i, rr := range actions {
		if rr.Header().Class != dns.ClassANY || rr.Header().Rrtype != dns.TypeNS {
			continue
		}
		if !strings.EqualFold(rr.Header().Name, zone) {
			continue
		}
		var newNS []dns.RR
		for _, later := range actions[i+1:] {
			if later.Header().Class == dns.ClassINET &&
				later.Header().Rrtype == dns.TypeNS &&
				strings.EqualFold(later.Header().Name, zone) {
				newNS = append(newNS, later)
			}
		}
		return newNS
	}
	return nil
}

// rrPresentIn reports whether rr appears in the list, comparing rdata rather
// than TTL: a nameserver kept across a replacement is the same nameserver even
// if the new record spells its TTL differently.
func rrPresentIn(list []dns.RR, rr dns.RR) bool {
	for _, cand := range list {
		if dns.IsDuplicate(cand, rr) {
			return true
		}
	}
	return false
}
