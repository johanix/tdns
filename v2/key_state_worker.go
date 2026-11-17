/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * KeyStateWorker: background goroutine for automatic DNSSEC key state transitions.
 * Handles time-based transitions (published→standby, retired→removed) and
 * maintains the configured number of standby keys per zone.
 */

package tdns

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultPropagationDelay = 1 * time.Hour
	defaultCheckInterval    = 1 * time.Minute
	defaultStandbyZskCount  = 1
	defaultStandbyKskCount  = 0
)

// KeyStateWorker runs periodic checks on DNSSEC key states and performs
// automatic transitions and standby key maintenance.
func KeyStateWorker(ctx context.Context, conf *Config) error {
	kasp := &conf.Dnssec.Kasp

	propagationDelay := defaultPropagationDelay
	if kasp.PropagationDelay != "" {
		if d, err := time.ParseDuration(kasp.PropagationDelay); err == nil {
			if d > 0 {
				propagationDelay = d
			} else {
				lgSigner.Warn("kasp.propagation-delay must be positive, using default", "value", kasp.PropagationDelay, "default", defaultPropagationDelay)
			}
		} else {
			lgSigner.Warn("invalid kasp.propagation-delay, using default", "value", kasp.PropagationDelay, "default", defaultPropagationDelay, "err", err)
		}
	}

	checkInterval := defaultCheckInterval
	if kasp.CheckInterval != "" {
		if d, err := time.ParseDuration(kasp.CheckInterval); err == nil {
			if d > 0 {
				checkInterval = d
			} else {
				lgSigner.Warn("kasp.check-interval must be positive, using default", "value", kasp.CheckInterval, "default", defaultCheckInterval)
			}
		} else {
			lgSigner.Warn("invalid kasp.check-interval, using default", "value", kasp.CheckInterval, "default", defaultCheckInterval, "err", err)
		}
	}

	// The global counts; a zone's policy may set its own (maintainStandbyKeys).
	standbyZskCount := conf.kaspStandbyCount(false)
	standbyKskCount := conf.kaspStandbyCount(true)

	kdb := conf.Internal.KeyDB
	if kdb == nil {
		lgSigner.Warn("KeyStateWorker: no KeyDB available, exiting")
		return nil
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	lgSigner.Info("KeyStateWorker started", "propagation-delay", propagationDelay, "standby-zsk-count", standbyZskCount, "standby-ksk-count", standbyKskCount, "check-interval", checkInterval)

	// Cross-check: any rollover policy whose attempt-timeout (=
	// confirm-timeout, derived from ds-publish-delay × 1.2 by default)
	// is shorter than 2 × check-interval will starve observe polling
	// — the next observe-tick lands past the attempt-timeout cliff
	// before any poll runs. Warn at startup so the operator catches
	// the misconfiguration without first losing a rollover cycle.
	for name, pol := range conf.Internal.DnssecPolicies {
		if pol.Rollover.Method != RolloverMethodMultiDS && pol.Rollover.Method != RolloverMethodDoubleSignature {
			continue
		}
		if pol.Rollover.ConfirmTimeout > 0 && pol.Rollover.ConfirmTimeout < 2*checkInterval {
			lgSigner.Warn("rollover: kasp.check-interval too coarse for policy attempt-timeout; observe polling will be starved",
				"policy", name,
				"attempt_timeout", pol.Rollover.ConfirmTimeout,
				"check-interval", checkInterval,
				"remedy", "lower kasp.check-interval (must be < attempt-timeout / 2) or raise rollover.ds-publish-delay")
		}
	}

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("KeyStateWorker stopping")
			return nil
		case <-ticker.C:
			checkAndTransitionKeys(ctx, conf, kdb, propagationDelay, standbyZskCount, standbyKskCount)
		}
	}
}

// checkAndTransitionKeys performs all periodic key state checks:
// 1. published → standby (time-based)
// 2. retired → removed (time-based)
// 3. maintain standby key count (generate new keys as needed)
func checkAndTransitionKeys(ctx context.Context, conf *Config, kdb *KeyDB, propagationDelay time.Duration, standbyZskCount, standbyKskCount int) {
	now := time.Now()

	// Rows whose ds is still unset get it from their zone's DS model, before
	// anything below reads it (keyrow_ds.go).
	fillDsForPolicyZones(ctx, kdb)

	rolloverAutomatedForAllZones(ctx, conf, kdb, propagationDelay, now)
	TransitionRolloverKskDsPublishedToPublished(ctx, conf, kdb, now, propagationDelay)
	TransitionRolloverKskPublishedToStandby(ctx, conf, kdb, now, propagationDelay)
	promoteStandbyKskBootstrapAll(conf, kdb)

	transitionPublishedToStandby(kdb, now, propagationDelay)

	rolloverZsksForAllZones(ctx, conf, kdb, propagationDelay, now)

	transitionRetiredToRemoved(ctx, kdb, now, propagationDelay)

	maintainStandbyKeys(ctx, kdb, propagationDelay, standbyZskCount, standbyKskCount)

	// Last, so the backstop sees every transition this tick made.
	markZonesForDSEngine(ctx, kdb)
}

// transitionPublishedToStandby transitions keys that have been in "published"
// state long enough for the DNSKEY RRset to propagate through all caches:
// propagation-delay for the key to reach every server, plus the served DNSKEY
// TTL for a resolver's copy of the RRset without it to expire. A standby key is
// one that may sign at once -- "asap --zsk" promotes the oldest on the next
// tick -- so leaving out the TTL let a new ZSK sign while resolvers still held
// a DNSKEY RRset that lacked it (#705). The KSK gate
// (transitionPublishedToStandbyForZone) and the retired-ZSK hold
// (zskRemovalMargin) already count the TTL.
//
// A global walk: it reaches every zone's published keys. A zone whose
// lifecycle is OWNED (KeyLifecycleOwner) is different: its owner runs every
// timer, and this walk leaves its keys alone.
func transitionPublishedToStandby(kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting published keys", "err", err)
		return
	}
	keys = keysOfUnownedZones(keys)

	type servedTTL struct {
		ttl   time.Duration
		known bool
	}
	ttls := map[string]servedTTL{}

	for _, key := range keys {
		if key.Flags&dns.SEP != 0 {
			if zd, ok := Zones.Get(key.ZoneName); ok && zd.DnssecPolicy != nil && zd.DnssecPolicy.Rollover.Method == RolloverMethodMultiDS {
				continue
			}
		}
		if key.PublishedAt == nil {
			// Legacy/migrated key with no published_at (column was added later with
			// DEFAULT ''): stamp it now (persisted via UpdateDnssecKeyState) so the
			// rollover can progress, instead of skipping it forever. Conservative —
			// the key then waits the full propagation delay measured from now.
			lgSigner.Warn("KeyStateWorker: published key missing published_at; stamping it now and deferring transition", "zone", key.ZoneName, "keyid", key.KeyTag)
			if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, DnskeyStatePublished); err != nil {
				lgSigner.Error("KeyStateWorker: failed to stamp published_at", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
			}
			continue
		}

		if key.PublishedAt.After(now.Add(5 * time.Minute)) {
			lgSigner.Warn("KeyStateWorker: published_at timestamp is in the future, skipping", "zone", key.ZoneName, "keyid", key.KeyTag, "published_at", key.PublishedAt)
			continue
		}

		if now.Sub(*key.PublishedAt) > 10*365*24*time.Hour {
			lgSigner.Warn("KeyStateWorker: published_at timestamp is unreasonably old (>10 years), skipping", "zone", key.ZoneName, "keyid", key.KeyTag, "published_at", key.PublishedAt)
			continue
		}

		st, seen := ttls[key.ZoneName]
		if !seen {
			st.ttl, st.known = servedDnskeyTTLForZone(kdb, key.ZoneName)
			ttls[key.ZoneName] = st
		}
		if !st.known {
			// The zone has no TTL in its policy and has not been signed yet.
			// Clears after the first SignZone; a zone's first keys are minted
			// active and never wait here.
			lgSigner.Debug("KeyStateWorker: deferring published→standby; DNSKEY TTL not yet observable", "zone", key.ZoneName, "keyid", key.KeyTag)
			continue
		}

		elapsed := now.Sub(*key.PublishedAt)
		if elapsed < propagationDelay+st.ttl {
			continue
		}

		lgSigner.Info("KeyStateWorker: transitioning published→standby", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second), "propagation_delay", propagationDelay, "dnskey_ttl", st.ttl)
		if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, DnskeyStateStandby); err != nil {
			lgSigner.Error("KeyStateWorker: published→standby failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
		}
	}
}

// servedDnskeyTTLForZone is how long a resolver may keep the zone's DNSKEY
// RRset: effectiveServedDnskeyTTL for a zone with a policy, else the largest
// TTL the last signing pass observed. (0, false) when neither is known.
func servedDnskeyTTLForZone(kdb *KeyDB, zone string) (time.Duration, bool) {
	if zd, ok := Zones.Get(zone); ok && zd.DnssecPolicy != nil {
		return effectiveServedDnskeyTTL(kdb, zone, zd.DnssecPolicy)
	}
	obs, err := LoadZoneSigningMaxTTL(kdb, zone)
	if err != nil || obs == 0 {
		return 0, false
	}
	return time.Duration(obs) * time.Second, true
}

// transitionRetiredToRemoved transitions keys that have been in "retired"
// state long enough for all RRSIGs made with them to expire from caches.
func transitionRetiredToRemoved(ctx context.Context, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateRetired)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting retired keys", "err", err)
		return
	}
	keys = keysOfUnownedZones(keys)

	for _, key := range keys {
		// 4B guard: SEP keys in rollover-managed zones are owned by the
		// rollover worker's pending-child-withdraw phase, which uses
		// effective_margin (not propagationDelay) and sequences the
		// retired→removed transition with a follow-up DS push. Skip them
		// here. ZSKs and SEP keys in non-rollover zones still flow
		// through this generic path.
		if key.Flags&dns.SEP != 0 {
			if zd, ok := Zones.Get(key.ZoneName); ok && zd.DnssecPolicy != nil && zd.DnssecPolicy.Rollover.Method != RolloverMethodNone {
				continue
			}
		}

		if key.RetiredAt == nil {
			lgSigner.Warn("KeyStateWorker: retired key has no retired_at timestamp, skipping", "zone", key.ZoneName, "keyid", key.KeyTag)
			continue
		}

		if key.RetiredAt.After(now.Add(5 * time.Minute)) {
			lgSigner.Warn("KeyStateWorker: retired_at timestamp is in the future, skipping", "zone", key.ZoneName, "keyid", key.KeyTag, "retired_at", key.RetiredAt)
			continue
		}

		if now.Sub(*key.RetiredAt) > 10*365*24*time.Hour {
			lgSigner.Warn("KeyStateWorker: retired_at timestamp is unreasonably old (>10 years), skipping", "zone", key.ZoneName, "keyid", key.KeyTag, "retired_at", key.RetiredAt)
			continue
		}

		margin := propagationDelay
		if key.Flags&dns.SEP == 0 {
			maxTTL, err := LoadZoneSigningMaxTTL(kdb, key.ZoneName)
			if err != nil {
				lgSigner.Warn("KeyStateWorker: LoadZoneSigningMaxTTL failed, using propagation-delay only", "zone", key.ZoneName, "err", err)
			} else {
				margin = zskRemovalMargin(propagationDelay, maxTTL)
			}
		}

		elapsed := now.Sub(*key.RetiredAt)
		if elapsed < margin {
			continue
		}

		// Strip the key's RRSIGs from the served zone BEFORE marking it removed,
		// so a strip failure leaves the key in 'retired' and the worker retries
		// the whole sequence next tick. (If we marked it removed first and the
		// strip then failed, the worker would no longer see the key and the
		// orphan RRSIGs would persist forever.) The strip only matters while the
		// zone is loaded; a not-loaded zone has nothing to serve.
		removedKeytag := key.KeyTag
		if zd, ok := Zones.Get(key.ZoneName); ok {
			if _, err := zd.StripZoneRRSIGs(ctx, func(rrsig *dns.RRSIG) bool {
				return rrsig.KeyTag == removedKeytag
			}); err != nil {
				// A cancelled context is an expected shutdown path, not a
				// per-key failure: stop the sweep quietly rather than
				// error-logging for every remaining retired key.
				if ctx.Err() != nil {
					lgSigner.Info("KeyStateWorker: stopping retired→removed sweep on context cancellation", "zone", key.ZoneName)
					return
				}
				lgSigner.Error("KeyStateWorker: failed to strip removed key's RRSIGs, will retry", "zone", key.ZoneName, "keyid", removedKeytag, "err", err)
				continue
			}
		}

		lgSigner.Info("KeyStateWorker: transitioning retired→removed", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second))
		// The key leaves the served DNSKEY RRset; the write re-signs (#918).
		if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, DnskeyStateRemoved); err != nil {
			lgSigner.Error("KeyStateWorker: retired→removed failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
		}
	}
}

// maintainStandbyKeys ensures each signing zone has the configured number of
// standby keys for both ZSKs and KSKs: the zone's policy's standby-zsks and
// standby-ksks when set, else the global standbyZskCount and standbyKskCount
// passed in. If a zone has fewer standby keys than required and no keys are
// in the published pipeline, new keys are generated.
// Every signing zone whose keys tdns's own machine runs; a zone whose key
// lifecycle an owner runs is the owner's (zoneOwned).
//
// propagationDelay is the tick's: with the served DNSKEY TTL it is the
// window a published key takes to reach standby, and a zone that keeps no
// standby ZSK mints its replacement that far ahead of its roll.
//
// ctx is honoured between zones. This was the last step of the worker's tick
// that did not take one, and it is the expensive one: generating a keypair is
// unbounded work -- seconds each for a large RSA key, and the PQ algorithms are
// worse -- so a server with a few hundred signing zones that all wanted a
// standby key would go on minting them right through shutdown.
func maintainStandbyKeys(ctx context.Context, kdb *KeyDB, propagationDelay time.Duration, standbyZskCount, standbyKskCount int) {
	for zoneName, zd := range Zones.Items() {
		if ctx.Err() != nil {
			lgSigner.Info("KeyStateWorker: stopping standby-key maintenance on context cancellation")
			return
		}
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zoneOwned(zd) {
			continue // the owner keeps its own standby keys
		}

		if zd.DnssecPolicy == nil {
			continue
		}

		zskCount := standbyKeyCount(zd.DnssecPolicy, false, standbyZskCount)
		kskCount := standbyKeyCount(zd.DnssecPolicy, true, standbyKskCount)

		// RELAXED completeness counts standby ZSKs by ROLE only (algorithm-
		// agnostic): N old-alg standbys satisfy the count, so an algorithm
		// change generates nothing eagerly — the gradual FIFO roll mints the
		// new algorithm only when the count actually drops (a standby was
		// promoted). STRICT keeps per-(role,algorithm) counting (the maintained
		// double-signature shape). See the algorithm-rollover plan §8.3 / D5.
		relaxed := Conf.Internal.Completeness == CompletenessRelaxed
		// A policy that keeps no standby ZSK still rolls: the replacement
		// is minted once the roll comes within the propagation window
		// (propagation-delay plus the served DNSKEY TTL: what published
		// takes to reach standby), so it is standby when the roll fires, as
		// a kept standby would be; the roll promotes it and the count is
		// zero again. A manual request has no lead: the key is minted at
		// the request, and the roll waits out the window.
		if zskCount == 0 && zskReplacementDue(kdb, zoneName, zd.DnssecPolicy, time.Now(), propagationDelay) {
			zskCount = 1
		}
		maintainStandbyKeysForType(ctx, kdb, zoneName, zd.DnssecPolicy.ZSKAlgorithm, "ZSK", 256, zskCount, relaxed)

		// In relaxed mode, cap the standby-ZSK TOTAL (any algorithm) at
		// zskCount: with the algorithm-based deletion skipped, an
		// asap-faster-than-drain or stray extra could otherwise bloat the
		// DNSKEY RRset. Keep the oldest zskCount (FIFO, by published_at),
		// delete the youngest surplus, NEVER by algorithm. Shares the same
		// role-total count as the maintainer above so the two never oscillate.
		if relaxed {
			capStandbyZsksByCount(kdb, zoneName, zskCount)
		}

		if kskCount > 0 && (zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method == RolloverMethodNone) {
			// KSK is always per-(role,algorithm): relaxed mode's role-only
			// discipline is a ZSK-roll property (the ZSK signs the whole zone);
			// a KSK algorithm change is refused, not gradually rolled, here.
			maintainStandbyKeysForType(ctx, kdb, zoneName, zd.DnssecPolicy.KSKAlgorithm, "KSK", 257, kskCount, false)
		}
	}
}

// maintainStandbyKeysForType checks and maintains standby key count for a
// specific key type (ZSK or KSK) in a zone. When roleOnly is true (relaxed-mode
// ZSK), the standby/published pipeline counts are by ROLE (flags) only, not by
// (role, algorithm): N old-algorithm standbys satisfy the count and nothing is
// generated. When false (strict, or any KSK), counts are per-(role, algorithm).
//
// A key generated here is staged PUBLISHED, so it enters the served DNSKEY
// RRset, and the RRSIG over that RRset was made without it: the zone is bogus
// until it is re-signed. Adding a key needs the re-sign as much as removing one
// (#566). The write that stages the key asks for it (#918).
func maintainStandbyKeysForType(ctx context.Context, kdb *KeyDB, zoneName string, alg uint8, keytype string, expectedFlags uint16, standbyKeyCount int, roleOnly bool) {
	standbyKeys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStateStandby)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting standby keys", "zone", zoneName, "keytype", keytype, "err", err)
		return
	}
	standbyCount := countKeysForMaintain(standbyKeys, expectedFlags, alg, roleOnly)

	if standbyCount >= standbyKeyCount {
		return
	}

	publishedKeys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting published keys", "zone", zoneName, "keytype", keytype, "err", err)
		return
	}
	publishedCount := countKeysForMaintain(publishedKeys, expectedFlags, alg, roleOnly)

	if publishedCount > 0 {
		lgSigner.Debug("KeyStateWorker: keys in pipeline, not generating", "zone", zoneName, "keytype", keytype, "pipeline", publishedCount)
		return
	}

	needed := standbyKeyCount - standbyCount
	lgSigner.Info("KeyStateWorker: generating standby keys", "zone", zoneName, "keytype", keytype, "have", standbyCount, "need", standbyKeyCount, "generating", needed)

	generated := 0
	for i := 0; i < needed; i++ {
		// Between keys, not inside one. A half-generated keypair is not a
		// thing that can be abandoned usefully, and each one that IS finished
		// is staged and durable, so stopping here loses nothing: the next tick
		// recounts and mints whatever is still short.
		if ctx.Err() != nil {
			lgSigner.Info("KeyStateWorker: stopping key generation on context cancellation",
				"zone", zoneName, "keytype", keytype, "generated", generated, "wanted", needed)
			break
		}
		keyid, err := GenerateAndStageKey(kdb, zoneName, "key-state-worker", alg, keytype)
		if err != nil {
			lgSigner.Error("KeyStateWorker: key generation failed", "zone", zoneName, "keytype", keytype, "err", err)
			break
		}
		generated++
		lgSigner.Info("KeyStateWorker: generated key", "zone", zoneName, "keytype", keytype, "keyid", keyid)
	}
}

// capStandbyZsksByCount enforces the relaxed-mode standby-ZSK total cap: if more
// than standbyZskCount standby ZSKs (flags=256, any algorithm) exist, delete the
// YOUNGEST surplus (highest published_at), keeping the oldest standbyZskCount.
// GetDnssecKeysByState returns standbys ordered published_at ASC, so the oldest
// (furthest through propagation, next to promote) are kept and only the tail is
// removed. Removal here is safe: a standby key has never signed, so there are no
// RRSIGs to orphan — its only footprint is the DNSKEY RRset. This shares the
// role-total count with maintainStandbyKeysForType(roleOnly=true), so generate
// and cap agree and never oscillate.
func capStandbyZsksByCount(kdb *KeyDB, zoneName string, standbyZskCount int) {
	standbyKeys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStateStandby)
	if err != nil {
		lgSigner.Error("KeyStateWorker: cap: error getting standby keys", "zone", zoneName, "err", err)
		return
	}
	var zsks []DnssecKeyWithTimestamps
	for _, k := range standbyKeys {
		if k.Flags == 256 {
			zsks = append(zsks, k)
		}
	}
	if len(zsks) <= standbyZskCount {
		return
	}
	for _, k := range zsks[standbyZskCount:] {
		lgSigner.Info("KeyStateWorker: relaxed cap: removing youngest surplus standby ZSK",
			"zone", zoneName, "keyid", k.KeyTag, "have", len(zsks), "cap", standbyZskCount,
			"alg", dns.AlgorithmToString[k.Algorithm])
		if err := UpdateDnssecKeyState(kdb, zoneName, k.KeyTag, DnskeyStateRemoved); err != nil {
			lgSigner.Error("KeyStateWorker: cap: remove surplus standby ZSK failed", "zone", zoneName, "keyid", k.KeyTag, "err", err)
		}
	}
}

// countKeysForMaintain counts keys for the standby maintainer. With roleOnly it
// matches by flags (role) only — algorithm-agnostic, the relaxed-mode ZSK shape;
// otherwise it matches flags AND algorithm (strict / KSK).
func countKeysForMaintain(keys []DnssecKeyWithTimestamps, expectedFlags uint16, alg uint8, roleOnly bool) int {
	count := 0
	for _, k := range keys {
		if k.Flags != expectedFlags {
			continue
		}
		if !roleOnly && k.Algorithm != alg {
			continue
		}
		count++
	}
	return count
}

// triggerResign asks the resigner to bring a zone's signatures into line with
// its active keys after a key-state change. Every caller is one -- rollovers,
// the key-state worker, the keystore API -- so the reason is fixed here rather
// than passed in.
func triggerResign(conf *Config, zoneName string) {
	zd, exists := Zones.Get(zoneName)
	// A key state change may have moved a KSK's ds column, which the served
	// DNSKEY RRset does not show; the DS engine decides whether the CDS
	// follows (#752). Owners reach this through TriggerResign.
	if exists {
		conf.Internal.KeyDB.KeysChanged(zd)
	}
	if conf.Internal.ResignQ == nil {
		return
	}

	if !exists {
		lgSigner.Warn("KeyStateWorker: zone not found for re-sign trigger", "zone", zoneName)
		return
	}

	// Marked BEFORE the send, not only on the drop. The request can also be
	// delivered and then fail inside the resigner, and both outcomes leave the
	// zone serving signatures by keys that are no longer active. The resigner
	// clears this only when a replace has actually succeeded.
	zd.markResignPending()

	// A key-row write that changes the served keys asks from the write path
	// (#918), and most callers ask again after it. One queued request covers
	// both: it is taken after both commits.
	if !zd.resignQueued.CompareAndSwap(false, true) {
		lgSigner.Debug("KeyStateWorker: re-sign already queued", "zone", zoneName)
		return
	}

	select {
	case conf.Internal.ResignQ <- ResignRequest{Zd: zd, Reason: ResignKeyStateChanged}:
		lgSigner.Debug("KeyStateWorker: triggered re-sign", "zone", zoneName)
	default:
		zd.resignQueued.Store(false)
		// Dropping used to lose the request outright. The log said it would
		// happen on the next cycle; that stopped being true when the ticker
		// moved from a full rebuild to renewal, because renewal only looks at
		// signature AGE and a post-rollover RRSIG by a retired key is not old.
		// The flag above is what the next cycle now finds.
		lgSigner.Warn("KeyStateWorker: ResignQ full, re-sign deferred to the next resigner pass",
			"zone", zoneName)
	}
}

// zskReplacementDue: the zone's ZSK roll is due, or comes due within the
// propagation window (propagationDelay plus the zone's served DNSKEY TTL,
// what a published key takes to reach standby), so that a zone keeping no
// standby ZSK has its replacement standing by when the roll fires. A
// manual request is due from its own earliest time, with no lead.
func zskReplacementDue(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time, propagationDelay time.Duration) bool {
	if kdb == nil || pol == nil {
		return false
	}
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return false
	}
	var activeAt *time.Time
	found := false
	for i := range active {
		if active[i].Flags == 256 {
			activeAt, found = active[i].ActiveAt, true
			break
		}
	}
	if !found {
		return false
	}
	lead := propagationDelay
	if ttl, known := servedDnskeyTTLForZone(kdb, zone); known {
		lead += ttl
	}
	if due, _ := zskRollDue(now.Add(lead), activeAt, pol.ZSK.Lifetime, ""); due {
		return true
	}
	manual, err := LoadZskManualRollover(kdb, zone)
	if err != nil || manual.Earliest == "" {
		return false
	}
	due, isManual := zskRollDue(now, activeAt, pol.ZSK.Lifetime, manual.Earliest)
	return due && isManual
}
