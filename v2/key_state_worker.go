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
				lgSigner.Warn("kasp.propagation_delay must be positive, using default", "value", kasp.PropagationDelay, "default", defaultPropagationDelay)
			}
		} else {
			lgSigner.Warn("invalid kasp.propagation_delay, using default", "value", kasp.PropagationDelay, "default", defaultPropagationDelay, "err", err)
		}
	}

	checkInterval := defaultCheckInterval
	if kasp.CheckInterval != "" {
		if d, err := time.ParseDuration(kasp.CheckInterval); err == nil {
			if d > 0 {
				checkInterval = d
			} else {
				lgSigner.Warn("kasp.check_interval must be positive, using default", "value", kasp.CheckInterval, "default", defaultCheckInterval)
			}
		} else {
			lgSigner.Warn("invalid kasp.check_interval, using default", "value", kasp.CheckInterval, "default", defaultCheckInterval, "err", err)
		}
	}

	standbyZskCount := defaultStandbyZskCount
	if kasp.StandbyZskCount > 0 {
		standbyZskCount = kasp.StandbyZskCount
	}
	standbyKskCount := defaultStandbyKskCount
	if kasp.StandbyKskCount > 0 {
		standbyKskCount = kasp.StandbyKskCount
	}

	kdb := conf.Internal.KeyDB
	if kdb == nil {
		lgSigner.Warn("KeyStateWorker: no KeyDB available, exiting")
		return nil
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	lgSigner.Info("KeyStateWorker started", "propagation_delay", propagationDelay, "standby_zsk_count", standbyZskCount, "standby_ksk_count", standbyKskCount, "check_interval", checkInterval)

	// Cross-check: any rollover policy whose attempt-timeout (=
	// confirm-timeout, derived from ds-publish-delay × 1.2 by default)
	// is shorter than 2 × check_interval will starve observe polling
	// — the next observe-tick lands past the attempt-timeout cliff
	// before any poll runs. Warn at startup so the operator catches
	// the misconfiguration without first losing a rollover cycle.
	for name, pol := range conf.Internal.DnssecPolicies {
		if pol.Rollover.Method != RolloverMethodMultiDS && pol.Rollover.Method != RolloverMethodDoubleSignature {
			continue
		}
		if pol.Rollover.ConfirmTimeout > 0 && pol.Rollover.ConfirmTimeout < 2*checkInterval {
			lgSigner.Warn("rollover: kasp.check_interval too coarse for policy attempt-timeout; observe polling will be starved",
				"policy", name,
				"attempt_timeout", pol.Rollover.ConfirmTimeout,
				"check_interval", checkInterval,
				"remedy", "lower kasp.check_interval (must be < attempt-timeout / 2) or raise rollover.ds-publish-delay")
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

	rolloverAutomatedForAllZones(ctx, conf, kdb, propagationDelay, now)
	TransitionRolloverKskDsPublishedToPublished(ctx, conf, kdb, now, propagationDelay)
	TransitionRolloverKskPublishedToStandby(ctx, conf, kdb, now, propagationDelay)
	promoteStandbyKskBootstrapAll(conf, kdb)

	transitionPublishedToStandby(conf, kdb, now, propagationDelay)

	rolloverZsksForAllZones(ctx, conf, kdb, propagationDelay, now)

	transitionRetiredToRemoved(ctx, conf, kdb, now, propagationDelay)

	maintainStandbyKeys(conf, kdb, standbyZskCount, standbyKskCount)
}

// transitionPublishedToStandby transitions keys that have been in "published"
// state long enough for the DNSKEY RRset to propagate through all caches.
func transitionPublishedToStandby(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting published keys", "err", err)
		return
	}

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

		elapsed := now.Sub(*key.PublishedAt)
		if elapsed < propagationDelay {
			continue
		}

		lgSigner.Info("KeyStateWorker: transitioning published→standby", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second))
		if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, DnskeyStateStandby); err != nil {
			lgSigner.Error("KeyStateWorker: published→standby failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
			continue
		}

		triggerResign(conf, key.ZoneName)
	}
}

// transitionRetiredToRemoved transitions keys that have been in "retired"
// state long enough for all RRSIGs made with them to expire from caches.
func transitionRetiredToRemoved(ctx context.Context, conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateRetired)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting retired keys", "err", err)
		return
	}

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
				lgSigner.Warn("KeyStateWorker: LoadZoneSigningMaxTTL failed, using propagation_delay only", "zone", key.ZoneName, "err", err)
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
		if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, DnskeyStateRemoved); err != nil {
			lgSigner.Error("KeyStateWorker: retired→removed failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
			continue
		}

		triggerResign(conf, key.ZoneName)
	}
}

// maintainStandbyKeys ensures each signing zone has the configured number of
// standby keys for both ZSKs and KSKs. If a zone has fewer standby keys than
// required and no keys are in the published pipeline, new keys are generated.
func maintainStandbyKeys(conf *Config, kdb *KeyDB, standbyZskCount, standbyKskCount int) {
	for zoneName, zd := range Zones.Items() {
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}

		// MP zones have their own key state worker and their own
		// keystore table (MPDnssecKeyStore). Skip them here.
		if zd.Options[OptMultiProvider] {
			continue
		}

		if zd.DnssecPolicy == nil {
			continue
		}

		// RELAXED completeness counts standby ZSKs by ROLE only (algorithm-
		// agnostic): N old-alg standbys satisfy the count, so an algorithm
		// change generates nothing eagerly — the gradual FIFO roll mints the
		// new algorithm only when the count actually drops (a standby was
		// promoted). STRICT keeps per-(role,algorithm) counting (the maintained
		// double-signature shape). See the algorithm-rollover plan §8.3 / D5.
		relaxed := Conf.Internal.Completeness == CompletenessRelaxed
		maintainStandbyKeysForType(kdb, zoneName, zd.DnssecPolicy.ZSKAlgorithm, "ZSK", 256, standbyZskCount, relaxed)

		// In relaxed mode, cap the standby-ZSK TOTAL (any algorithm) at
		// standbyZskCount: with the algorithm-based deletion skipped, an
		// asap-faster-than-drain or stray extra could otherwise bloat the
		// DNSKEY RRset. Keep the oldest standbyZskCount (FIFO, by published_at),
		// delete the youngest surplus, NEVER by algorithm. Shares the same
		// role-total count as the maintainer above so the two never oscillate.
		if relaxed {
			capStandbyZsksByCount(kdb, zoneName, standbyZskCount)
		}

		if standbyKskCount > 0 && (zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method == RolloverMethodNone) {
			// KSK is always per-(role,algorithm): relaxed mode's role-only
			// discipline is a ZSK-roll property (the ZSK signs the whole zone);
			// a KSK algorithm change is refused, not gradually rolled, here.
			maintainStandbyKeysForType(kdb, zoneName, zd.DnssecPolicy.KSKAlgorithm, "KSK", 257, standbyKskCount, false)
		}
	}
}

// maintainStandbyKeysForType checks and maintains standby key count for a
// specific key type (ZSK or KSK) in a zone. When roleOnly is true (relaxed-mode
// ZSK), the standby/published pipeline counts are by ROLE (flags) only, not by
// (role, algorithm): N old-algorithm standbys satisfy the count and nothing is
// generated. When false (strict, or any KSK), counts are per-(role, algorithm).
func maintainStandbyKeysForType(kdb *KeyDB, zoneName string, alg uint8, keytype string, expectedFlags uint16, standbyKeyCount int, roleOnly bool) {
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
		lgSigner.Debug("KeyStateWorker: keys in pipeline, not generating", "zone", zoneName, "keytype", keytype, "published", publishedCount)
		return
	}

	needed := standbyKeyCount - standbyCount
	lgSigner.Info("KeyStateWorker: generating standby keys", "zone", zoneName, "keytype", keytype, "have", standbyCount, "need", standbyKeyCount, "generating", needed)

	for i := 0; i < needed; i++ {
		keyid, err := GenerateAndStageKey(kdb, zoneName, "key-state-worker", alg, keytype)
		if err != nil {
			lgSigner.Error("KeyStateWorker: key generation failed", "zone", zoneName, "keytype", keytype, "err", err)
			break
		}
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

// triggerResign sends a zone to the ResignQ to trigger a re-sign after key state changes.
func triggerResign(conf *Config, zoneName string) {
	if conf.Internal.ResignQ == nil {
		return
	}

	zd, exists := Zones.Get(zoneName)
	if !exists {
		lgSigner.Warn("KeyStateWorker: zone not found for re-sign trigger", "zone", zoneName)
		return
	}

	select {
	case conf.Internal.ResignQ <- zd:
		lgSigner.Debug("KeyStateWorker: triggered re-sign", "zone", zoneName)
	default:
		lgSigner.Warn("KeyStateWorker: ResignQ full, re-sign will happen on next cycle", "zone", zoneName)
	}
}
