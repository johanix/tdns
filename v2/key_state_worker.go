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
	kasp := &conf.Kasp

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
	TransitionRolloverKskDsPublishedToStandby(conf, kdb, now, propagationDelay)
	promoteStandbyKskBootstrapAll(conf, kdb)

	transitionPublishedToStandby(conf, kdb, now, propagationDelay)

	transitionRetiredToRemoved(conf, kdb, now, propagationDelay)

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
			lgSigner.Warn("KeyStateWorker: published key has no published_at timestamp, skipping", "zone", key.ZoneName, "keyid", key.KeyTag)
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
func transitionRetiredToRemoved(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateRetired)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting retired keys", "err", err)
		return
	}

	for _, key := range keys {
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

		elapsed := now.Sub(*key.RetiredAt)
		if elapsed < propagationDelay {
			continue
		}

		targetState := DnskeyStateRemoved
		lgSigner.Info("KeyStateWorker: transitioning retired→removed", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second))
		if err := UpdateDnssecKeyState(kdb, key.ZoneName, key.KeyTag, targetState); err != nil {
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

		alg := zd.DnssecPolicy.Algorithm

		maintainStandbyKeysForType(kdb, zoneName, alg, "ZSK", 256, standbyZskCount)

		if standbyKskCount > 0 && (zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method == RolloverMethodNone) {
			maintainStandbyKeysForType(kdb, zoneName, alg, "KSK", 257, standbyKskCount)
		}
	}
}

// maintainStandbyKeysForType checks and maintains standby key count for a
// specific key type (ZSK or KSK) in a zone.
func maintainStandbyKeysForType(kdb *KeyDB, zoneName string, alg uint8, keytype string, expectedFlags uint16, standbyKeyCount int) {
	standbyKeys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStateStandby)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting standby keys", "zone", zoneName, "keytype", keytype, "err", err)
		return
	}
	standbyCount := countKeysByFlags(standbyKeys, expectedFlags)

	if standbyCount >= standbyKeyCount {
		return
	}

	publishedKeys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting published keys", "zone", zoneName, "keytype", keytype, "err", err)
		return
	}
	publishedCount := countKeysByFlags(publishedKeys, expectedFlags)

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

// countKeysByFlags counts how many keys in the slice have the expected flags value.
// ZSK: flags=256, KSK/CSK: flags=257.
func countKeysByFlags(keys []DnssecKeyWithTimestamps, expectedFlags uint16) int {
	count := 0
	for _, k := range keys {
		if k.Flags == expectedFlags {
			count++
		}
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
