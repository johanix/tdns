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
)

const (
	defaultPropagationDelay = 1 * time.Hour
	defaultCheckInterval    = 1 * time.Minute
	defaultStandbyKeyCount  = 1
)

// KeyStateWorker runs periodic checks on DNSSEC key states and performs
// automatic transitions and standby key maintenance.
func KeyStateWorker(ctx context.Context, conf *Config) error {
	kasp := &conf.Kasp

	propagationDelay := defaultPropagationDelay
	if kasp.PropagationDelay != "" {
		if d, err := time.ParseDuration(kasp.PropagationDelay); err == nil {
			propagationDelay = d
		} else {
			lgSigner.Warn("invalid kasp.propagation_delay, using default", "value", kasp.PropagationDelay, "default", defaultPropagationDelay, "err", err)
		}
	}

	checkInterval := defaultCheckInterval
	if kasp.CheckInterval != "" {
		if d, err := time.ParseDuration(kasp.CheckInterval); err == nil {
			checkInterval = d
		} else {
			lgSigner.Warn("invalid kasp.check_interval, using default", "value", kasp.CheckInterval, "default", defaultCheckInterval, "err", err)
		}
	}

	standbyKeyCount := defaultStandbyKeyCount
	if kasp.StandbyKeyCount > 0 {
		standbyKeyCount = kasp.StandbyKeyCount
	}

	kdb := conf.Internal.KeyDB
	if kdb == nil {
		lgSigner.Warn("KeyStateWorker: no KeyDB available, exiting")
		return nil
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	lgSigner.Info("KeyStateWorker started", "propagation_delay", propagationDelay, "standby_key_count", standbyKeyCount, "check_interval", checkInterval)

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("KeyStateWorker stopping")
			return nil
		case <-ticker.C:
			checkAndTransitionKeys(conf, kdb, propagationDelay, standbyKeyCount)
		}
	}
}

// checkAndTransitionKeys performs all periodic key state checks:
// 1. published → standby (time-based)
// 2. retired → removed (time-based)
// 3. maintain standby key count (generate new keys as needed)
func checkAndTransitionKeys(conf *Config, kdb *KeyDB, propagationDelay time.Duration, standbyKeyCount int) {
	now := time.Now()

	// (1) Check published → standby transitions
	transitionPublishedToStandby(conf, kdb, now, propagationDelay)

	// (2) Check retired → removed transitions
	transitionRetiredToRemoved(conf, kdb, now, propagationDelay)

	// (3) Maintain standby key count per zone
	maintainStandbyKeys(conf, kdb, standbyKeyCount)
}

// transitionPublishedToStandby transitions keys that have been in "published"
// state long enough for the DNSKEY RRset to propagate through all caches.
func transitionPublishedToStandby(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := kdb.GetDnssecKeysByState("", DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting published keys", "err", err)
		return
	}

	for _, key := range keys {
		if key.PublishedAt == nil {
			lgSigner.Warn("KeyStateWorker: published key has no published_at timestamp, skipping", "zone", key.ZoneName, "keyid", key.KeyTag)
			continue
		}

		elapsed := now.Sub(*key.PublishedAt)
		if elapsed < propagationDelay {
			continue
		}

		lgSigner.Info("KeyStateWorker: transitioning published→standby", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second))
		if err := kdb.UpdateDnssecKeyState(key.ZoneName, key.KeyTag, DnskeyStateStandby); err != nil {
			lgSigner.Error("KeyStateWorker: published→standby failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
			continue
		}

		triggerResign(conf, key.ZoneName)
	}
}

// transitionRetiredToRemoved transitions keys that have been in "retired"
// state long enough for all RRSIGs made with them to expire from caches.
func transitionRetiredToRemoved(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := kdb.GetDnssecKeysByState("", DnskeyStateRetired)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting retired keys", "err", err)
		return
	}

	for _, key := range keys {
		if key.RetiredAt == nil {
			lgSigner.Warn("KeyStateWorker: retired key has no retired_at timestamp, skipping", "zone", key.ZoneName, "keyid", key.KeyTag)
			continue
		}

		elapsed := now.Sub(*key.RetiredAt)
		if elapsed < propagationDelay {
			continue
		}

		lgSigner.Info("KeyStateWorker: transitioning retired→removed", "zone", key.ZoneName, "keyid", key.KeyTag, "elapsed", elapsed.Truncate(time.Second))
		if err := kdb.UpdateDnssecKeyState(key.ZoneName, key.KeyTag, DnskeyStateRemoved); err != nil {
			lgSigner.Error("KeyStateWorker: retired→removed failed", "zone", key.ZoneName, "keyid", key.KeyTag, "err", err)
			continue
		}

		triggerResign(conf, key.ZoneName)
	}
}

// maintainStandbyKeys ensures each signing zone has the configured number of
// standby keys for both ZSKs and KSKs. If a zone has fewer standby keys than
// required and no keys are in the pipeline (published or mpdist), new keys
// are generated via GenerateAndStageKey.
func maintainStandbyKeys(conf *Config, kdb *KeyDB, standbyKeyCount int) {
	for zoneName, zd := range Zones.Items() {
		// Only process zones that do signing
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}

		// Skip multi-provider zones where we are not a signer
		if zd.Options[OptMultiProvider] {
			shouldSign, _ := zd.weAreASigner()
			if !shouldSign {
				continue
			}
		}

		if zd.DnssecPolicy == nil {
			continue
		}

		isMP := zd.Options[OptMultiProvider]
		alg := zd.DnssecPolicy.Algorithm

		// Maintain ZSK standby count
		maintainStandbyKeysForType(kdb, zoneName, alg, "ZSK", 256, isMP, standbyKeyCount)

		// Maintain KSK standby count
		maintainStandbyKeysForType(kdb, zoneName, alg, "KSK", 257, isMP, standbyKeyCount)
	}
}

// maintainStandbyKeysForType checks and maintains standby key count for a
// specific key type (ZSK or KSK) in a zone.
func maintainStandbyKeysForType(kdb *KeyDB, zoneName string, alg uint8, keytype string, expectedFlags uint16, isMP bool, standbyKeyCount int) {
	// Count standby keys of this type
	standbyKeys, err := kdb.GetDnssecKeysByState(zoneName, DnskeyStateStandby)
	if err != nil {
		lgSigner.Error("KeyStateWorker: error getting standby keys", "zone", zoneName, "keytype", keytype, "err", err)
		return
	}
	standbyCount := countKeysByFlags(standbyKeys, expectedFlags)

	if standbyCount >= standbyKeyCount {
		return // Already have enough
	}

	// Check pipeline: don't generate if published or mpdist keys exist for this type
	publishedKeys, _ := kdb.GetDnssecKeysByState(zoneName, DnskeyStatePublished)
	publishedCount := countKeysByFlags(publishedKeys, expectedFlags)

	mpdistKeys, _ := kdb.GetDnssecKeysByState(zoneName, DnskeyStateMpdist)
	mpdistCount := countKeysByFlags(mpdistKeys, expectedFlags)

	if publishedCount > 0 || mpdistCount > 0 {
		lgSigner.Debug("KeyStateWorker: keys in pipeline, not generating", "zone", zoneName, "keytype", keytype, "published", publishedCount, "mpdist", mpdistCount)
		return
	}

	needed := standbyKeyCount - standbyCount
	lgSigner.Info("KeyStateWorker: generating standby keys", "zone", zoneName, "keytype", keytype, "have", standbyCount, "need", standbyKeyCount, "generating", needed)

	for i := 0; i < needed; i++ {
		keyid, err := kdb.GenerateAndStageKey(zoneName, "key-state-worker", alg, keytype, isMP)
		if err != nil {
			lgSigner.Error("KeyStateWorker: key generation failed", "zone", zoneName, "keytype", keytype, "err", err)
			break
		}
		lgSigner.Info("KeyStateWorker: generated key", "zone", zoneName, "keytype", keytype, "keyid", keyid, "mp", isMP)
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
