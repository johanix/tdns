/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Automated ZSK rollover: age-based pre-publish roll driven by ZSK.Lifetime.
 */

package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// zskRollDue reports whether an active ZSK has lived past policy.ZSK.Lifetime.
func zskRollDue(now time.Time, activeAt *time.Time, lifetimeSec uint32) bool {
	if lifetimeSec == 0 || activeAt == nil {
		return false
	}
	lifetime := time.Duration(lifetimeSec) * time.Second
	return now.Sub(*activeAt) >= lifetime
}

// zskRemovalMargin is the hold time before a retired ZSK may be removed:
// propagationDelay + max observed signing TTL (sum, not max).
func zskRemovalMargin(propagationDelay time.Duration, maxObservedTTL uint32) time.Duration {
	margin := propagationDelay
	if maxObservedTTL > 0 {
		margin += time.Duration(maxObservedTTL) * time.Second
	}
	return margin
}

// rolloverZsksForAllZones runs automated ZSK rollover for every eligible zone.
// Invoked from KeyStateWorker after published→standby and before retired→removed.
func rolloverZsksForAllZones(ctx context.Context, conf *Config, kdb *KeyDB, propagationDelay time.Duration, now time.Time) {
	for _, zd := range Zones.Items() {
		if ctx.Err() != nil {
			return
		}
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] {
			continue
		}
		pol := zd.DnssecPolicy
		if pol == nil || pol.Mode != DnssecPolicyModeKSKZSK || pol.ZSK.Lifetime == 0 {
			continue
		}
		if err := rolloverZskForZone(ctx, conf, kdb, zd, propagationDelay, now); err != nil {
			lgSigner.Error("zsk rollover: tick error", "zone", zd.ZoneName, "err", err)
		}
	}
}

func rolloverZskForZone(ctx context.Context, conf *Config, kdb *KeyDB, zd *ZoneData, propagationDelay time.Duration, now time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	pol := zd.DnssecPolicy
	zone := dns.Fqdn(zd.ZoneName)

	release, err := defaultAcquireRolloverLock(zone)
	if err != nil {
		lgSigner.Debug("zsk rollover: lock acquisition skipped", "zone", zone, "err", err)
		return nil
	}
	defer release()

	activeKeys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return fmt.Errorf("list active keys: %w", err)
	}
	var activeZSK *DnssecKeyWithTimestamps
	for i := range activeKeys {
		if activeKeys[i].Flags == 256 {
			activeZSK = &activeKeys[i]
			break
		}
	}
	if activeZSK == nil {
		return nil
	}

	if !zskRollDue(now, activeZSK.ActiveAt, pol.ZSK.Lifetime) {
		return nil
	}

	standbyKeys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return fmt.Errorf("list standby keys: %w", err)
	}
	haveStandby := false
	for i := range standbyKeys {
		if standbyKeys[i].Flags == 256 {
			haveStandby = true
			break
		}
	}
	if !haveStandby {
		lgSigner.Warn("zsk rollover: roll due but no standby ZSK available", "zone", zone, "active_keyid", activeZSK.KeyTag)
		return nil
	}

	oldActive, newActive, err := kdb.RolloverKey(zone, "ZSK", nil)
	if err != nil {
		return fmt.Errorf("RolloverKey: %w", err)
	}
	lgSigner.Info("zsk rollover: completed", "zone", zone, "old_active", oldActive, "new_active", newActive)
	triggerResign(conf, zd.ZoneName)
	return nil
}
