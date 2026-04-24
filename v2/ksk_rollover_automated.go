package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const (
	rolloverPhaseIdle                 = "idle"
	rolloverPhasePendingParentPush    = "pending-parent-push"
	rolloverPhasePendingParentObserve = "pending-parent-observe"
)

func kskIndexPushNeeded(row *RolloverZoneRow, low, high int, indexOK bool, haveDS bool) bool {
	if !haveDS {
		return false
	}
	if !indexOK {
		return false
	}
	if row == nil || !row.LastSubmittedLow.Valid || !row.LastSubmittedHigh.Valid {
		return true
	}
	return int(row.LastSubmittedLow.Int64) != low || int(row.LastSubmittedHigh.Int64) != high
}

// RolloverAutomatedTick runs one slice of automated KSK rollover for multi-ds (pipeline fill,
// DS push / observe phase machine). double-signature is not implemented yet.
func RolloverAutomatedTick(ctx context.Context, conf *Config, kdb *KeyDB, imr *Imr, zd *ZoneData, now time.Time) error {
	if zd == nil || zd.DnssecPolicy == nil {
		return nil
	}
	pol := zd.DnssecPolicy
	if pol.Rollover.Method == RolloverMethodNone {
		return nil
	}
	if pol.Rollover.Method == RolloverMethodDoubleSignature {
		return nil
	}

	zone := dns.Fqdn(zd.ZoneName)
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}

	num := pol.Rollover.NumDS
	for {
		n, err := CountKskInRolloverPipeline(kdb, zone)
		if err != nil {
			return err
		}
		if n >= num {
			break
		}
		kid, _, err := GenerateKskRolloverCreated(kdb, zone, "key-state-worker", pol.Algorithm, pol.Rollover.Method)
		if err != nil {
			lgSigner.Error("rollover: pipeline KSK generation failed", "zone", zone, "err", err)
			break
		}
		lgSigner.Info("rollover: generated pipeline KSK", "zone", zone, "keyid", kid)
	}

	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	phase := row.RolloverPhase
	if phase == "" {
		phase = rolloverPhaseIdle
	}

	switch phase {
	case rolloverPhaseIdle:
		ds, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, zone, uint8(dns.SHA256))
		if err != nil {
			return err
		}
		if kskIndexPushNeeded(row, low, high, idxOK, len(ds) > 0) {
			if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentPush); err != nil {
				return err
			}
			lgSigner.Info("rollover: arming DS push", "zone", zone)
		}
	case rolloverPhasePendingParentPush:
		if imr == nil {
			lgSigner.Warn("rollover: ImrEngine nil, cannot DS push", "zone", zone)
			return nil
		}
		pushCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		res, err := PushWholeDSRRset(pushCtx, zd, kdb, imr)
		cancel()
		if err != nil {
			lgSigner.Warn("rollover: DS push failed", "zone", zone, "err", err)
			return nil
		}
		if res.Rcode != dns.RcodeSuccess {
			lgSigner.Warn("rollover: DS push non-NOERROR", "zone", zone, "rcode", dns.RcodeToString[res.Rcode])
			return nil
		}
		if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentObserve); err != nil {
			return err
		}
	case rolloverPhasePendingParentObserve:
		agent := pol.Rollover.ParentAgent
		if agent == "" {
			lgSigner.Warn("rollover: parent-agent unset, cannot observe", "zone", zone)
			return nil
		}
		expected, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, zone, uint8(dns.SHA256))
		if err != nil {
			return err
		}
		if len(expected) == 0 {
			if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
				return err
			}
			return nil
		}
		obs, err := QueryParentAgentDS(ctx, zone, agent)
		if err != nil {
			lgSigner.Debug("rollover: parent-agent DS query failed", "zone", zone, "err", err)
			return nil
		}
		if !ObservedDSSetMatchesExpected(obs, expected) {
			return nil
		}
		if !idxOK {
			lgSigner.Warn("rollover: DS observed but rollover_index incomplete for all KSK rows; cannot advance created→ds-published", "zone", zone)
			if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
				return err
			}
			return nil
		}
		if err := saveLastDSConfirmedRange(kdb, zone, low, high); err != nil {
			return fmt.Errorf("rollover: save confirmed range: %w", err)
		}
		created, err := GetDnssecKeysByState(kdb, zone, DnskeyStateCreated)
		if err != nil {
			return err
		}
		for i := range created {
			k := &created[i]
			if k.Flags&dns.SEP == 0 {
				continue
			}
			ri, ok, err := RolloverIndexForKey(kdb, zone, k.KeyTag)
			if err != nil {
				return err
			}
			if !ok || ri < low || ri > high {
				continue
			}
			if err := UpdateDnssecKeyState(kdb, zone, k.KeyTag, DnskeyStateDsPublished); err != nil {
				lgSigner.Warn("rollover: created→ds-published failed", "zone", zone, "keyid", k.KeyTag, "err", err)
				continue
			}
			if err := setRolloverKeyDsObservedAt(kdb, zone, k.KeyTag, now); err != nil {
				lgSigner.Warn("rollover: ds_observed_at", "zone", zone, "keyid", k.KeyTag, "err", err)
			}
			triggerResign(conf, zone)
		}
		if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
			return err
		}
		lgSigner.Info("rollover: parent DS observed, advanced created keys", "zone", zone)
	default:
		if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
			return err
		}
	}
	return nil
}

// TransitionRolloverKskDsPublishedToStandby moves SEP keys from ds-published to standby after propagation delay.
func TransitionRolloverKskDsPublishedToStandby(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateDsPublished)
	if err != nil {
		lgSigner.Error("rollover: list ds-published keys", "err", err)
		return
	}
	for i := range keys {
		k := &keys[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		zd, ok := Zones.Get(k.ZoneName)
		if !ok || zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method != RolloverMethodMultiDS {
			continue
		}
		dsAt, err := rolloverKeyDsObservedAt(kdb, k.ZoneName, k.KeyTag)
		if err != nil || dsAt == nil {
			continue
		}
		if now.Sub(*dsAt) < propagationDelay {
			continue
		}
		if err := UpdateDnssecKeyState(kdb, k.ZoneName, k.KeyTag, DnskeyStateStandby); err != nil {
			lgSigner.Error("rollover: ds-published→standby failed", "zone", k.ZoneName, "keyid", k.KeyTag, "err", err)
			continue
		}
		lgSigner.Info("rollover: ds-published→standby", "zone", k.ZoneName, "keyid", k.KeyTag)
		triggerResign(conf, k.ZoneName)
	}
}

// PromoteStandbyKskIfNoActive activates one standby KSK when the zone has none (bootstrap).
func PromoteStandbyKskIfNoActive(conf *Config, kdb *KeyDB, zone string) {
	zone = dns.Fqdn(zone)
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return
	}
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			return
		}
	}
	standby, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return
	}
	var best *DnssecKeyWithTimestamps
	for i := range standby {
		k := &standby[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		if best == nil || k.KeyTag < best.KeyTag {
			best = k
		}
	}
	if best == nil {
		return
	}
	if err := UpdateDnssecKeyState(kdb, zone, best.KeyTag, DnskeyStateActive); err != nil {
		lgSigner.Error("rollover: standby→active (bootstrap) failed", "zone", zone, "keyid", best.KeyTag, "err", err)
		return
	}
	lgSigner.Info("rollover: promoted standby KSK to active (no active KSK)", "zone", zone, "keyid", best.KeyTag)
	triggerResign(conf, zone)
}

func rolloverAutomatedForAllZones(ctx context.Context, conf *Config, kdb *KeyDB, now time.Time) {
	imr := conf.Internal.ImrEngine
	for _, zd := range Zones.Items() {
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] {
			continue
		}
		if zd.DnssecPolicy == nil {
			continue
		}
		if err := RolloverAutomatedTick(ctx, conf, kdb, imr, zd, now); err != nil {
			lgSigner.Error("rollover: tick error", "zone", zd.ZoneName, "err", err)
		}
	}
}

func promoteStandbyKskBootstrapAll(conf *Config, kdb *KeyDB) {
	for zoneName, zd := range Zones.Items() {
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] || zd.DnssecPolicy == nil {
			continue
		}
		if zd.DnssecPolicy.Rollover.Method != RolloverMethodMultiDS {
			continue
		}
		PromoteStandbyKskIfNoActive(conf, kdb, zoneName)
	}
}
