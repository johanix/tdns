/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func APIzone(app *AppDetails, refreshq chan ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zp ZonePost
		err := decoder.Decode(&zp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "zone", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /zone request", "cmd", zp.Command, "from", r.RemoteAddr)

		resp := ZoneResponse{
			Time:    time.Now(),
			AppName: app.Name,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "zone", "err", err)
			}
		}()

		zd, exist := Zones.Get(zp.Zone)
		if !exist && zp.Command != "list-zones" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zp.Zone)
			return
		}
		if zd == nil && zp.Command != "list-zones" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s: zone data is nil", zp.Zone)
			return
		}

		switch zp.Command {
		case "bump":
			// resp.Msg, err = BumpSerial(conf, cp.Zone)

			br, err := zd.BumpSerial()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zp.Zone, br.OldSerial, br.NewSerial)

		case "write-zone":
			msg, err := zd.WriteZone(false, zp.Force)
			resp.Msg = msg
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "sign-zone":
			newrrsigs, err := zd.SignZone(kdb, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: signed with %d new RRSIGs", zd.ZoneName, newrrsigs)

		case "resign-zone":
			newrrsigs, err := zd.ResignZone(kdb)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: resigned, %d RRSIGs written by currently-active keys", zd.ZoneName, newrrsigs)

		case "set-policy":
			resp.Msg, err = setZonePolicy(zd, kdb, zp.Policy)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "generate-nsec":
			err := zd.GenerateNsecChain(kdb)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "show-nsec-chain":
			resp.Names, err = zd.ShowNsecChain()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "freeze":
			// If a zone has modifications, freezing implies that the updated
			// zone data should be written out to disk.
			if !zd.Options[OptAllowUpdates] && !zd.Options[OptAllowChildUpdates] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s does not allow updates. Freeze would be a no-op", zd.ZoneName)
			}

			if zd.Options[OptFrozen] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s is already frozen", zd.ZoneName)
			}

			// zd.mu.Lock()
			zd.SetOption(OptFrozen, true)
			//zd.mu.Unlock()
			if zd.Options[OptDirty] {
				tosource := true
				zd.WriteZone(tosource, false)
				resp.Msg = fmt.Sprintf("Zone %s is now frozen, modifications will be written to disk", zd.ZoneName)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is now frozen", zd.ZoneName)
			}

		case "thaw":
			if !zd.Options[OptAllowUpdates] && !zd.Options[OptAllowChildUpdates] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s does not allow updates. Thaw would be a no-op", zd.ZoneName)
			}
			if !zd.Options[OptFrozen] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s is not frozen", zd.ZoneName)
			}
			zd.SetOption(OptFrozen, false)
			resp.Msg = fmt.Sprintf("Zone %s is now thawed", zd.ZoneName)

		case "reload":
			// XXX: Note: if the zone allows updates and is dirty, then reloading should be denied
			lgApi.Info("reloading zone, will check for delegation data changes")
			// resp.Msg, err = ReloadZone(cp.Zone, cp.Force)
			resp.Msg, err = zd.ReloadZone(refreshq, zp.Force, zp.Wait, zp.Timeout)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "list-zones":
			zones := map[string]ZoneConf{}
			lgApi.Debug("listing zones", "count", len(Zones.Keys()))
			for item := range Zones.IterBuffered() {
				zname := item.Key
				zd := item.Val

				// dump.P(zd.Options)
				options := []ZoneOption{}
				for opt, val := range zd.Options {
					if val {
						options = append(options, opt)
					}
				}

				// For secondary zones, Primary should be the Upstream address, not Parent
				primary := ""
				if zd.ZoneType == Secondary {
					primary = zd.Upstream
				}
				// For primary zones, we could show Parent if needed, but typically Primary field is for secondary zones

				// Effective DNSSEC policy (the one bound to the running zone)
				// and, when it came from a dynamic set-policy override, the
				// config-base policy it overrides (for display). A lookup error
				// degrades that one zone's override flag to false (the listing
				// still succeeds); log it rather than silently swallow.
				_, overridden, ovErr := GetZonePolicyOverride(kdb, zname)
				if ovErr != nil {
					lgApi.Warn("list-zones: failed to read DNSSEC policy override", "zone", zname, "err", ovErr)
				}
				configPolicy := ""
				if overridden {
					// Conf.Zones is replaced wholesale by a config reload;
					// guard the scan with confMu (read lock).
					confMu.RLock()
					for i := range Conf.Zones {
						if dns.Fqdn(Conf.Zones[i].Name) == zname {
							configPolicy = Conf.Zones[i].DnssecPolicy
							break
						}
					}
					confMu.RUnlock()
				}

				zconf := ZoneConf{
					Name:                   zname,
					Type:                   ZoneTypeToString[zd.ZoneType],
					Store:                  ZoneStoreToString[zd.ZoneStore],
					Dirty:                  zd.Options[OptDirty],
					Frozen:                 zd.Options[OptFrozen],
					Options:                options,
					Error:                  zd.Error,
					ErrorType:              zd.ErrorType,
					ErrorMsg:               zd.ErrorMsg,
					RefreshCount:           zd.RefreshCount,
					SourceCatalog:          zd.SourceCatalog,
					Zonefile:               zd.Zonefile,
					Primary:                primary,
					Notify:                 zd.Downstreams, // Notify addresses (displayed by CLI)
					Downstreams:            zd.Downstreams,
					EffectiveDnssecPolicy:  zd.DnssecPolicyName,
					DnssecPolicyOverridden: overridden,
					DnssecPolicyConfigBase: configPolicy,
				}
				zones[zname] = zconf
			}
			resp.Zones = zones

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zp.Command)
			resp.Error = true
		}
	}
}

// setZonePolicy applies a DNSSEC policy to a zone at runtime: it validates the
// named policy, persists a per-zone override (so the change survives restart
// without rewriting the operator's YAML), rebinds the zone to the new policy,
// and re-signs. The re-sign is ADDITIVE (SignZone, not ResignZone): the
// algorithm reconcile in EnsureActiveDnssecKeys retires any wrong-algorithm
// active key and generates one of the new policy's algorithm, while the
// retired key's existing RRSIGs stay in place. The zone is therefore briefly
// double-signed and stays validatable; the KeyStateWorker removes the retired
// keys and strips their RRSIGs after propagation_delay.
func setZonePolicy(zd *ZoneData, kdb *KeyDB, policyName string) (string, error) {
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", fmt.Errorf("set-policy: no policy specified")
	}
	// Snapshot the resolved policy under confMu: a concurrent config reload
	// (ReloadZoneConfig / ReloadZone) replaces Conf.Internal.DnssecPolicies
	// wholesale. pol is a value copy, so we can release the lock immediately
	// and not hold it across the re-sign below.
	confMu.RLock()
	pol, ok := Conf.Internal.DnssecPolicies[policyName]
	confMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("set-policy: DNSSEC policy %q does not exist", policyName)
	}
	if pol.Error != "" {
		return "", fmt.Errorf("set-policy: DNSSEC policy %q is broken: %s", policyName, pol.Error)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return "", fmt.Errorf("set-policy: zone %s is not signed (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// Capture the current policy (pointer + name + algorithms) before rebinding,
	// so we can report the transition, decide whether it double-signs, and
	// restore it if the re-sign fails.
	zd.mu.Lock()
	oldPol := zd.DnssecPolicy
	oldName := zd.DnssecPolicyName
	var oldKSKAlg, oldZSKAlg uint8
	if zd.DnssecPolicy != nil {
		oldKSKAlg, oldZSKAlg = zd.DnssecPolicy.KSKAlgorithm, zd.DnssecPolicy.ZSKAlgorithm
	}
	zd.mu.Unlock()
	// A different algorithm in either role means new keys are introduced
	// alongside the retired old ones — the zone is transiently double-signed.
	algChanged := oldKSKAlg != pol.KSKAlgorithm || oldZSKAlg != pol.ZSKAlgorithm

	// Rebind and re-sign FIRST; only persist the durable override after the
	// re-sign succeeds. Otherwise a sign failure would leave a persisted
	// override (surviving restart) for a policy the zone was never actually
	// signed under. On failure, restore the previous in-memory binding.
	zd.mu.Lock()
	zd.DnssecPolicy = &pol
	zd.DnssecPolicyName = policyName
	zd.mu.Unlock()

	UpdateSigValidityFloor(zd, zd.DnssecPolicy, Conf.KaspPropagationDelay(), 0, false, Conf.IsLargeAlgorithm)

	// Additive sign: reconcile (retire wrong-alg, generate new) + add new-key
	// RRSIGs, leaving the retired keys' RRSIGs in place for a graceful
	// transition.
	newrrsigs, err := zd.SignZone(kdb, true)
	if err != nil {
		zd.mu.Lock()
		zd.DnssecPolicy = oldPol
		zd.DnssecPolicyName = oldName
		zd.mu.Unlock()
		return "", fmt.Errorf("set-policy: re-sign zone %s: %w", zd.ZoneName, err)
	}

	if err := SetZonePolicyOverride(kdb, zd.ZoneName, policyName); err != nil {
		return "", fmt.Errorf("set-policy: zone re-signed but persisting the override failed (the change will not survive restart): %w", err)
	}

	// Build an explicit, multi-line message: a live DNSSEC policy change is
	// intrusive (transient double-signing + divergence from the YAML config),
	// so spell out what happened and what the operator should do.
	var b strings.Builder
	if oldName != "" && oldName != policyName {
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy changed from %q to %q (%d new RRSIGs).\n",
			zd.ZoneName, oldName, policyName, newrrsigs)
	} else {
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy set to %q (%d new RRSIGs).\n",
			zd.ZoneName, policyName, newrrsigs)
	}
	b.WriteString("WARNING: the policy change is stored in the keystore, not the zone config.\n")
	if algChanged {
		b.WriteString("WARNING: this change has caused multiple signatures on RRsets (new keys+sigs added alongside the old).\n")
	}
	fmt.Fprintf(&b, "NOTE #1: update the zone's dnssec_policy in YAML to make %q the permanent policy.", policyName)
	if algChanged {
		fmt.Fprintf(&b, "\nNOTE #2: to clean up keys and signatures from the previous policy use \"... keystore dnssec policy-cleanup -z %s\" (note that this may break DNSSEC validation).", zd.ZoneName)
	}
	return b.String(), nil
}

func APIzoneDsync(ctx context.Context, app *AppDetails, refreshq chan ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zdp ZoneDsyncPost
		err := decoder.Decode(&zdp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "zoneDsync", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /zone/dsync request", "cmd", zdp.Command, "from", r.RemoteAddr)

		resp := ZoneDsyncResponse{
			AppName:   app.Name,
			Time:      time.Now(),
			Functions: map[string]string{},
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "zoneDsync", "err", err)
			}
		}()

		zd, exist := Zones.Get(zdp.Zone)
		if !exist {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %q is unknown", zdp.Zone)
			return
		}

		// Most of the dsync commands relate to the child role. The exception is the publish/unpublish commands
		if !zd.Options[OptDelSyncChild] && zdp.Command != "publish-dsync-rrset" && zdp.Command != "unpublish-dsync-rrset" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %q does not support delegation sync (option delegation-sync-child=false)", zd.ZoneName)
			return
		}

		if zd.Parent == "" {
			if Globals.ImrEngine == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %q: error: ImrEngine not active. Cannot determine parent zone", zd.ZoneName)
				return
			}
			zd.Parent, err = Globals.ImrEngine.ParentZone(zd.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
		}

		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return
		}

		switch zdp.Command {
		case "status":
			keyrrset, err := zd.GetRRset(zd.ZoneName, dns.TypeKEY)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = fmt.Sprintf("Zone %s: current delegation sync status", zdp.Zone)
			if keyrrset != nil && len(keyrrset.RRs) > 0 {
				resp.Functions["SIG(0) key publication"] = "done"
			} else if zd.ZoneType == Secondary {
				if zd.Options[OptDelSyncChild] {
					resp.Functions["SIG(0) key publication"] = "not done; KEY record must be added to zone at primary server"
					resp.Todo = append(resp.Todo, fmt.Sprintf("Add this KEY record to the %s zone at primary server:\n%s", zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs[0].String()))
				} else {
					resp.Functions["SIG(0) key publication"] = "disabled by policy (delegation-sync-child=false)"
				}
			} else if zd.ZoneType == Primary {
				if zd.Options[OptAllowUpdates] {
					resp.Functions["SIG(0) key publication"] = "failed"
				} else {
					resp.Functions["SIG(0) key publication"] = "disabled by policy (allow-updates=false)"

				}
			}

			resp.Functions["Latest delegation sync transaction"] = "successful"
			resp.Functions["Latest delegation sync transaction"] = "successful"
			resp.Functions["Time of latest delegation sync"] = "2024-05-01 12:00:00"
			resp.Functions["Current delegation status"] = fmt.Sprintf("parent \"%s\" is in sync with \"%s\" (the child)", zd.Parent, zd.ZoneName)

		case "bootstrap-sig0-key":
			resp.Msg = fmt.Sprintf("Zone %s: bootstrapping published SIG(0) with parent", zd.ZoneName)
			resp.Msg, resp.UpdateResult, err = zd.BootstrapSig0KeyWithParent(ctx, zdp.Algorithm)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "roll-sig0-key":
			switch zdp.Action {
			case "complete":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent", zd.ZoneName)
			case "add":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: ADDING NEW KEY", zd.ZoneName)
			case "remove":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: REMOVING OLD KEY", zd.ZoneName)
			case "update-local":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: UPDATING LOCAL KEYSTORE", zd.ZoneName)
			}
			resp.Msg, resp.OldKeyID, resp.NewKeyID, resp.UpdateResult, err = zd.RolloverSig0KeyWithParent(ctx, zdp.Algorithm, zdp.Action)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "publish-dsync-rrset":
			resp.Msg = fmt.Sprintf("Zone %s: publishing DSYNC RRset", zd.ZoneName)
			err = zd.PublishDsyncRRs()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "unpublish-dsync-rrset":
			resp.Msg = fmt.Sprintf("Zone %s: unpublishing DSYNC RRset", zd.ZoneName)
			err = zd.UnpublishDsyncRRs()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zdp.Command)
			resp.Error = true
		}
	}
}
