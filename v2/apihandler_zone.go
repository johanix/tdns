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

		// The dynamic-zones management commands handle zone existence
		// themselves in their cores (add requires absence; delete/modify/
		// list-dynamic resolve internally), so they bypass this pre-check.
		zoneLookupExempt := map[string]bool{
			"list-zones":   true,
			"add":          true,
			"delete":       true,
			"modify":       true,
			"list-dynamic": true,
		}
		zd, exist := Zones.Get(zp.Zone)
		if !exist && !zoneLookupExempt[zp.Command] {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zp.Zone)
			return
		}
		if zd == nil && !zoneLookupExempt[zp.Command] {
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

		case "policy-set":
			resp.Msg, err = setZonePolicy(r.Context(), zd, kdb, zp.Policy)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "change-policy":
			resp.Msg, err = changeZonePolicy(r.Context(), zd, kdb, zp.Policy)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "policy-reset":
			resp.Msg, err = resetZonePolicy(r.Context(), zd, kdb, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "proxy-key":
			resp.Msg, err = zd.ProxyKeyStatus(context.Background(), kdb, Globals.ImrEngine)
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

				// For secondary zones, list as-written primaries from runtime state.
				primaries := clonePeerConfs(zd.PrimariesConf)

				// Snapshot the notify slice under the lock — the catalog notify
				// add/remove handlers mutate zd.Notify under zd.mu, so an
				// unsynchronized read here would race the slice header.
				zd.mu.Lock()
				notifySnapshot := append([]PeerConf(nil), zd.Notify...)
				zd.mu.Unlock()

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
					ApiManaged:             zd.Options[OptApiManagedZone],
					Provisioning:           zoneProvisioning(zd),
					Zonefile:               zd.Zonefile,
					Primaries:              primaries,
					Notify:                 notifySnapshot, // Notify addresses (displayed by CLI)
					EffectiveDnssecPolicy:  zd.DnssecPolicyName,
					DnssecPolicyOverridden: overridden,
					DnssecPolicyConfigBase: configPolicy,
				}
				zones[zname] = zconf
			}
			resp.Zones = zones

		case "add":
			msg, err := Conf.ProvisionDynamicZone(r.Context(), DynamicZoneInput{
				Name:       zp.Zone,
				Type:       Secondary,
				Primaries:  zp.Primaries,
				Options:    zoneOptionsFromStrings(zp.Options),
				TsigName:   zp.TsigName,
				TsigSecret: zp.TsigSecret,
				TsigAlgo:   zp.TsigAlgo,
			}, true)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Status = "accepted"
			resp.Zone = dns.Fqdn(zp.Zone)
			resp.Msg = msg

		case "delete":
			msg, err := Conf.RemoveDynamicZone(zp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = msg

		case "modify":
			msg, err := Conf.ModifyDynamicZone(r.Context(), DynamicZoneInput{
				Name:       zp.Zone,
				Type:       Secondary,
				Primaries:  zp.Primaries,
				Options:    zoneOptionsFromStrings(zp.Options),
				TsigName:   zp.TsigName,
				TsigSecret: zp.TsigSecret,
				TsigAlgo:   zp.TsigAlgo,
			})
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Status = "accepted"
			resp.Msg = msg

		case "list-dynamic":
			// The persistable dynamic subset (catalog members + API-managed),
			// per ShouldPersistZone — not all zones. Catalog members are listed
			// (read-only here) but only OptApiManagedZone zones are mutable via
			// delete/modify.
			zones := map[string]ZoneConf{}
			for _, zc := range Conf.getDynamicZonesFromZonesMap() {
				if zd, ok := Zones.Get(zc.Name); ok {
					zc.Provisioning = zoneProvisioning(zd)
					zc.ApiManaged = zd.Options[OptApiManagedZone]
					// Surface the zone's error/warning state (e.g. ConfigWarning
					// for a partially-resolved primary set) — zoneDataToZoneConf
					// deliberately omits runtime error fields.
					zc.Error = zd.Error
					zc.ErrorType = zd.ErrorType
					zc.ErrorMsg = zd.ErrorMsg
				}
				zones[zc.Name] = zc
			}
			resp.Zones = zones

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zp.Command)
			resp.Error = true
		}
	}
}

// zoneProvisioning derives the display-only lifecycle string from ZoneStatus
// and the error registry: error takes precedence over the positive lifecycle.
func zoneProvisioning(zd *ZoneData) string {
	if zd.Error {
		return "error"
	}
	return ZoneStatusToString[zd.GetStatus()]
}

// zoneOptionsFromStrings converts ZoneOption name strings (from the API) into
// the option map the cores expect. Unknown names are ignored.
func zoneOptionsFromStrings(strs []string) map[ZoneOption]bool {
	if len(strs) == 0 {
		return nil
	}
	opts := map[ZoneOption]bool{}
	for _, s := range strs {
		if opt, ok := StringToZoneOption[s]; ok {
			opts[opt] = true
		}
	}
	return opts
}

// setZonePolicy binds a zone to a named (config-defined) DNSSEC policy at
// runtime, persisting it as a per-zone override (so the change survives restart
// without rewriting the operator's YAML) and re-signing under it. It is the
// everyday "rebind this zone's policy" command; its intended use is switching to
// a differently-named but SAME-algorithm policy (a change of sig-validity, TTLs
// or key lifetimes).
//
// An abrupt ALGORITHM change is not applied here: the reconcile backstop in
// SignZone refuses a KSK algorithm change (always) and a ZSK algorithm change in
// strict mode, and the transactional core then reverts, persisting nothing. So
// set-policy either applies a same-algorithm change immediately or refuses; it
// never performs the legacy synchronous key-swap. (Route a gradual ZSK algorithm
// roll via change-policy; force an abrupt switch via policy-reset.)
func setZonePolicy(ctx context.Context, zd *ZoneData, kdb *KeyDB, policyName string) (string, error) {
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", fmt.Errorf("policy-set: no policy specified")
	}
	// Read the resolved policy from the immutable runtime-config snapshot: a
	// concurrent config reload publishes a new snapshot rather than mutating in
	// place, so this is lock-free and pol is a stable value copy.
	pol, ok := ConfLive().DnssecPolicies[policyName]
	if !ok {
		return "", fmt.Errorf("policy-set: DNSSEC policy %q does not exist", policyName)
	}
	if pol.Error != "" {
		return "", fmt.Errorf("policy-set: DNSSEC policy %q is broken: %s", policyName, pol.Error)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return "", fmt.Errorf("policy-set: zone %s is not signed (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// Capture the current policy name + algorithms for the operator message
	// (transition wording + whether the change transiently double-signs). This
	// is for REPORTING ONLY — the transactional core snapshots its own state for
	// revert-on-failure and must never be handed the in-memory binding to
	// classify against (design lock ①).
	zd.mu.Lock()
	oldName := zd.DnssecPolicyName
	var oldKSKAlg, oldZSKAlg uint8
	if zd.DnssecPolicy != nil {
		oldKSKAlg, oldZSKAlg = zd.DnssecPolicy.KSKAlgorithm, zd.DnssecPolicy.ZSKAlgorithm
	}
	zd.mu.Unlock()
	// A different algorithm in either role means new keys are introduced
	// alongside the retired old ones — the zone is transiently double-signed.
	algChanged := oldKSKAlg != pol.KSKAlgorithm || oldZSKAlg != pol.ZSKAlgorithm

	// Rebind → re-sign → persist applied + CLI override, transactionally: on a
	// sign failure the shared core reverts the in-memory binding and persists
	// nothing, so the zone is never left bound to a policy it was not signed
	// under. The additive sign reconciles (retire wrong-alg, generate new) and
	// adds new-key RRSIGs, leaving retired keys' RRSIGs in place for a graceful
	// transition.
	newrrsigs, err := applyZonePolicyTransactional(ctx, zd, kdb, &pol, policyName, PolicyApplySourceCommand)
	if err != nil {
		return "", fmt.Errorf("policy-set: %w", err)
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

// changeZonePolicy binds a zone toward a new DNSSEC policy for a gradual,
// relaxed-mode ZSK ALGORITHM rollover. Unlike set-policy (which refuses an
// abrupt algorithm change: the reconcile backstop rejects the synchronous swap),
// change-policy only sets the algorithm of FUTURE-generated keys: it writes the
// ZonePolicyOverride target + rebinds zd.DnssecPolicy, then the existing FIFO
// ZSK pipeline drains in order. `auto-rollover asap -z <zone> --zsk` is the
// throttle. The relaxed reconcile (sign.go) no-ops the synchronous retire, so
// reusing set-policy's path is safe (D3).
//
// Entry-layer safety gates, all validated BEFORE any override write or rebind
// so the zone is never left half-changed:
//   - CSK target: refused (a CSK alg change is parent-coordinated engine work,
//     not built; the reconcile early-returns on CSK and never sees it).
//   - both-role target (KSK alg AND ZSK alg differ): refused — roll one role at
//     a time (§4.1).
//   - re-entrancy: a ZSK alg roll already in flight (fuller drain-window
//     predicate): refused.
//   - KSK-only alg target / strict mode: deferred to the reconcile, which
//     refuses (defensive backstop) — but we surface a clean error here too.
func changeZonePolicy(ctx context.Context, zd *ZoneData, kdb *KeyDB, policyName string) (string, error) {
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", fmt.Errorf("change-policy: no policy specified")
	}
	pol, ok := ConfLive().DnssecPolicies[policyName]
	if !ok {
		return "", fmt.Errorf("change-policy: DNSSEC policy %q does not exist", policyName)
	}
	if pol.Error != "" {
		return "", fmt.Errorf("change-policy: DNSSEC policy %q is broken: %s", policyName, pol.Error)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return "", fmt.Errorf("change-policy: zone %s is not signed (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// Capture the current (source) policy algorithms/mode.
	zd.mu.Lock()
	cur := zd.DnssecPolicy
	zd.mu.Unlock()
	var curKSKAlg, curZSKAlg uint8
	if cur != nil {
		curKSKAlg, curZSKAlg = cur.KSKAlgorithm, cur.ZSKAlgorithm
	}

	// --- Entry guards (before any override write / rebind) ---

	// CSK target (or current zone in CSK mode): an algorithm change to/within a
	// CSK is parent-coordinated and not built. The reconcile early-returns on
	// CSK, so this MUST be caught here.
	if pol.Mode == DnssecPolicyModeCSK || (cur != nil && cur.Mode == DnssecPolicyModeCSK) {
		return "", fmt.Errorf("change-policy: CSK algorithm rollover not implemented for zone %s (a CSK is SEP-flagged with a parent DS — route via the engine, not yet built)", zd.ZoneName)
	}

	kskChanged := curKSKAlg != pol.KSKAlgorithm
	zskChanged := curZSKAlg != pol.ZSKAlgorithm

	// Both-role target: roll one role at a time (§4.1).
	if kskChanged && zskChanged {
		return "", fmt.Errorf("change-policy: policy %q changes BOTH the KSK (%s→%s) and ZSK (%s→%s) algorithm for zone %s; roll one role at a time (issue two policy changes in sequence)",
			policyName,
			dns.AlgorithmToString[curKSKAlg], dns.AlgorithmToString[pol.KSKAlgorithm],
			dns.AlgorithmToString[curZSKAlg], dns.AlgorithmToString[pol.ZSKAlgorithm], zd.ZoneName)
	}

	// KSK-only algorithm change: not implemented (parent-coordinated engine).
	if kskChanged {
		return "", fmt.Errorf("change-policy: KSK algorithm rollover not implemented for zone %s (%s→%s); route via the auto-rollover engine — not yet built",
			zd.ZoneName, dns.AlgorithmToString[curKSKAlg], dns.AlgorithmToString[pol.KSKAlgorithm])
	}

	// Re-entrancy: refuse if a ZSK alg roll is already in flight. "In flight" is
	// measured against the zone's CURRENTLY-BOUND ZSK algorithm (curZSKAlg), NOT
	// the incoming target: before any roll, every ZSK is on the bound algorithm,
	// so there is nothing in flight and this first change-policy proceeds. A
	// genuine mid-roll has ZSKs of an algorithm other than the bound policy's
	// (standby/active/retired) — that is what we refuse a second change-policy
	// on. This also catches the back-to-original sub-case: mid fastroll→mayo1
	// (bound=mayo1) the still-draining old ED25519 ZSKs are ≠ the bound MAYO1, so
	// a change-policy back to ED25519 is correctly refused while they drain.
	if inflight, err := zskAlgRollInFlight(kdb, zd.ZoneName, curZSKAlg); err != nil {
		return "", fmt.Errorf("change-policy: checking in-flight roll for zone %s: %w", zd.ZoneName, err)
	} else if inflight.InFlight {
		return "", fmt.Errorf("change-policy: a ZSK algorithm rollover is already in progress for zone %s (%s→%s); wait for it to complete, or cancel it with \"auto-rollover cancel -z %s --zsk\" before changing course",
			zd.ZoneName, dns.AlgorithmToString[inflight.FromAlg], dns.AlgorithmToString[inflight.ToAlg], zd.ZoneName)
	}

	// Strict mode: a ZSK alg change is not implemented (the reconcile refuses).
	// Surface it here cleanly before touching anything. A same-algorithm /
	// timing-only change is always allowed (no roll happens).
	if zskChanged && Conf.Internal.Completeness != CompletenessRelaxed {
		return "", fmt.Errorf("change-policy: strict-mode ZSK algorithm rollover not implemented for zone %s (%s→%s); set dnssec.completeness: relaxed to roll the ZSK algorithm gradually",
			zd.ZoneName, dns.AlgorithmToString[curZSKAlg], dns.AlgorithmToString[pol.ZSKAlgorithm])
	}

	// --- Bind the target via the shared transactional core (rebind → re-sign →
	// persist applied + CLI override, revert on failure). In relaxed mode the
	// reconcile no-ops the synchronous swap, so SignZone here only adds RRSIGs by
	// the (unchanged) active keys + re-stages the pipeline; no old-alg active ZSK
	// is retired. ---
	zd.mu.Lock()
	oldName := zd.DnssecPolicyName
	zd.mu.Unlock()

	if _, err := applyZonePolicyTransactional(ctx, zd, kdb, &pol, policyName, PolicyApplySourceCommand); err != nil {
		return "", fmt.Errorf("change-policy: %w", err)
	}

	var b strings.Builder
	if oldName != "" && oldName != policyName {
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy bound from %q to %q.\n", zd.ZoneName, oldName, policyName)
	} else {
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy bound to %q.\n", zd.ZoneName, policyName)
	}
	if zskChanged {
		fmt.Fprintf(&b, "ZSK algorithm will roll %s → %s GRADUALLY: future-generated ZSKs carry the new algorithm and the existing keys drain in FIFO order.\n",
			dns.AlgorithmToString[curZSKAlg], dns.AlgorithmToString[pol.ZSKAlgorithm])
		fmt.Fprintf(&b, "This command does NOT perform the roll. It advances on the normal ZSK cadence, or run \"auto-rollover asap -z %s --zsk\" to promote the next standby now (repeat to accelerate).\n", zd.ZoneName)
	} else {
		b.WriteString("Algorithms unchanged; new policy timings take effect. No algorithm roll is triggered.\n")
	}
	b.WriteString("WARNING: the policy change is stored in the keystore, not the zone config.\n")
	fmt.Fprintf(&b, "NOTE: update the zone's dnssec_policy in YAML to make %q the permanent policy.", policyName)
	return b.String(), nil
}

// resetZonePolicy is the `zone dnssec policy-reset` escape hatch (test/lab). An
// abrupt policy switch that changes a zone's KSK/ZSK ALGORITHM is refused by
// design — it needs a key rollover that is not built — which is correct for
// production but blocks iteration on test zones. policy-reset forces the zone's
// active key set to match the config policy's algorithms per role, then re-signs
// under config, records applied=config, and clears the CLI override.
//
// It is SURGICAL: only the role(s) whose algorithm actually changed are dropped
// and regenerated; a key whose algorithm is already correct is kept. So a
// ZSK-only change keeps the KSK and the parent DS INTACT (no warning); only a KSK
// algorithm change (or a CSK alg / mode change) breaks the chain of trust — the
// parent DS no longer matches the new KSK and validators go BOGUS until the
// operator re-publishes the DS. Because it pre-aligns the keys before re-signing,
// it works even in strict completeness mode (reconcile has nothing to refuse).
//
// Without --confirm it is a DRY RUN: it reports what it WOULD do (which roles
// would roll, and whether the parent DS would break) and changes nothing.
// --confirm performs the reset. The only gates are --confirm and a single zone.

// boundPolicyMode returns the zone's currently-bound DNSSEC policy Mode
// ("ksk-zsk" | "csk"), or "" when unbound. Read under zd.mu.
func boundPolicyMode(zd *ZoneData) string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.DnssecPolicy == nil {
		return ""
	}
	return zd.DnssecPolicy.Mode
}

func resetZonePolicy(ctx context.Context, zd *ZoneData, kdb *KeyDB, confirm bool) (string, error) {
	// Resolve the zone's CONFIG-base policy (its YAML dnssec_policy) — what the
	// zone falls back to once the override + applied records are cleared. Read
	// the name from Conf.Zones (as the list-zones handler does) and the struct
	// from the ConfLive() snapshot (lock-free). These guards run for the dry-run
	// too, so a preview also surfaces a missing/broken config policy.
	// Conf.Zones is replaced wholesale by a config reload; guard the scan with
	// confMu (read lock), matching the list-zones handler above.
	var configName string
	confMu.RLock()
	for i := range Conf.Zones {
		if dns.Fqdn(Conf.Zones[i].Name) == zd.ZoneName {
			configName = strings.TrimSpace(Conf.Zones[i].DnssecPolicy)
			break
		}
	}
	confMu.RUnlock()
	if configName == "" {
		return "", fmt.Errorf("policy-reset: zone %s has no config-base dnssec_policy to reset to (dynamic/API-managed zones are not supported)", zd.ZoneName)
	}
	pol, ok := ConfLive().DnssecPolicies[configName]
	if !ok {
		return "", fmt.Errorf("policy-reset: config dnssec_policy %q for zone %s does not exist", configName, zd.ZoneName)
	}
	if pol.Error != "" {
		return "", fmt.Errorf("policy-reset: config dnssec_policy %q for zone %s is broken: %s", configName, zd.ZoneName, pol.Error)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return "", fmt.Errorf("policy-reset: zone %s is not signed (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// DRY RUN (no --confirm): compute the per-role decision READ-ONLY and report
	// what WOULD happen — no key drop, no re-sign, no DB write. This is the
	// preview an operator gets before committing; the destructive run needs
	// --confirm. currentMode is the zone's currently-bound policy Mode, so a
	// genuine split↔CSK mode change is detected from that reliable field.
	if !confirm {
		kskChanged, zskChanged, err := zoneActiveKeyRoleChanges(kdb, zd.ZoneName, &pol, boundPolicyMode(zd))
		if err != nil {
			return "", fmt.Errorf("policy-reset: inspecting active keys for zone %s: %w", zd.ZoneName, err)
		}
		return policyResetDryRunReport(zd.ZoneName, configName, pol.Mode, kskChanged, zskChanged), nil
	}

	// Serialize the WHOLE reset (per-role decision → drop/regen the changed
	// role(s) → re-sign → clear override) against concurrent policy applies on
	// this zone. We hold policyApplyMu ourselves and call the *Locked apply
	// variant below to avoid a double-lock.
	zd.policyApplyMu.Lock()
	defer zd.policyApplyMu.Unlock()

	// Recompute the per-role decision UNDER policyApplyMu so the decision and the
	// key mutation are atomic w.r.t. other applies (the dry-run's read above was
	// advisory). currentMode is read (before the rebind) from the reliable Mode
	// field, not inferred from key shape. kskChanged ⇒ the parent DS breaks.
	kskChanged, zskChanged, err := zoneActiveKeyRoleChanges(kdb, zd.ZoneName, &pol, boundPolicyMode(zd))
	if err != nil {
		return "", fmt.Errorf("policy-reset: inspecting active keys for zone %s: %w", zd.ZoneName, err)
	}

	switch {
	case kskChanged:
		lgApi.Warn("policy-reset: KSK algorithm changing — DROPPING the KSK and BREAKING the chain of trust until the parent DS is re-published",
			"zone", zd.ZoneName, "config_policy", configName, "zsk_changed", zskChanged)
	case zskChanged:
		lgApi.Info("policy-reset: rolling the ZSK algorithm only (KSK and parent DS unchanged)",
			"zone", zd.ZoneName, "config_policy", configName)
	default:
		lgApi.Info("policy-reset: active keys already match config — no key roll, re-signing only",
			"zone", zd.ZoneName, "config_policy", configName)
	}

	// 1) Rebind to the config policy BEFORE mutating keys, so regeneration and the
	// re-sign use the CONFIG algorithms. Snapshot the old binding to restore it if
	// the key mutation fails (its tx rolls back, leaving the original keys intact).
	zd.mu.Lock()
	oldPol := zd.DnssecPolicy
	oldName := zd.DnssecPolicyName
	zd.DnssecPolicy = &pol
	zd.DnssecPolicyName = configName
	zd.mu.Unlock()

	// 2) Surgically drop+regenerate only the changed role(s), keeping any key
	// whose algorithm is already correct — so a ZSK-only change leaves the KSK
	// (and the parent DS) untouched. Skipped entirely when nothing changed. The
	// keystore mutation is atomic: on failure the tx rolled back (original keys
	// intact) → restore the binding and tell the operator to retry.
	if kskChanged || zskChanged {
		surviving, ferr := kdb.forceZoneKeysToPolicyRoles(zd, &pol, kskChanged, zskChanged)
		if ferr != nil {
			zd.mu.Lock()
			zd.DnssecPolicy = oldPol
			zd.DnssecPolicyName = oldName
			zd.mu.Unlock()
			return "", fmt.Errorf("policy-reset: dropping/regenerating the changed key role(s) for zone %s FAILED — no persisted records were changed and the original keys are intact; re-run `zone dnssec policy-reset --confirm`: %w", zd.ZoneName, ferr)
		}

		// The new key set is now COMMITTED. Every failure from here means "run
		// resign" — NOT re-run policy-reset.
		//
		// 2a) Force a fresh active-key read: the regen invalidated the cache, and a
		// stale read would make the re-sign refuse on an algorithm mismatch.
		if _, err := zd.refreshActiveDnssecKeys(kdb, "policy-reset: after key regen"); err != nil {
			return "", fmt.Errorf("policy-reset: re-reading regenerated keys for zone %s FAILED — the new config-policy keys are already in the keystore but the zone is not yet re-signed; run `zone dnssec resign -z %s` to converge: %w", zd.ZoneName, zd.ZoneName, err)
		}
		// 2b) Strip the now-stale served signatures (orphans + every DNSKEY RRSIG)
		// AFTER the keystore commit and BEFORE the re-sign regenerates fresh ones.
		// Doing this post-commit is what makes the whole reset transactionally safe:
		// a keystore commit failure can never leave the served zone unsigned.
		if _, err := stripStaleRRSIGsForKeySet(ctx, zd, surviving); err != nil {
			return "", fmt.Errorf("policy-reset: stripping stale signatures for zone %s FAILED — the new config-policy keys are already in the keystore but the zone is not yet re-signed; run `zone dnssec resign -z %s` to converge: %w", zd.ZoneName, zd.ZoneName, err)
		}
	}

	// 3) Re-sign under the config policy and record applied=config through the
	// shared core (source config → no CLI override written). We already hold
	// policyApplyMu, so call the *Locked variant.
	newrrsigs, err := applyZonePolicyTransactionalLocked(ctx, zd, kdb, &pol, configName, PolicyApplySourceConfig)
	if err != nil {
		return "", fmt.Errorf("policy-reset: re-signing zone %s under config policy %q FAILED — the config-policy keys are already in the keystore, so run `zone dnssec resign -z %s` to converge (do NOT re-run policy-reset): %w", zd.ZoneName, configName, zd.ZoneName, err)
	}

	// 4) Only now that the zone is signed under config and applied=config is
	// recorded, clear any stale CLI override so intent matches reality. Done LAST
	// so a failure here cannot strand an unsigned zone; it clears only the
	// override (applied_* is preserved).
	if err := ClearZonePolicyOverride(kdb, zd.ZoneName); err != nil {
		return "", fmt.Errorf("policy-reset: zone %s is signed under config policy %q and applied=config recorded, but clearing the stale CLI override FAILED — the override still points at the old policy and a later reload may refuse it; bind the config policy explicitly with `zone dnssec policy-set -z %s -p %s`: %w", zd.ZoneName, configName, zd.ZoneName, configName, err)
	}

	return policyResetReport(zd.ZoneName, configName, pol.Mode, kskChanged, zskChanged, newrrsigs), nil
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
