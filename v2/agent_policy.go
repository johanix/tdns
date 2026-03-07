/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zdr *ZoneDataRepo) EvaluateUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	lgAgent.Debug("evaluating update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.

	switch synchedDataUpdate.UpdateType {
	case "remote":
		// Validate Operations if present
		if len(synchedDataUpdate.Update.Operations) > 0 {
			for _, op := range synchedDataUpdate.Update.Operations {
				rrtype, ok := dns.StringToType[op.RRtype]
				if !ok {
					return false, fmt.Sprintf("Update for zone %q from %q: unknown RR type in operation: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, op.RRtype), nil
				}
				if !AllowedLocalRRtypes[rrtype] {
					return false, fmt.Sprintf("Update for zone %q from %q: disallowed RR type in operation: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, op.RRtype), nil
				}
				for _, rrStr := range op.Records {
					rr, err := dns.NewRR(rrStr)
					if err != nil {
						return false, fmt.Sprintf("Update for zone %q from %q: invalid RR in operation: %s",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrStr), nil
					}
					if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
						return false, fmt.Sprintf("Update for zone %q from %q: RR outside apex in operation: %s",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrStr), nil
					}
				}
			}
		}

		// Validate legacy Records/RRsets
		for _, rrset := range synchedDataUpdate.Update.RRsets {
			for _, rr := range rrset.RRs {
				if !AllowedLocalRRtypes[rr.Header().Rrtype] {
					lgAgent.Warn("invalid RR type", "rr", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR type: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
				if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
					lgAgent.Warn("invalid RR name (outside apex)", "rr", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR name (outside apex): %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
			}
		}

	case "local":
		rrs := append([]dns.RR{}, synchedDataUpdate.Update.RRs...)

		// Check HSYNC nsmgmt policy for NS record operations
		hasNS := false
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
				break
			}
		}
		if hasNS {
			zd, exists := Zones.Get(string(synchedDataUpdate.Zone))
			if !exists {
				return false, fmt.Sprintf("Local update for zone %q: zone not found", synchedDataUpdate.Zone), nil
			}
			apex, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				return false, fmt.Sprintf("Local update for zone %q: cannot get apex: %v", synchedDataUpdate.Zone, err), nil
			}
			hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
			if !exists || len(hsyncRRset.RRs) == 0 {
				return false, fmt.Sprintf("Local update for zone %q: no HSYNC record (NS management not configured)",
					synchedDataUpdate.Zone), nil
			}
			hsync := hsyncRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNC)
			if hsync.NSmgmt != core.HsyncNSmgmtAGENT {
				return false, fmt.Sprintf("Local update for zone %q: HSYNC nsmgmt=%s, NS management not delegated to agents",
					synchedDataUpdate.Zone, core.HsyncNSmgmtToString[hsync.NSmgmt]), nil
			}
		}

		// Must check for (at least): approved RRtype, apex of zone and zone with us in the HSYNC RRset
		for _, rr := range rrs {
			if !AllowedLocalRRtypes[rr.Header().Rrtype] {
				lgAgent.Warn("invalid RR type", "rr", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR type: %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}
			if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
				lgAgent.Warn("invalid RR name (outside apex)", "rr", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR name (outside apex): %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}

			// For local deletes, verify the RR belongs to this agent
			if rr.Header().Class == dns.ClassNONE {
				agentRepo, ok := zdr.Get(synchedDataUpdate.Zone)
				if ok {
					nod, ok := agentRepo.Get(synchedDataUpdate.AgentId)
					if ok {
						rrset, ok := nod.RRtypes.Get(rr.Header().Rrtype)
						if ok {
							checkRR := dns.Copy(rr)
							checkRR.Header().Class = dns.ClassINET
							found := false
							for _, existingRR := range rrset.RRs {
								if dns.IsDuplicate(existingRR, checkRR) {
									found = true
									break
								}
							}
							if !found {
								return false, fmt.Sprintf("Local delete for zone %q: RR not owned by this agent (%s)",
									synchedDataUpdate.Zone, rr.String()), nil
							}
						} else {
							return false, fmt.Sprintf("Local delete for zone %q: no %s RRset owned by this agent",
								synchedDataUpdate.Zone, dns.TypeToString[rr.Header().Rrtype]), nil
						}
					} else {
						return false, fmt.Sprintf("Local delete for zone %q: no data owned by this agent",
							synchedDataUpdate.Zone), nil
					}
				}
			}
		}
	}
	return true, "", nil
}

// Returns change (true/false), msg (string), error (error)
func (zdr *ZoneDataRepo) ProcessUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	var msg string
	var changed bool
	lgAgent.Debug("processing update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	var nar *AgentRepo
	var err error
	var ok bool
	if nar, ok = zdr.Get(synchedDataUpdate.Zone); !ok {
		lgAgent.Debug("creating new agent repo", "zone", synchedDataUpdate.Zone)
		nar, err = NewAgentRepo()
		lgAgent.Debug("new agent repo created")
		if err != nil {
			return false, "", err
		}
		lgAgent.Debug("setting new agent repo", "zone", synchedDataUpdate.Zone)
		zdr.Set(synchedDataUpdate.Zone, nar)
	}

	lgAgent.Debug("agent repo should now exist", "zone", synchedDataUpdate.Zone)
	// Initialize agent data if it doesn't exist
	var nod *OwnerData
	lgAgent.Debug("getting owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	if nod, ok = nar.Get(synchedDataUpdate.AgentId); !ok {
		lgAgent.Debug("creating new owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
		nod = NewOwnerData(string(synchedDataUpdate.Zone))
		nar.Set(synchedDataUpdate.AgentId, nod)
	}

	isLocal := synchedDataUpdate.UpdateType == "local"

	// Process explicit Operations if present (takes precedence over RRsets for remote updates)
	if !isLocal && len(synchedDataUpdate.Update.Operations) > 0 {
		changed, msg = zdr.processOperations(synchedDataUpdate, nar, nod)
		nar.Set(synchedDataUpdate.AgentId, nod)
		zdr.Set(synchedDataUpdate.Zone, nar)
		return changed, msg, nil
	}

	// Iterate through RRsets in the update and only replace those with data
	lgAgent.Debug("iterating through RRsets in the update")
	for rrtype, rrset := range synchedDataUpdate.Update.RRsets {
		if len(rrset.RRs) > 0 {
			lgAgent.Debug("adding RRset to agent", "zone", synchedDataUpdate.Zone,
				"rrtype", dns.TypeToString[rrtype], "agent", synchedDataUpdate.AgentId)
			// XXX: If there are new RRs, then we just replace the existing RRset.
			// nar.Get(update.AgentId).RRtypes.Set(rrtype, rrset)
			cur_rrset, ok := nod.RRtypes.Get(rrtype)
			for _, rr := range rrset.RRs {
				switch rr.Header().Class {
				case dns.ClassANY:
					// ANY = delete entire RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
					} else if isLocal {
						// Local delete: don't remove yet — mark as changed so the
						// delete is sent to combiner/agents. The actual removal
						// happens when the combiner confirms.
						msg = fmt.Sprintf("Requesting removal of %s %s RRset from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						changed = true
					} else {
						// Remote delete: apply immediately (remote agent mirrors
						// originating agent's intent, doesn't own lifecycle).
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						nod.RRtypes.Delete(rrtype)
						// Remove tracking for this entire RRtype
						zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
						changed = true
					}
				case dns.ClassNONE:
					// NONE = delete this RR from the RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s RR %q from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, rr.String(), synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
					} else if isLocal {
						// Local delete: don't remove from repo yet. Keep the RR
						// with ClassNONE intact in the ZoneUpdate so transport
						// sends the delete intent to combiner/agents. The actual
						// removal from the repo happens on combiner confirmation.
						msg = fmt.Sprintf("Requesting removal of %s RR from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						changed = true
					} else {
						// Remote delete: copy the RR before mutating class for
						// local Delete(). The original RR keeps ClassNONE for
						// forwarding to this agent's combiner.
						msg = fmt.Sprintf("Removing %s RR from agent %q (remote)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						delRR := dns.Copy(rr)
						delRR.Header().Class = dns.ClassINET
						cur_rrset.Delete(delRR)
						zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, delRR.String())
						nod.RRtypes.Set(rrtype, cur_rrset)
						changed = true
					}
				case dns.ClassINET:
					// IN = add this RR to the RRset
					if !ok {
						msg = fmt.Sprintf("Adding %s %s RRset to agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						cur_rrset = *rrset.Clone()
						changed = true
					} else {
						for _, rr := range rrset.RRs {
							prevLen := len(cur_rrset.RRs)
							cur_rrset.Add(rr)
							if len(cur_rrset.RRs) > prevLen {
								msg = fmt.Sprintf("Adding RR: %s to RRset", rr.String())
								lgAgent.Debug(msg)
								changed = true
							} else if synchedDataUpdate.Force {
								lgAgent.Debug("RR already present but --force set, marking changed", "rr", rr.String())
								changed = true
							} else {
								lgAgent.Debug("RR already present, skipping", "rr", rr.String())
							}
						}
					}
					nod.RRtypes.Set(rrtype, cur_rrset)
				}
			}
			rrset, ok = nod.RRtypes.Get(rrtype)
			if !ok {
				lgAgent.Debug("RRset does not exist",
					"zone", synchedDataUpdate.Zone, "rrtype", dns.TypeToString[rrtype])
			} else {
				lgAgent.Debug("RRset after addition/deletion",
					"zone", synchedDataUpdate.Zone, "rrtype", dns.TypeToString[rrtype], "rrs", rrset.RRs)
			}
		}
	}
	lgAgent.Debug("setting owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	nar.Set(synchedDataUpdate.AgentId, nod)
	lgAgent.Debug("setting agent repo", "zone", synchedDataUpdate.Zone)
	zdr.Set(synchedDataUpdate.Zone, nar)
	return changed, msg, nil
}

// processOperations handles explicit Operations (add, delete, replace) on a remote update.
// Returns (changed bool, msg string).
func (zdr *ZoneDataRepo) processOperations(synchedDataUpdate *SynchedDataUpdate, nar *AgentRepo, nod *OwnerData) (bool, string) {
	var changed bool
	var msg string

	for _, op := range synchedDataUpdate.Update.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			lgAgent.Warn("unknown RR type in operation, skipping", "rrtype", op.RRtype)
			continue
		}

		switch op.Operation {
		case "replace":
			changed, msg = zdr.processReplaceOp(synchedDataUpdate, nod, rrtype, op)

		case "add":
			curRRset, _ := nod.RRtypes.Get(rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					lgAgent.Warn("invalid RR in add operation, skipping", "rr", rrStr, "err", err)
					continue
				}
				prevLen := len(curRRset.RRs)
				curRRset.Add(rr)
				if len(curRRset.RRs) > prevLen {
					msg = fmt.Sprintf("Added RR via operation: %s", rr.String())
					lgAgent.Debug(msg)
					changed = true
				}
			}
			nod.RRtypes.Set(rrtype, curRRset)

		case "delete":
			curRRset, exists := nod.RRtypes.Get(rrtype)
			if !exists {
				lgAgent.Debug("delete operation: RRset does not exist", "rrtype", op.RRtype)
				continue
			}
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					lgAgent.Warn("invalid RR in delete operation, skipping", "rr", rrStr, "err", err)
					continue
				}
				curRRset.Delete(rr)
				zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, rr.String())
				msg = fmt.Sprintf("Deleted RR via operation: %s", rr.String())
				lgAgent.Debug(msg)
				changed = true
			}
			if len(curRRset.RRs) == 0 {
				nod.RRtypes.Delete(rrtype)
				zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
			} else {
				nod.RRtypes.Set(rrtype, curRRset)
			}

		default:
			lgAgent.Warn("unknown operation type, skipping", "operation", op.Operation)
		}
	}

	return changed, msg
}

// processReplaceOp handles a "replace" operation: makes the agent's RRset for the
// given rrtype match the provided set exactly. RRs in the old set but not in the
// new set are implicitly removed. Empty Records means delete the entire RRset.
func (zdr *ZoneDataRepo) processReplaceOp(synchedDataUpdate *SynchedDataUpdate, nod *OwnerData, rrtype uint16, op core.RROperation) (bool, string) {
	var changed bool
	var msg string

	// Parse all new RRs
	var newRRs []dns.RR
	for _, rrStr := range op.Records {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgAgent.Warn("invalid RR in replace operation, skipping", "rr", rrStr, "err", err)
			continue
		}
		newRRs = append(newRRs, rr)
	}

	oldRRset, hadOld := nod.RRtypes.Get(rrtype)

	// Empty replacement set = delete entire RRset
	if len(newRRs) == 0 {
		if hadOld && len(oldRRset.RRs) > 0 {
			nod.RRtypes.Delete(rrtype)
			zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
			msg = fmt.Sprintf("Replace with empty set: removed %s %s RRset from agent %q",
				synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
			lgAgent.Info(msg)
			changed = true
		}
		return changed, msg
	}

	// Build the new RRset
	var newRRset core.RRset
	for _, rr := range newRRs {
		newRRset.RRs = append(newRRset.RRs, rr)
	}

	// Check if anything actually changed by comparing old and new
	if hadOld {
		// Quick length check
		if len(oldRRset.RRs) != len(newRRset.RRs) {
			changed = true
		} else {
			// Check if all old RRs are in the new set and vice versa
			for _, oldRR := range oldRRset.RRs {
				found := false
				for _, newRR := range newRRset.RRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					changed = true
					break
				}
			}
		}
	} else {
		// No old set — any new RRs means change
		changed = len(newRRs) > 0
	}

	if changed {
		// Remove tracking only for RRs that are being removed by this REPLACE.
		// Surviving RRs keep their tracking state (e.g. ACCEPTED) so they are
		// not regressed to PENDING when MarkRRsPending runs afterwards.
		if hadOld {
			for _, oldRR := range oldRRset.RRs {
				found := false
				for _, newRR := range newRRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, oldRR.String())
				}
			}
		}
		// Set the new RRset
		nod.RRtypes.Set(rrtype, newRRset)
		msg = fmt.Sprintf("Replaced %s %s RRset for agent %q: %d RRs",
			synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId, len(newRRs))
		lgAgent.Info(msg)
	} else {
		msg = fmt.Sprintf("Replace %s %s for agent %q: no change (idempotent)",
			synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
		lgAgent.Debug(msg)
	}

	return changed, msg
}
