/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Combiner business logic for multi-provider DNSSEC coordination (HSYNC).
 * Receives sync updates from agents and applies them to zones.
 *
 * Transport handling (CHUNK NOTIFY routing, EDNS0 extraction, decryption) is
 * handled by the unified ChunkNotifyHandler in agent/transport/. This file
 * contains only combiner-specific business logic: sync parsing, update
 * processing (ClassINET/ClassNONE/ClassANY), policy checks, and the
 * registration functions that wire ChunkNotifyHandler for combiner/signer roles.
 */

package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgCombiner = Logger("combiner")

// CombinerSyncRequest represents a sync request to the combiner.
// Uses the same data structure as CombinerPost.Data for transport neutrality.
type CombinerSyncRequest struct {
	SenderID       string                   // Identity of the sending agent
	DeliveredBy    string                   // Identity of the agent that delivered this to the combiner
	Zone           string                   // Zone being updated
	ZoneClass      string                   // "mp" (default) or "provider"
	SyncType       string                   // Type of sync: "NS", "DNSKEY", "CDS", "CSYNC", "GLUE"
	Records        map[string][]string      // RR strings grouped by owner name (same as CombinerPost.Data)
	Operations     []core.RROperation       // Explicit operations (takes precedence over Records)
	Publish        *core.PublishInstruction // KEY/CDS publication instruction
	Serial         uint32                   // Zone serial (optional)
	DistributionID string                   // Distribution ID for tracking
	Timestamp      time.Time                // When the request was created
}

// CombinerSyncResponse represents a confirmation from the combiner.
type CombinerSyncResponse struct {
	DistributionID string         // Echoed from request
	Zone           string         // Zone that was updated
	Nonce          string         // Echoed nonce from the incoming sync/update message
	Status         string         // "ok", "partial", "error"
	Message        string         // Human-readable message
	AppliedRecords []string       // RRs that were successfully applied (additions)
	RemovedRecords []string       // RRs that were successfully removed (deletions)
	RejectedItems  []RejectedItem // Items that were rejected with reasons
	Timestamp      time.Time      // When the response was created
	DataChanged    bool           // True when zone data was actually mutated (not idempotent re-apply)
}

// RejectedItem describes an RR that was rejected and why.
type RejectedItem struct {
	Record string // The RR string
	Reason string // Why it was rejected
}

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// detectDelegationChanges inspects a CombinerSyncResponse for changes
// to NS records or KSK DNSKEYs (flags=257, SEP bit). These changes
// require parent delegation synchronization.
func detectDelegationChanges(resp *CombinerSyncResponse) (nsChanged, kskChanged bool) {
	for _, rr := range append(resp.AppliedRecords, resp.RemovedRecords...) {
		parsed, err := dns.NewRR(rr)
		if err != nil {
			continue
		}
		switch parsed.Header().Rrtype {
		case dns.TypeNS:
			nsChanged = true
		case dns.TypeDNSKEY:
			if dk, ok := parsed.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					kskChanged = true
				}
			}
		}
	}
	return
}

// CombinerState holds combiner-specific state that outlives individual CHUNK messages.
// Used by CLI commands (error journal queries) and in-process SendToCombiner.
// Transport routing is handled by the unified ChunkNotifyHandler.
type CombinerState struct {
	// ErrorJournal records errors during CHUNK NOTIFY processing for operational diagnostics.
	// Queried via "transaction errors" CLI commands. If nil, errors are only logged.
	ErrorJournal *ErrorJournal

	// ProtectedNamespaces: domain suffixes belonging to this provider.
	// NS records from remote agents whose targets fall within these namespaces are rejected.
	ProtectedNamespaces []string

	// chunkHandler is the underlying ChunkNotifyHandler (internal wiring).
	// Access is via SetRouter/SetGetPeerAddress/SetSecureWrapper.
	chunkHandler *transport.ChunkNotifyHandler
}

// ChunkHandler returns the underlying ChunkNotifyHandler for wiring into TransportManager.
func (cs *CombinerState) ChunkHandler() *transport.ChunkNotifyHandler {
	return cs.chunkHandler
}

// ProcessUpdate delegates to the standalone CombinerProcessUpdate.
func (cs *CombinerState) ProcessUpdate(req *CombinerSyncRequest, localAgents map[string]bool, kdb *KeyDB, tm *MPTransportBridge) *CombinerSyncResponse {
	return CombinerProcessUpdate(req, cs.ProtectedNamespaces, localAgents, kdb, tm)
}

// --- Standalone business logic functions ---

// RecordCombinerError records an error in the ErrorJournal if available.
func RecordCombinerError(journal *ErrorJournal, distID, sender, messageType, errMsg, qname string) {
	if journal == nil {
		return
	}
	journal.Record(ErrorJournalEntry{
		DistributionID: distID,
		Sender:         sender,
		MessageType:    messageType,
		ErrorMsg:       errMsg,
		QNAME:          qname,
		Timestamp:      time.Now(),
	})
}

// ParseAgentMsgNotify parses a sync payload into a CombinerSyncRequest.
// Expects the standard AgentMsgPost format (OriginatorID/Zone/Records).
func ParseAgentMsgNotify(data []byte, distributionID string) (*CombinerSyncRequest, error) {
	var msg struct {
		OriginatorID string                   `json:"OriginatorID"`
		Zone         string                   `json:"Zone"`
		ZoneClass    string                   `json:"ZoneClass"`
		Records      map[string][]string      `json:"Records"`
		Operations   []core.RROperation       `json:"Operations"`
		Publish      *core.PublishInstruction `json:"Publish,omitempty"`
		Time         time.Time                `json:"Time"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if msg.OriginatorID == "" {
		return nil, fmt.Errorf("missing OriginatorID")
	}
	if msg.Zone == "" && msg.ZoneClass != "provider" {
		return nil, fmt.Errorf("missing Zone")
	}

	records := msg.Records
	if records == nil {
		records = make(map[string][]string)
	}

	rrCount := 0
	for _, rrs := range records {
		rrCount += len(rrs)
	}
	lgCombiner.Debug("parsed sync", "sender", msg.OriginatorID, "zone", msg.Zone, "rrs", rrCount, "owners", len(records))

	return &CombinerSyncRequest{
		SenderID:       msg.OriginatorID,
		Zone:           msg.Zone,
		ZoneClass:      msg.ZoneClass,
		Records:        records,
		Operations:     msg.Operations,
		Publish:        msg.Publish,
		DistributionID: distributionID,
		Timestamp:      msg.Time,
	}, nil
}

// CombinerProcessUpdate handles a sync request and returns a response.
// This is the main entry point for CHUNK-based and API-based updates to the combiner.
// Both transports use the same data structure (map[string][]string) for transport neutrality.
//
// RR class determines the operation:
//   - ClassINET: add/update the RR (existing behavior)
//   - ClassNONE: delete this specific RR from the agent's contributions
//   - ClassANY:  delete the entire RRset for the RR's type from the agent's contributions
//
// findProviderZoneForRequest finds the best-matching zone for a provider update
// that did not specify a zone. It examines owner names from Operations and Records,
// finds the most specific zone in Zones that contains each owner, and returns an
// error if no matching zone exists or if the matched zone is not a configured
// provider zone.
func findProviderZoneForRequest(req *CombinerSyncRequest) (string, error) {
	// Collect all owner names from the request.
	var ownerNames []string
	for _, op := range req.Operations {
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err == nil {
				ownerNames = append(ownerNames, dns.Fqdn(rr.Header().Name))
			}
		}
	}
	for owner := range req.Records {
		ownerNames = append(ownerNames, dns.Fqdn(owner))
	}
	if len(ownerNames) == 0 {
		return "", fmt.Errorf("provider update has no zone and no records to derive zone from")
	}

	// Find the most specific zone that contains all owner names. All owners must
	// fall within the same zone.
	best := ""
	bestLabels := 0
	Zones.IterCb(func(zonename string, _ *ZoneData) {
		labels := dns.CountLabel(zonename)
		if labels <= bestLabels {
			return
		}
		for _, owner := range ownerNames {
			if !dns.IsSubDomain(zonename, owner) {
				return
			}
		}
		best = zonename
		bestLabels = labels
	})
	if best == "" {
		return "", fmt.Errorf("no zone found on this combiner that contains owner name(s) %v", ownerNames)
	}
	if GetProviderZoneRRtypes(best) == nil {
		return "", fmt.Errorf("zone %q is known but not configured as a provider zone on this combiner", best)
	}
	return best, nil
}

// checkMPauthorization verifies that the combiner is authorized to accept
// contributions for this zone. Returns nil if authorized, or a descriptive
// error explaining exactly why the contribution was rejected.
func checkMPauthorization(zd *ZoneData) error {
	if !zd.Options[OptMultiProvider] {
		return fmt.Errorf("zone %q: contributions rejected — zone is not configured as a multi-provider zone (OptMultiProvider not set)", zd.ZoneName)
	}
	if zd.MP == nil || zd.MP.MPdata == nil {
		// MPdata is nil despite OptMultiProvider being set. This means one of
		// guards 2-4 failed during zone refresh. Provide a specific explanation.
		// Re-run the checks to produce a precise message.
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			return fmt.Errorf("zone %q: contributions rejected — cannot inspect zone apex: %v", zd.ZoneName, err)
		}
		_, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
		_, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
		_, h1exists := apex.RRtypes.Get(core.TypeHSYNC)
		_, h2exists := apex.RRtypes.Get(core.TypeHSYNC2)
		if !((h3exists && hpExists) || h1exists || h2exists) {
			return fmt.Errorf("zone %q: contributions rejected — zone has OptMultiProvider set but the zone owner has not published HSYNC3+HSYNCPARAM records (zone is not declared as multi-provider by its owner)", zd.ZoneName)
		}
		ourIdentities := ourHsyncIdentities()
		matched, _, _ := zd.matchHsyncProvider(ourIdentities)
		if !matched {
			return fmt.Errorf("zone %q: contributions rejected — none of our agent identities %v match any HSYNC3 provider record in the zone (we are not a recognized provider for this zone)", zd.ZoneName, ourIdentities)
		}
		// Must be guard 4: we are a provider but not a signer
		return fmt.Errorf("zone %q: rejected (mp-disallow-edits: zone is signed, we are not a signer)", zd.ZoneName)
	}
	return nil
}

func CombinerProcessUpdate(req *CombinerSyncRequest, protectedNamespaces []string, localAgents map[string]bool, kdb *KeyDB, tm *MPTransportBridge) *CombinerSyncResponse {
	// Count total records for logging
	totalRecords := 0
	for _, rrs := range req.Records {
		totalRecords += len(rrs)
	}
	lgCombiner.Debug("processing legacy update", "sender", req.SenderID, "zone", req.Zone, "owners", len(req.Records), "records", totalRecords)

	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:           req.Zone,
		Timestamp:      time.Now(),
	}

	// Get the zone data. For provider updates without a specified zone, discover
	// the zone from the record owner names.
	var zonename string
	if req.Zone == "" && req.ZoneClass == "provider" {
		discovered, err := findProviderZoneForRequest(req)
		if err != nil {
			lgCombiner.Error("provider zone discovery failed", "sender", req.SenderID, "err", err)
			resp.Status = "error"
			resp.Message = err.Error()
			return resp
		}
		lgCombiner.Debug("provider zone discovered", "zone", discovered, "sender", req.SenderID)
		zonename = discovered
		req.Zone = zonename
		resp.Zone = zonename
	} else {
		zonename = dns.Fqdn(req.Zone)
		req.Zone = zonename
	}
	zd, exists := Zones.Get(zonename)
	if !exists {
		lgCombiner.Error("zone not found", "zone", req.Zone, "sender", req.SenderID)
		resp.Status = "error"
		resp.Message = fmt.Sprintf("zone %q not found on this combiner", req.Zone)
		return resp
	}

	// Multi-provider safety gate: for MP-zone updates (not provider-zone updates),
	// verify that the zone is a confirmed multi-provider zone and that we are an
	// authorized provider (and signer, if the zone is signed).
	if req.ZoneClass != "provider" {
		if err := checkMPauthorization(zd); err != nil {
			lgCombiner.Warn("rejecting contribution", "zone", req.Zone, "sender", req.SenderID, "reason", err)
			resp.Status = "error"
			resp.Message = err.Error()
			// Populate RejectedItems so the agent can match per-record rejections
			reason := err.Error()
			if len(req.Operations) > 0 {
				for _, op := range req.Operations {
					for _, rr := range op.Records {
						resp.RejectedItems = append(resp.RejectedItems, RejectedItem{Record: rr, Reason: reason})
					}
				}
			} else {
				for _, rrs := range req.Records {
					for _, rr := range rrs {
						resp.RejectedItems = append(resp.RejectedItems, RejectedItem{Record: rr, Reason: reason})
					}
				}
			}
			return resp
		}
	}

	// Process Operations (the only supported format for SYNC/UPDATE)
	if len(req.Operations) > 0 {
		resp = combinerProcessOperations(req, zd, zonename, protectedNamespaces, localAgents)
		if resp.Status != "error" {
			if req.Publish != nil {
				combinerApplyPublishInstruction(req, zd, kdb)
			}
			combinerResyncSignalKeys(req.SenderID, zonename, zd, kdb)
			if resp.DataChanged {
				nsChanged, kskChanged := detectDelegationChanges(resp)
				if nsChanged || kskChanged {
					go combinerNotifyDelegationChange(tm, req.DeliveredBy, zonename, zd, nsChanged, kskChanged)
				}
			}
		}
		return resp
	}

	// No Operations: handle publish-only or reject
	if req.Publish != nil {
		combinerApplyPublishInstruction(req, zd, kdb)
		combinerResyncSignalKeys(req.SenderID, zonename, zd, kdb)
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("publish instruction applied for zone %q (no data operations)", req.Zone)
		return resp
	}

	resp.Status = "error"
	resp.Message = fmt.Sprintf("update for zone %q has no Operations", req.Zone)
	return resp
}

// combinerNotifyDelegationChange publishes CDS/CSYNC as needed and sends a
// STATUS-UPDATE notification to the local agent that delivered the update.
// Runs as a goroutine — fire-and-forget from the combiner's perspective.
func combinerNotifyDelegationChange(tm *MPTransportBridge, senderID, zonename string, zd *ZoneData, nsChanged, kskChanged bool) {
	if tm == nil {
		lgCombiner.Warn("combinerNotifyDelegationChange: no transport, skipping", "zone", zonename)
		return
	}
	// Determine if the zone is signed by checking HSYNCPARAM signers
	zoneSigned := false
	apex, err := zd.GetOwner(zd.ZoneName)
	if err == nil && apex != nil {
		if hpRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM); exists && len(hpRRset.RRs) > 0 {
			hsyncparam := hpRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
			if len(hsyncparam.GetSigners()) > 0 {
				zoneSigned = true
			}
		}
	}

	lgCombiner.Info("combinerNotifyDelegationChange: delegation change detected", "zone", zonename, "nsChanged", nsChanged, "kskChanged", kskChanged, "zoneSigned", zoneSigned)

	// Publish indicator records via combiner data path (not UpdateQ, which
	// the combiner doesn't consume). This ensures CSYNC/CDS are stored in
	// AgentContributions and persisted, surviving combiner restarts.
	changed := false
	if nsChanged {
		if !zoneSigned {
			lgCombiner.Debug("combinerNotifyDelegationChange: NS changed but zone is not signed, skipping CSYNC", "zone", zonename)
		} else {
			csync := &dns.CSYNC{
				Serial:     zd.CurrentSerial,
				Flags:      0,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA},
			}
			csync.Hdr = dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeCSYNC,
				Class:  dns.ClassINET,
				Ttl:    120,
			}
			_, _, csyncChanged, err := ReplaceCombinerDataByRRtype(zd, tm.LocalID, zonename, dns.TypeCSYNC, []dns.RR{csync})
			if err != nil {
				lgCombiner.Error("combinerNotifyDelegationChange: CSYNC replace failed", "zone", zonename, "err", err)
			} else {
				lgCombiner.Info("combinerNotifyDelegationChange: CSYNC published", "zone", zonename, "changed", csyncChanged)
				changed = changed || csyncChanged
			}
		}
	}
	if kskChanged {
		cdsRRs, err := zd.synthesizeCdsRRs()
		if err != nil {
			lgCombiner.Error("combinerNotifyDelegationChange: CDS synthesis failed", "zone", zonename, "err", err)
		} else if len(cdsRRs) > 0 {
			_, _, cdsChanged, err := ReplaceCombinerDataByRRtype(zd, tm.LocalID, zonename, dns.TypeCDS, cdsRRs)
			if err != nil {
				lgCombiner.Error("combinerNotifyDelegationChange: CDS replace failed", "zone", zonename, "err", err)
			} else {
				lgCombiner.Info("combinerNotifyDelegationChange: CDS published", "zone", zonename, "changed", cdsChanged)
				changed = changed || cdsChanged
			}
		}
	}
	if changed {
		if bumperResp, err := zd.BumpSerialOnly(); err != nil {
			lgCombiner.Error("combinerNotifyDelegationChange: BumpSerialOnly failed", "zone", zonename, "err", err)
		} else {
			lgCombiner.Debug("combinerNotifyDelegationChange: serial bumped", "zone", zonename, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}

	// Collect current NS records as strings
	var nsRecords []string
	if apex != nil {
		nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
		for _, rr := range nsRRset.RRs {
			nsRecords = append(nsRecords, rr.String())
		}
	}

	// Collect current DS records (derived from KSK DNSKEYs) as strings
	var dsRecords []string
	if kskChanged && apex != nil {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						dsRecords = append(dsRecords, ds.String())
					}
				}
			}
		}
	}

	// Send one notification per change type
	if nsChanged {
		lgCombiner.Info("combinerNotifyDelegationChange: sending ns-changed", "zone", zonename, "agent", senderID)
		sendDelegationStatusUpdate(tm, senderID, zonename, "ns-changed", nsRecords, nil)
	}
	if kskChanged {
		lgCombiner.Info("combinerNotifyDelegationChange: sending ksk-changed", "zone", zonename, "agent", senderID)
		sendDelegationStatusUpdate(tm, senderID, zonename, "ksk-changed", nil, dsRecords)
	}
}

// sendDelegationStatusUpdate sends a STATUS-UPDATE message to the agent
// via the DNSTransport fire-and-forget NOTIFY(CHUNK) mechanism.
func sendDelegationStatusUpdate(tm *MPTransportBridge, agentID, zonename, subtype string, nsRecords, dsRecords []string) {
	if tm == nil || tm.DNSTransport == nil {
		lgCombiner.Warn("sendDelegationStatusUpdate: no DNSTransport, cannot notify agent", "zone", zonename, "subtype", subtype)
		return
	}

	peer, exists := tm.PeerRegistry.Get(agentID)
	if !exists {
		lgCombiner.Warn("sendDelegationStatusUpdate: agent not in peer registry", "agent", agentID, "zone", zonename, "subtype", subtype)
		return
	}

	post := &core.StatusUpdatePost{
		Zone:      zonename,
		SubType:   subtype,
		NSRecords: nsRecords,
		DSRecords: dsRecords,
		Time:      time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.SendStatusUpdate(ctx, peer, post)
	if err != nil {
		lgCombiner.Error("sendDelegationStatusUpdate: failed to send", "zone", zonename, "subtype", subtype, "agent", agentID, "err", err)
	} else {
		lgCombiner.Info("sendDelegationStatusUpdate: sent", "zone", zonename, "subtype", subtype, "agent", agentID)
	}
}

// combinerApplyPublishInstruction processes a PublishInstruction from an agent.
// It publishes/retracts KEY RRs at the zone apex and/or at _signal names
// in provider zones, and persists the instruction for NS-change resync.
func combinerApplyPublishInstruction(req *CombinerSyncRequest, zd *ZoneData, kdb *KeyDB) {
	if req.Publish == nil {
		return
	}
	instr := req.Publish
	zone := req.Zone
	senderID := req.SenderID

	// Load previously stored instruction (if any)
	var storedInstr *StoredPublishInstruction
	if kdb != nil {
		storedInstr, _ = GetPublishInstruction(kdb, zone, senderID)
	}

	// Retract: empty Locations means remove all published KEYs
	if len(instr.Locations) == 0 {
		// Remove apex KEY
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, nil)
		// Remove all _signal KEYs
		if storedInstr != nil {
			for _, ns := range storedInstr.PublishedNS {
				publishSignalKeyToProvider(zone, ns, senderID, nil)
			}
		}
		if kdb != nil {
			DeletePublishInstruction(kdb, zone, senderID)
		}
		lgCombiner.Info("publish instruction retracted", "zone", zone, "sender", senderID)
		return
	}

	locSet := make(map[string]bool)
	for _, loc := range instr.Locations {
		locSet[loc] = true
	}

	// Handle at-apex
	if locSet["at-apex"] {
		var parsedRRs []dns.RR
		for _, rrStr := range instr.KEYRRs {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				lgCombiner.Warn("publish instruction: bad KEY RR", "zone", zone, "rr", rrStr, "err", err)
				continue
			}
			parsedRRs = append(parsedRRs, rr)
		}
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, parsedRRs)
	} else if storedInstr != nil && containsString(storedInstr.Locations, "at-apex") {
		// Was at-apex before, now removed
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, nil)
	}

	// Handle at-ns
	var publishedNS []string
	if locSet["at-ns"] {
		currentNS := getAgentNSTargets(zd, senderID, zone)
		var prevPublished []string
		if storedInstr != nil {
			prevPublished = storedInstr.PublishedNS
		}
		curSet := stringSet(currentNS)

		// Always publish for all current NS targets. The operation is idempotent
		// (ReplaceCombinerDataByRRtype is a no-op when data matches), so
		// re-publishing is safe and avoids stale state after zone reloads.
		for _, ns := range currentNS {
			publishSignalKeyToProvider(zone, ns, senderID, instr.KEYRRs)
		}
		// Remove _signal KEYs for NS targets no longer contributed
		for _, ns := range prevPublished {
			if !curSet[ns] {
				publishSignalKeyToProvider(zone, ns, senderID, nil)
			}
		}
		publishedNS = currentNS
	} else if storedInstr != nil && containsString(storedInstr.Locations, "at-ns") {
		// Was at-ns before, now removed — retract all
		for _, ns := range storedInstr.PublishedNS {
			publishSignalKeyToProvider(zone, ns, senderID, nil)
		}
	}

	// Persist
	if kdb != nil {
		if err := SavePublishInstruction(kdb, zone, senderID, instr, publishedNS); err != nil {
			lgCombiner.Error("failed to save publish instruction", "zone", zone, "sender", senderID, "err", err)
		}
	}

	lgCombiner.Info("publish instruction applied", "zone", zone, "sender", senderID, "locations", instr.Locations, "publishedNS", publishedNS)
}

// combinerResyncSignalKeys is called when NS records change for an agent.
// It diffs the current NS targets against the stored PublishedNS and
// adds/removes _signal KEY records accordingly.
func combinerResyncSignalKeys(senderID, zone string, zd *ZoneData, kdb *KeyDB) {
	if kdb == nil {
		return
	}
	storedInstr, err := GetPublishInstruction(kdb, zone, senderID)
	if err != nil || storedInstr == nil {
		return
	}
	if !containsString(storedInstr.Locations, "at-ns") {
		return
	}

	currentNS := getAgentNSTargets(zd, senderID, zone)
	prevSet := stringSet(storedInstr.PublishedNS)
	curSet := stringSet(currentNS)

	changed := false
	for _, ns := range currentNS {
		if !prevSet[ns] {
			publishSignalKeyToProvider(zone, ns, senderID, storedInstr.KEYRRs)
			changed = true
		}
	}
	for _, ns := range storedInstr.PublishedNS {
		if !curSet[ns] {
			publishSignalKeyToProvider(zone, ns, senderID, nil)
			changed = true
		}
	}

	if changed {
		instr := storedInstr.ToPublishInstruction()
		if err := SavePublishInstruction(kdb, zone, senderID, instr, currentNS); err != nil {
			lgCombiner.Error("failed to update published NS after resync", "zone", zone, "sender", senderID, "err", err)
		}
		lgCombiner.Info("signal keys resynced after NS change", "zone", zone, "sender", senderID, "publishedNS", currentNS)
	}
}

// publishSignalKeyToProvider directly applies a _signal KEY record to the
// provider zone that contains the NS target. If keyRRs is nil/empty, the KEY
// is removed. The combiner applies this locally (no transport needed — we ARE
// the combiner).
func publishSignalKeyToProvider(childZone, nsTarget, senderID string, keyRRs []string) {
	ownerName := Sig0KeyOwnerName(childZone, nsTarget)

	// Find the provider zone that contains this owner name
	providerZone := findProviderZoneForOwner(ownerName)
	if providerZone == "" {
		lgCombiner.Debug("no provider zone found for _signal owner", "owner", ownerName, "childZone", childZone, "ns", nsTarget)
		return
	}
	zd, ok := Zones.Get(providerZone)
	if !ok {
		lgCombiner.Warn("provider zone not loaded", "zone", providerZone, "owner", ownerName)
		return
	}

	var parsedRRs []dns.RR
	for _, rrStr := range keyRRs {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgCombiner.Warn("publishSignalKeyToProvider: bad KEY RR", "rr", rrStr, "err", err)
			continue
		}
		rr.Header().Name = ownerName
		parsedRRs = append(parsedRRs, rr)
	}

	_, _, changed, err := ReplaceCombinerDataByRRtype(zd, senderID, ownerName, dns.TypeKEY, parsedRRs)
	if err != nil {
		lgCombiner.Error("failed to apply _signal KEY to provider zone", "zone", providerZone, "owner", ownerName, "err", err)
		return
	}
	if changed {
		if bumperResp, err := zd.BumpSerialOnly(); err != nil {
			lgCombiner.Error("BumpSerialOnly failed for provider zone", "zone", providerZone, "err", err)
		} else {
			lgCombiner.Debug("provider zone serial bumped", "zone", providerZone, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}
	lgCombiner.Info("_signal KEY applied to provider zone", "zone", providerZone, "owner", ownerName, "keys", len(parsedRRs), "changed", changed)
}

// findProviderZoneForOwner finds the most specific configured provider zone
// that contains the given owner name. Returns "" if no match.
func findProviderZoneForOwner(ownerName string) string {
	zd, _ := FindZone(dns.Fqdn(ownerName))
	if zd == nil {
		return ""
	}
	if GetProviderZoneRRtypes(zd.ZoneName) == nil {
		return ""
	}
	return zd.ZoneName
}

// getAgentNSTargets returns the NS target names from an agent's contributions for a zone.
func getAgentNSTargets(zd *ZoneData, senderID, zone string) []string {
	agentData, ok := zd.MP.AgentContributions[senderID]
	if !ok {
		return nil
	}
	nsRRset, ok := agentData[zone][dns.TypeNS]
	if !ok {
		return nil
	}
	var targets []string
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			targets = append(targets, dns.Fqdn(ns.Ns))
		}
	}
	return targets
}

// --- Startup re-apply of stored publish instructions for provider zones ---

// signalKeyEntry represents a _signal KEY that should be published in a provider zone.
type signalKeyEntry struct {
	OwnerName string   // e.g. _sig0key.whisky.dnslab._signal.ns2.alpha.dnslab.
	SenderID  string   // agent identity that owns the KEY
	KEYRRs    []string // KEY RRs in text format
}

// pendingSignalKeyMap holds signal keys grouped by provider zone, built once
// from CombinerPublishInstructions and consumed by each provider zone's OnFirstLoad.
type pendingSignalKeyMap struct {
	mu      sync.Mutex
	built   bool
	entries map[string][]signalKeyEntry // providerZone → entries
}

var pendingSignalKeys = &pendingSignalKeyMap{}

// buildPendingSignalKeys is called by the first provider zone's OnFirstLoad.
// It loads all stored publish instructions and maps NS targets to provider zones.
func buildPendingSignalKeys(kdb *KeyDB) {
	if kdb == nil {
		lgCombiner.Warn("buildPendingSignalKeys: kdb is nil, skipping")
		pendingSignalKeys.entries = make(map[string][]signalKeyEntry)
		return
	}
	allInstr, err := LoadAllPublishInstructions(kdb)
	if err != nil {
		lgCombiner.Error("failed to load publish instructions for startup re-apply", "err", err)
		pendingSignalKeys.entries = make(map[string][]signalKeyEntry)
		return
	}

	entries := make(map[string][]signalKeyEntry)
	for zone, senders := range allInstr {
		for senderID, stored := range senders {
			if !containsString(stored.Locations, "at-ns") || len(stored.KEYRRs) == 0 {
				continue
			}
			for _, ns := range stored.PublishedNS {
				ownerName := Sig0KeyOwnerName(zone, ns)
				providerZone := findProviderZoneForOwner(ownerName)
				if providerZone == "" {
					lgCombiner.Debug("startup re-apply: no provider zone for NS target", "ns", ns, "childZone", zone)
					continue
				}
				entries[providerZone] = append(entries[providerZone], signalKeyEntry{
					OwnerName: ownerName,
					SenderID:  senderID,
					KEYRRs:    stored.KEYRRs,
				})
			}
		}
	}
	pendingSignalKeys.entries = entries
	lgCombiner.Info("built pending signal key map", "providerZones", len(entries))
}

// applyPendingSignalKeys is called by each provider zone's OnFirstLoad.
// It applies any pending _signal KEY entries for this zone and removes them from the map.
func applyPendingSignalKeys(zd *ZoneData, kdb *KeyDB) {
	pendingSignalKeys.mu.Lock()
	if !pendingSignalKeys.built {
		buildPendingSignalKeys(kdb)
		pendingSignalKeys.built = true
	}
	myEntries := pendingSignalKeys.entries[zd.ZoneName]
	delete(pendingSignalKeys.entries, zd.ZoneName)
	pendingSignalKeys.mu.Unlock()

	if len(myEntries) == 0 {
		return
	}

	for _, entry := range myEntries {
		var parsedRRs []dns.RR
		for _, rrStr := range entry.KEYRRs {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			rr.Header().Name = entry.OwnerName
			parsedRRs = append(parsedRRs, rr)
		}
		_, _, changed, err := ReplaceCombinerDataByRRtype(zd, entry.SenderID, entry.OwnerName, dns.TypeKEY, parsedRRs)
		if err != nil {
			lgCombiner.Error("startup re-apply: failed to apply _signal KEY", "zone", zd.ZoneName, "owner", entry.OwnerName, "err", err)
			continue
		}
		if changed {
			lgCombiner.Info("startup re-apply: _signal KEY applied", "zone", zd.ZoneName, "owner", entry.OwnerName, "sender", entry.SenderID)
		}
	}
}

// findExistingContribution checks whether any sender OTHER than excludeSender
// already has a contribution for the given zone/rrtype. Returns the sender ID
// and the RRs, or ("", nil) if no other sender has this rrtype.
func findExistingContribution(zd *ZoneData, owner string, rrtype uint16, excludeSender string) (string, []dns.RR) {
	for senderID, zones := range zd.MP.AgentContributions {
		if senderID == excludeSender {
			continue
		}
		if owners, ok := zones[owner]; ok {
			if rrset, ok := owners[rrtype]; ok && len(rrset.RRs) > 0 {
				return senderID, rrset.RRs
			}
		}
	}
	return "", nil
}

// sameRRData returns true if two RR slices contain the same records (order-independent).
func sameRRData(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ra := range a {
		found := false
		for _, rb := range b {
			if dns.IsDuplicate(ra, rb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func stringSet(slice []string) map[string]bool {
	m := make(map[string]bool, len(slice))
	for _, s := range slice {
		m[s] = true
	}
	return m
}

// combinerProcessOperations handles explicit Operations (add, delete, replace)
// at the combiner level. Each operation is applied to the agent's contributions.
func combinerProcessOperations(req *CombinerSyncRequest, zd *ZoneData, zonename string, protectedNamespaces []string, localAgents map[string]bool) *CombinerSyncResponse {
	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:           req.Zone,
		Timestamp:      time.Now(),
	}

	var appliedRecords []string
	var removedRecords []string
	var rejectedItems []RejectedItem
	dataChanged := false

	// Select the RRtype whitelist and owner policy based on ZoneClass.
	isProvider := req.ZoneClass == "provider"
	allowedRRtypes := AllowedLocalRRtypes
	if isProvider {
		if pzt := GetProviderZoneRRtypes(req.Zone); pzt != nil {
			allowedRRtypes = pzt
		} else {
			resp.Status = "error"
			resp.Message = fmt.Sprintf("zone %q is not configured as a provider zone", req.Zone)
			return resp
		}
	}

	for _, op := range req.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("unknown RR type: %s", op.RRtype),
			})
			continue
		}
		if !allowedRRtypes[rrtype] {
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("RRtype %s not allowed for combiner updates", op.RRtype),
			})
			continue
		}

		// DNSKEY policy: only signers may contribute DNSKEYs
		if rrtype == dns.TypeDNSKEY && !isProvider {
			reject, reason := checkDNSKEYPolicy(zd, req.SenderID)
			if reject {
				for _, rec := range op.Records {
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: rec,
						Reason: reason,
					})
				}
				continue
			}
		}

		// Parse and validate all RRs in this operation
		var parsedRRs []dns.RR
		parseOk := true
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("parse error: %v", err),
				})
				parseOk = false
				continue
			}
			// MP zones: owner must be at zone apex. Provider zones: any owner within the zone.
			if isProvider {
				lowerOwner := strings.ToLower(rr.Header().Name)
				lowerZone := strings.ToLower(zonename)
				if lowerOwner != lowerZone && !strings.HasSuffix(lowerOwner, "."+lowerZone) {
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: rrStr,
						Reason: fmt.Sprintf("owner %q is not within zone %q", rr.Header().Name, zonename),
					})
					parseOk = false
					continue
				}
			} else if !strings.EqualFold(rr.Header().Name, zonename) {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("owner %q is not at zone apex %q", rr.Header().Name, zonename),
				})
				parseOk = false
				continue
			}
			// M71: Validate TTL range
			if rr.Header().Ttl > 604800 {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("TTL %d exceeds maximum (604800)", rr.Header().Ttl),
				})
				parseOk = false
				continue
			}
			if reason := checkContentPolicy(rr, protectedNamespaces); reason != "" {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: reason,
				})
				parseOk = false
				continue
			}
			warnNSTargetUnresolvable(rr, zd)
			parsedRRs = append(parsedRRs, rr)
		}

		switch op.Operation {
		case "replace":
			if !parseOk && len(parsedRRs) == 0 && len(op.Records) > 0 {
				// All records rejected — skip replace to avoid accidental wipe
				continue
			}

			// Local-trumps-remote deduplication for KEY and CDS.
			// When the same records exist under a different sender, apply single-origin rule:
			// - Local contribution already exists → remote sender gets no-op (positive confirmation)
			// - Remote contribution exists, local sender arrives → re-attribute to local sender
			if (rrtype == dns.TypeKEY || rrtype == dns.TypeCDS) && len(parsedRRs) > 0 {
				senderIsLocal := localAgents[req.SenderID]
				if existingSender, existingRRs := findExistingContribution(zd, zonename, rrtype, req.SenderID); existingSender != "" {
					existingIsLocal := localAgents[existingSender]
					if sameRRData(existingRRs, parsedRRs) {
						if existingIsLocal && !senderIsLocal {
							// Local already has it — no-op for remote sender, report as applied
							lgCombiner.Debug("dedup: local contribution exists, remote is no-op",
								"rrtype", op.RRtype, "zone", zonename, "local", existingSender, "remote", req.SenderID)
							for _, rr := range parsedRRs {
								appliedRecords = append(appliedRecords, rr.String())
							}
							continue
						}
						if !existingIsLocal && senderIsLocal {
							// Remote had it first, local now claims — re-attribute to local
							lgCombiner.Info("dedup: re-attributing contribution from remote to local",
								"rrtype", op.RRtype, "zone", zonename, "from", existingSender, "to", req.SenderID)
							ReplaceCombinerDataByRRtype(zd, existingSender, zonename, rrtype, nil) // remove from remote
							// fall through to normal replace, which will store under local sender
						}
					}
				}
			}

			applied, removed, changed, err := ReplaceCombinerDataByRRtype(zd, req.SenderID, zonename, rrtype, parsedRRs)
			if err != nil {
				lgCombiner.Error("REPLACE operation failed", "err", err)
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: fmt.Sprintf("(replace %s)", op.RRtype),
					Reason: fmt.Sprintf("replace failed: %v", err),
				})
				continue
			}
			// Always report records as applied regardless of whether data changed.
			// The agent needs to know its records are present at the combiner so it
			// can transition them from pending to accepted in the SDE.
			if len(applied) > 0 {
				appliedRecords = append(appliedRecords, applied...)
			} else if len(parsedRRs) > 0 {
				// No-op replace: report what's actually stored at the combiner.
				if stored, ok := zd.MP.AgentContributions[req.SenderID][zonename][rrtype]; ok {
					for _, rr := range stored.RRs {
						appliedRecords = append(appliedRecords, rr.String())
					}
				}
			}
			removedRecords = append(removedRecords, removed...)
			if changed {
				dataChanged = true
			}

		case "add":
			addRecords := make(map[string][]string)
			for _, rr := range parsedRRs {
				owner := rr.Header().Name
				addRecords[owner] = append(addRecords[owner], rr.String())
			}
			if len(addRecords) > 0 {
				addChanged, err := AddCombinerDataNG(zd, req.SenderID, addRecords)
				if err != nil {
					lgCombiner.Error("ADD operation failed", "err", err)
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: fmt.Sprintf("(add %s)", op.RRtype),
						Reason: fmt.Sprintf("add failed: %v", err),
					})
					continue
				}
				if addChanged {
					dataChanged = true
				}
				for _, rrs := range addRecords {
					appliedRecords = append(appliedRecords, rrs...)
				}
			}

		case "delete":
			delRecords := make(map[string][]string)
			for _, rr := range parsedRRs {
				owner := rr.Header().Name
				delRecords[owner] = append(delRecords[owner], rr.String())
			}
			if len(delRecords) > 0 {
				removed, err := RemoveCombinerDataNG(zd, req.SenderID, delRecords)
				if err != nil {
					lgCombiner.Error("DELETE operation failed", "err", err)
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: fmt.Sprintf("(delete %s)", op.RRtype),
						Reason: fmt.Sprintf("delete failed: %v", err),
					})
					continue
				}
				if len(removed) > 0 {
					dataChanged = true
				}
				removedRecords = append(removedRecords, removed...)
			}

		default:
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("unknown operation: %s", op.Operation),
			})
		}
	}

	resp.AppliedRecords = appliedRecords
	resp.RemovedRecords = removedRecords
	resp.RejectedItems = rejectedItems

	totalActions := len(appliedRecords) + len(removedRecords)
	if len(rejectedItems) == 0 {
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("applied %d added %d removed for zone %q (via operations)",
			len(appliedRecords), len(removedRecords), req.Zone)
	} else if totalActions > 0 {
		resp.Status = "partial"
		resp.Message = fmt.Sprintf("applied %d added %d removed %d rejected for zone %q (via operations)",
			len(appliedRecords), len(removedRecords), len(rejectedItems), req.Zone)
	} else {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("all operations rejected for zone %q", req.Zone)
	}

	// Build summary of operation types for log
	opTypes := make(map[string]int)
	for _, op := range req.Operations {
		opTypes[strings.ToUpper(op.Operation)]++
	}
	var opSummary []string
	for opType, count := range opTypes {
		opSummary = append(opSummary, fmt.Sprintf("%s:%d", opType, count))
	}
	lgCombiner.Info("operations processed", "ops", strings.Join(opSummary, ","), "status", resp.Status, "message", resp.Message)
	for _, ri := range rejectedItems {
		lgCombiner.Warn("operation rejected", "zone", req.Zone, "sender", req.SenderID, "record", ri.Record, "reason", ri.Reason)
	}

	resp.DataChanged = dataChanged
	if dataChanged {
		bumperResp, err := zd.BumpSerialOnly()
		if err != nil {
			lgCombiner.Error("BumpSerialOnly failed", "zone", req.Zone, "err", err)
		} else {
			lgCombiner.Info("serial bumped", "zone", req.Zone, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}

	return resp
}

// isNoOpUpdate checks whether an incoming update would cause any actual change.
// Checks against both the live zone data (GetRRset) and CombinerData (merged agent
// contributions). A record is considered present if it exists in either source.
func isNoOpUpdate(zd *ZoneData, senderID string, records map[string][]string) bool {
	for owner, rrStrings := range records {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				return false
			}

			rrtype := rr.Header().Rrtype
			switch rr.Header().Class {
			case dns.ClassINET:
				if !rrExistsInZone(zd, owner, rrtype, rr) {
					lgCombiner.Info("legacy isNoOpUpdate: RR not found, update is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())
					return false
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RR already present (no-op)",
					"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())

			case dns.ClassNONE:
				delRR := dns.Copy(rr)
				delRR.Header().Class = dns.ClassINET
				if rrExistsInZone(zd, owner, rrtype, delRR) {
					lgCombiner.Info("legacy isNoOpUpdate: RR exists, delete is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())
					return false // RR exists → removing it IS a change
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RR already absent (delete is no-op)",
					"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())

			case dns.ClassANY:
				if rrTypeExistsInZone(zd, owner, rrtype) {
					lgCombiner.Info("legacy isNoOpUpdate: RRtype has records, bulk delete is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "owner", owner, "rrtype", dns.TypeToString[rrtype])
					return false
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RRtype empty (bulk delete is no-op)",
					"sender", senderID, "zone", zd.ZoneName, "owner", owner, "rrtype", dns.TypeToString[rrtype])

			default:
				return false
			}
		}
	}

	lgCombiner.Info("isNoOpUpdate: all records already present, update is a no-op",
		"sender", senderID, "zone", zd.ZoneName)
	return true
}

// IsNoOpOperations checks whether explicit Operations would cause any actual change.
// For replace: compares the replacement set against the agent's current contributions.
// For add: checks if all RRs already exist. For delete: checks if all RRs are already absent.
func IsNoOpOperations(zd *ZoneData, senderID string, ops []core.RROperation) bool {
	zonename := zd.ZoneName
	for _, op := range ops {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			return false // Unknown type — not a no-op
		}

		switch op.Operation {
		case "replace":
			// Get agent's current contributions for this rrtype
			var existingRRs []dns.RR
			if zd.MP.AgentContributions != nil {
				if agentData, ok := zd.MP.AgentContributions[senderID]; ok {
					if ownerMap, ok := agentData[zonename]; ok {
						if rrset, ok := ownerMap[rrtype]; ok {
							existingRRs = rrset.RRs
						}
					}
				}
			}

			// Parse replacement RRs
			var newRRs []dns.RR
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				newRRs = append(newRRs, rr)
			}

			// Both empty = no-op
			if len(existingRRs) == 0 && len(newRRs) == 0 {
				continue
			}
			// Different length = change
			if len(existingRRs) != len(newRRs) {
				return false
			}
			// Check all existing RRs are in the new set
			for _, oldRR := range existingRRs {
				found := false
				for _, newRR := range newRRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

		case "add":
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				if !rrExistsInZone(zd, zonename, rrtype, rr) {
					return false
				}
			}

		case "delete":
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				delRR := dns.Copy(rr)
				delRR.Header().Class = dns.ClassINET
				if rrExistsInZone(zd, zonename, rrtype, delRR) {
					return false // RR still exists — deleting it IS a change
				}
			}

		default:
			return false
		}
	}

	lgCombiner.Info("IsNoOpOperations: all operations are no-ops",
		"sender", senderID, "zone", zd.ZoneName)
	return true
}

// rrExistsInZone checks whether the given RR exists in either the live zone data
// or CombinerData. Returns true if found in either source.
func rrExistsInZone(zd *ZoneData, owner string, rrtype uint16, rr dns.RR) bool {
	rrStr := rr.String()
	rrtypeStr := dns.TypeToString[rrtype]

	// Check live zone data first
	existing, err := zd.GetRRset(owner, rrtype)
	if err != nil {
		lgCombiner.Info("rrExistsInZone: GetRRset error", "owner", owner, "rrtype", rrtypeStr, "err", err)
	} else if existing == nil {
		lgCombiner.Info("rrExistsInZone: no RRset in live zone", "owner", owner, "rrtype", rrtypeStr, "zoneStore", ZoneStoreToString[zd.ZoneStore])
	} else {
		for _, existingRR := range existing.RRs {
			if dns.IsDuplicate(rr, existingRR) {
				lgCombiner.Info("rrExistsInZone: found in live zone", "owner", owner, "rrtype", rrtypeStr, "rr", rrStr)
				return true
			}
		}
		// RRset exists but this specific RR is not in it
		var existingStrs []string
		for _, e := range existing.RRs {
			existingStrs = append(existingStrs, e.String())
		}
		lgCombiner.Info("rrExistsInZone: RRset exists in live zone but RR not found",
			"owner", owner, "rrtype", rrtypeStr, "lookingFor", rrStr, "existing", existingStrs)
	}

	// Check CombinerData
	if zd.MP.CombinerData == nil {
		lgCombiner.Info("rrExistsInZone: CombinerData is nil", "zone", zd.ZoneName)
	} else {
		ownerData, ownerExists := zd.MP.CombinerData.Get(owner)
		if !ownerExists {
			// Dump all CombinerData keys for diagnostics
			var cdOwners []string
			for item := range zd.MP.CombinerData.IterBuffered() {
				cdOwners = append(cdOwners, item.Key)
			}
			lgCombiner.Info("rrExistsInZone: owner not in CombinerData",
				"owner", owner, "cdOwners", cdOwners)
		} else {
			cdRRset, rrtypeExists := ownerData.RRtypes.Get(rrtype)
			if !rrtypeExists || len(cdRRset.RRs) == 0 {
				var cdRRtypes []string
				for _, rt := range ownerData.RRtypes.Keys() {
					cdRRtypes = append(cdRRtypes, dns.TypeToString[rt])
				}
				lgCombiner.Info("rrExistsInZone: rrtype not in CombinerData for owner",
					"owner", owner, "rrtype", rrtypeStr, "cdRRtypes", cdRRtypes)
			} else {
				for _, existingRR := range cdRRset.RRs {
					if dns.IsDuplicate(rr, existingRR) {
						lgCombiner.Info("rrExistsInZone: found in CombinerData (not in live zone)",
							"owner", owner, "rrtype", rrtypeStr, "rr", rrStr)
						return true
					}
				}
				// RRset exists in CombinerData but this specific RR is not in it
				var existingStrs []string
				for _, e := range cdRRset.RRs {
					existingStrs = append(existingStrs, e.String())
				}
				lgCombiner.Info("rrExistsInZone: RRset exists in CombinerData but RR not found",
					"owner", owner, "rrtype", rrtypeStr, "lookingFor", rrStr, "existing", existingStrs)
			}
		}
	}

	return false
}

// rrTypeExistsInZone checks whether the given owner/rrtype has any records in
// either the live zone data or CombinerData.
func rrTypeExistsInZone(zd *ZoneData, owner string, rrtype uint16) bool {
	existing, err := zd.GetRRset(owner, rrtype)
	if err == nil && existing != nil && len(existing.RRs) > 0 {
		return true
	}
	if zd.MP.CombinerData != nil {
		if ownerData, ok := zd.MP.CombinerData.Get(owner); ok {
			if cdRRset, ok := ownerData.RRtypes.Get(rrtype); ok && len(cdRRset.RRs) > 0 {
				return true
			}
		}
	}
	return false
}

// NewCombinerSyncHandler creates a transport.MessageHandlerFunc for combiner UPDATE processing.
// The handler returns an immediate "pending" ACK in the DNS response and routes the update
// to MsgQs for async processing by CombinerMsgHandler. The actual CombinerProcessUpdate()
// runs asynchronously, and the detailed confirmation is sent back as a separate CONFIRM NOTIFY.
func NewCombinerSyncHandler() transport.MessageHandlerFunc {
	return func(ctx *transport.MessageContext) error {
		lgCombiner.Debug("received update, sending pending ACK", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

		// Build pending ACK for DNS response
		ack := struct {
			Type           string `json:"type"`
			Status         string `json:"status"`
			DistributionID string `json:"distribution_id"`
			Message        string `json:"message"`
			Timestamp      int64  `json:"timestamp"`
		}{
			Type:           "confirm",
			Status:         "pending",
			DistributionID: ctx.DistributionID,
			Message:        "update received, processing asynchronously",
			Timestamp:      time.Now().Unix(),
		}
		ackPayload, err := json.Marshal(ack)
		if err != nil {
			return fmt.Errorf("failed to marshal pending ack: %w", err)
		}
		ctx.Data["response"] = ackPayload

		// Route to MsgQs for async processing via RouteToMsgHandler middleware.
		// incoming_message is already set by ChunkNotifyHandler.parsePayload before the router runs.
		ctx.Data["message_type"] = "update"

		return nil
	}
}

// --- Registration functions ---

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler using ChunkNotifyHandler.
// Creates a ChunkNotifyHandler with combiner-appropriate settings and registers it as a
// NotifyHandlerFunc. Returns CombinerState for error journal access and in-process updates.
func RegisterCombinerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerState, error) {
	state := &CombinerState{
		ErrorJournal: NewErrorJournal(1000, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil, // Set after router initialization
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	if secureWrapper != nil && secureWrapper.IsEnabled() {
		lgCombiner.Info("registering CHUNK handler with crypto enabled", "localID", localID)
	} else {
		lgCombiner.Info("registering CHUNK handler", "localID", localID)
	}

	// Wire FetchChunkQuery for chunk_mode=query (combiner has no DNSTransport)
	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	// Store handler reference in state so main_initfuncs can set Router after initialization
	state.chunkHandler = handler

	return state, nil
}

// RegisterSignerChunkHandler registers a CHUNK NOTIFY handler for the signer (tdns-auth).
// Uses ChunkNotifyHandler — the signer only routes messages through the signer router
// which handles ping and KEYSTATE.
func RegisterSignerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerState, error) {
	state := &CombinerState{
		ErrorJournal: NewErrorJournal(100, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil, // Set after router initialization via SetRouter()
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	// Wire FetchChunkQuery for chunk_mode=query (signer has no DNSTransport)
	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	if secureWrapper != nil && secureWrapper.IsEnabled() {
		lgCombiner.Info("registering signer CHUNK handler with crypto enabled", "localID", localID)
	} else {
		lgCombiner.Info("registering signer CHUNK handler", "localID", localID)
	}
	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	state.chunkHandler = handler

	return state, nil
}

// SetRouter sets the router on the underlying ChunkNotifyHandler.
// Called from main_initfuncs.go after the router is initialized.
func (cs *CombinerState) SetRouter(router *transport.DNSMessageRouter) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.Router = router
	}
}

// SetSecureWrapper sets the secure wrapper on the underlying ChunkNotifyHandler.
func (cs *CombinerState) SetSecureWrapper(sw *transport.SecurePayloadWrapper) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.SecureWrapper = sw
	}
}

// SetGetPeerAddress sets the GetPeerAddress callback on the underlying ChunkNotifyHandler.
func (cs *CombinerState) SetGetPeerAddress(fn func(senderID string) (address string, ok bool)) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.GetPeerAddress = fn
	}
}

// fetchChunkPayloadViaQuery queries the given DNS server for qname CHUNK and returns the first CHUNK RR's Data.
// Used as the FetchChunkQuery callback for combiner/signer ChunkNotifyHandlers.
func fetchChunkPayloadViaQuery(ctx context.Context, serverAddr, qname string) ([]byte, error) {
	// Ensure server has a port (default 53)
	if host, port, err := net.SplitHostPort(serverAddr); err != nil {
		if host != "" {
			serverAddr = net.JoinHostPort(host, "53")
		} else {
			serverAddr = net.JoinHostPort(serverAddr, "53")
		}
	} else if port == "" {
		serverAddr = net.JoinHostPort(host, "53")
	}

	m := new(dns.Msg)
	q := dns.Fqdn(qname)
	m.SetQuestion(q, core.TypeCHUNK)
	m.RecursionDesired = false

	// Use TCP for CHUNK queries - encrypted payloads (JWS/JWE + base64) are too large for UDP
	c := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}
	in, _, err := c.ExchangeContext(ctx, m, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("CHUNK query %s to %s failed: %w", qname, serverAddr, err)
	}
	if in == nil || in.Rcode != dns.RcodeSuccess {
		rcode := dns.RcodeSuccess
		if in != nil {
			rcode = in.Rcode
		}
		return nil, fmt.Errorf("CHUNK query %s to %s returned rcode %s", qname, serverAddr, dns.RcodeToString[rcode])
	}
	for _, rr := range in.Answer {
		if prr, ok := rr.(*dns.PrivateRR); ok && prr.Hdr.Rrtype == core.TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				return chunk.Data, nil
			}
		}
	}
	return nil, fmt.Errorf("no CHUNK RR in response from %s for qname %s", serverAddr, qname)
}

// --- Helper functions ---

// SendToCombiner is a helper function that sends a sync request to the combiner
// and waits for a response. This is called from SynchedDataEngine.
// For in-process communication, this calls CombinerProcessUpdate directly.
func SendToCombiner(state *CombinerState, req *CombinerSyncRequest) *CombinerSyncResponse {
	if state == nil {
		lgCombiner.Error("state is nil, cannot send update")
		return &CombinerSyncResponse{
			DistributionID: req.DistributionID,
			Zone:           req.Zone,
			Status:         "error",
			Message:        "combiner state not initialized",
			Timestamp:      time.Now(),
		}
	}

	return state.ProcessUpdate(req, nil, nil, nil)
}

// ConvertZoneUpdateToSyncRequest converts a ZoneUpdate to a CombinerSyncRequest.
// Groups records by owner for transport neutrality (same structure as CombinerPost).
func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, senderID string, distributionID string) *CombinerSyncRequest {
	// Group records by owner name
	records := make(map[string][]string)

	// First, add RRs if present (these are individual RRs to add)
	for _, rr := range update.RRs {
		owner := rr.Header().Name
		records[owner] = append(records[owner], rr.String())
	}

	// Also add from RRsets (for backwards compatibility)
	for _, rrset := range update.RRsets {
		for _, rr := range rrset.RRs {
			owner := rr.Header().Name
			records[owner] = append(records[owner], rr.String())
		}
	}

	// Determine sync type from the RRs
	syncType := determineSyncType(update)

	req := &CombinerSyncRequest{
		SenderID:       senderID,
		Zone:           string(update.Zone),
		ZoneClass:      update.ZoneClass,
		SyncType:       syncType,
		Records:        records,
		DistributionID: distributionID,
		Timestamp:      time.Now(),
	}
	if len(update.Operations) > 0 {
		req.Operations = update.Operations
	}
	if update.Publish != nil {
		req.Publish = update.Publish
	}
	return req
}

// determineSyncType examines the update and returns an appropriate sync type string.
func determineSyncType(update *ZoneUpdate) string {
	types := make(map[uint16]bool)

	for _, rr := range update.RRs {
		types[rr.Header().Rrtype] = true
	}
	for rrtype := range update.RRsets {
		types[rrtype] = true
	}

	// Return the most specific type, or "MIXED" if multiple types
	if len(types) == 1 {
		for rrtype := range types {
			return dns.TypeToString[rrtype]
		}
	}
	if len(types) > 1 {
		return "MIXED"
	}
	return "UNKNOWN"
}

// --- Policy check functions ---

// checkDNSKEYPolicy checks whether a sender is allowed to contribute DNSKEYs.
// Returns (reject bool, reason string). Rejects if:
// - the zone has no HSYNCPARAM (no signer information)
// - the zone has no signers listed
// - the sender is not listed as a signer
func checkDNSKEYPolicy(zd *ZoneData, senderID string) (bool, string) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return true, "DNSKEY rejected: cannot inspect zone apex"
	}

	hpRRset, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !hpExists || len(hpRRset.RRs) == 0 {
		return true, "DNSKEY rejected: no HSYNCPARAM in zone (cannot determine signers)"
	}
	prr, ok := hpRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return true, "DNSKEY rejected: HSYNCPARAM parse error"
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return true, "DNSKEY rejected: HSYNCPARAM type error"
	}
	signers := hp.GetSigners()
	if len(signers) == 0 {
		return true, "DNSKEY not allowed in unsigned zone (no signers in HSYNCPARAM)"
	}

	h3RRset, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !h3exists || len(h3RRset.RRs) == 0 {
		return true, "DNSKEY rejected: no HSYNC3 records (cannot resolve sender to label)"
	}
	senderLabel := ""
	for _, rr := range h3RRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				if h3.Identity == senderID {
					senderLabel = h3.Label
					break
				}
			}
		}
	}
	if senderLabel == "" {
		return true, fmt.Sprintf("DNSKEY rejected: sender %s not found in zone HSYNC3 records", senderID)
	}

	if !hp.IsSignerLabel(senderLabel) {
		return true, fmt.Sprintf("DNSKEY rejected: sender %s (label %q) is not a signer (signers: %v)", senderID, senderLabel, signers)
	}

	return false, ""
}

// checkContentPolicy applies content-based policy checks to a parsed RR.
// Returns empty string if accepted, or a rejection reason.
func checkContentPolicy(rr dns.RR, protectedNamespaces []string) string {
	if rr.Header().Rrtype == dns.TypeNS && rr.Header().Class == dns.ClassINET {
		return checkNSNamespacePolicy(rr, protectedNamespaces)
	}
	return ""
}

// warnNSTargetUnresolvable logs a warning if an in-bailiwick NS target has no
// address records in the combiner's zone data. Out-of-bailiwick targets are
// skipped (the combiner has no way to verify them without IMR access).
// This is advisory only — it does not reject the NS record.
func warnNSTargetUnresolvable(rr dns.RR, zd *ZoneData) {
	nsRR, ok := rr.(*dns.NS)
	if !ok {
		return
	}
	target := nsRR.Ns
	if !strings.HasSuffix(target, "."+zd.ZoneName) && target != zd.ZoneName {
		return // out-of-bailiwick, skip
	}
	owner, err := zd.GetOwner(target)
	if err != nil || owner == nil {
		lgCombiner.Warn("NS target has no address records (owner not found)", "zone", zd.ZoneName, "nsTarget", target)
		return
	}
	_, hasA := owner.RRtypes.Get(dns.TypeA)
	_, hasAAAA := owner.RRtypes.Get(dns.TypeAAAA)
	if !hasA && !hasAAAA {
		lgCombiner.Warn("NS target has no address records", "zone", zd.ZoneName, "nsTarget", target)
	}
}

// checkNSNamespacePolicy rejects NS records whose targets fall within any of
// our protected namespaces. This prevents remote agents from claiming
// nameservers inside our provider's domains.
//
// Example: if protected-namespaces contains "echo.dnslab.", then an NS record
// targeting "ns7.echo.dnslab." from any remote agent is rejected. But
// "ns12.cooldns.com." from the same agent is accepted (not our namespace).
func checkNSNamespacePolicy(rr dns.RR, protectedNamespaces []string) string {
	if len(protectedNamespaces) == 0 {
		return ""
	}

	nsRR, ok := rr.(*dns.NS)
	if !ok {
		return ""
	}

	target := strings.ToLower(nsRR.Ns)
	for _, ns := range protectedNamespaces {
		ns = strings.ToLower(ns)
		if strings.HasSuffix(target, "."+ns) || target == ns {
			return fmt.Sprintf("NS target %s intrudes on protected namespace %s",
				nsRR.Ns, ns)
		}
	}
	return ""
}
