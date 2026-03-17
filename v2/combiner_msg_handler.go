/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Combiner message handler goroutine.
 * Consumes beat, hello, ping, and update messages from MsgQs.
 * Update processing runs asynchronously: the DNS handler returns an immediate "pending" ACK,
 * and CombinerMsgHandler applies the update and sends a detailed CONFIRM NOTIFY back.
 */

package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// CombinerMsgHandler consumes beat, hello, ping, and sync messages from MsgQs.
// Updates PeerRegistry liveness on beats and logs hello/ping messages.
// Processes sync messages asynchronously: applies zone updates via CombinerProcessUpdate
// and sends detailed confirmation back to the agent via DNSTransport.Confirm().
func CombinerMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs,
	protectedNamespaces []string, errorJournal *ErrorJournal) {
	if msgQs == nil {
		lgCombiner.Warn("no MsgQs configured, exiting")
		return
	}

	tm := conf.Internal.TransportManager
	var peerRegistry *transport.PeerRegistry
	if tm != nil {
		peerRegistry = tm.PeerRegistry
	}

	// Build set of local agent identities (our own provider's agents).
	// Protected-namespace checks only apply to remote agents, not our own.
	localAgents := make(map[string]bool)
	if conf.MultiProvider != nil {
		for _, a := range conf.MultiProvider.Agents {
			if a != nil && a.Identity != "" {
				localAgents[a.Identity] = true
			}
		}
	}

	lgCombiner.Info("message handler starting", "peerRegistry", peerRegistry != nil, "tm", tm != nil, "localAgents", len(localAgents))

	for {
		select {
		case <-ctx.Done():
			lgCombiner.Info("context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgCombiner.Debug("beat received", "sender", senderID, "interval", report.BeatInterval, "distrib", report.DistributionID)

			// Update PeerRegistry liveness
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.LastBeatReceived = time.Now()
				peer.SetState(transport.PeerStateOperational, "beat received")
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgCombiner.Debug("hello received", "sender", senderID)

			// Update PeerRegistry on hello
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.SetState(transport.PeerStateOperational, "hello received")
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			lgCombiner.Debug("ping received", "sender", string(report.Identity), "distrib", report.DistributionID)

		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg == nil {
				continue
			}
			lgCombiner.Info("STATUS-UPDATE received (no action on combiner)", "zone", statusMsg.Zone, "subtype", statusMsg.SubType, "sender", statusMsg.SenderID)

		case msg := <-msgQs.Msg:
			if msg == nil {
				continue
			}
			senderID := string(msg.OriginatorID)   // Original author of the update
			deliveredBy := string(msg.DeliveredBy) // Agent that delivered it to us
			if deliveredBy == "" {
				deliveredBy = senderID // Fallback: direct delivery
			}
			zone := string(msg.Zone)

			if senderID == "" || (zone == "" && msg.ZoneClass != "provider") {
				lgCombiner.Warn("rejecting message with empty zone or sender", "zone", zone, "sender", senderID)
				continue
			}

			// Handle RFI messages (e.g. RFI EDITS) — dispatch and continue
			if msg.MessageType == AgentMsgRfi {
				lgCombiner.Info("RFI received", "type", msg.RfiType, "sender", senderID, "zone", zone)
				switch msg.RfiType {
				case "EDITS":
					go sendEditsToAgent(conf, tm, senderID, zone)
				default:
					lgCombiner.Warn("unknown RFI type, ignoring", "type", msg.RfiType, "sender", senderID)
				}
				continue
			}

			lgCombiner.Info("processing async update", "sender", senderID, "deliveredBy", deliveredBy, "zone", zone, "distrib", msg.DistributionID)

			kdb := conf.Internal.KeyDB

			// Persist all incoming edits to CombinerPendingEdits first.
			var editID int
			if kdb != nil {
				editID, _ = kdb.NextEditID()
				rec := &PendingEditRecord{
					EditID:         editID,
					Zone:           zone,
					SenderID:       senderID,
					DeliveredBy:    deliveredBy,
					DistributionID: msg.DistributionID,
					Records:        msg.Records,
					ReceivedAt:     time.Now(),
				}
				if err := kdb.SavePendingEdit(rec); err != nil {
					lgCombiner.Error("failed to persist edit", "zone", zone, "err", err)
				} else {
					lgCombiner.Debug("persisted edit", "editID", editID, "sender", senderID, "zone", zone)
				}
			}

			// Manual approval gate: if zone has mp-manual-approval, keep the
			// edit pending for operator review — unless it's a no-op.
			if zd, exists := Zones.Get(dns.Fqdn(zone)); exists && zd.Options[OptMPManualApproval] {
				// Check for no-op: use Operations-aware check when Operations are present
				var noOp bool
				if len(msg.Operations) > 0 {
					noOp = isNoOpOperations(zd, senderID, msg.Operations)
				} else {
					noOp = isNoOpUpdate(zd, senderID, msg.Records)
				}
				if noOp {
					lgCombiner.Debug("no-op edit, auto-confirming", "zone", zone, "editID", editID, "sender", senderID)
					// Clean up the pending edit (move to approved as no-op)
					if kdb != nil && editID > 0 {
						if err := kdb.ResolvePendingEdit(editID, msg.Records, nil, ""); err != nil {
							lgCombiner.Error("failed to resolve no-op edit", "editID", editID, "err", err)
						}
					}
					// Include the original records as AppliedRecords so the
					// agent can match them and transition from pending to accepted.
					var allRRs []string
					if len(msg.Operations) > 0 {
						for _, op := range msg.Operations {
							if op.Operation == "replace" || op.Operation == "add" {
								allRRs = append(allRRs, op.Records...)
							}
						}
					} else {
						for _, rrs := range msg.Records {
							allRRs = append(allRRs, rrs...)
						}
					}
					combinerSendConfirmation(tm, deliveredBy, &CombinerSyncResponse{
						DistributionID: msg.DistributionID,
						Zone:           zone,
						Nonce:          msg.Nonce,
						Status:         "ok",
						Message:        "no changes needed (data already current)",
						AppliedRecords: allRRs,
						Timestamp:      time.Now(),
					})
					continue
				}
				lgCombiner.Info("edit awaits manual approval", "zone", zone, "editID", editID)
				// Send PENDING confirmation to the delivering agent
				combinerSendConfirmation(tm, deliveredBy, &CombinerSyncResponse{
					DistributionID: msg.DistributionID,
					Zone:           zone,
					Nonce:          msg.Nonce,
					Status:         "pending",
					Message:        "update queued for manual approval",
					Timestamp:      time.Now(),
				})
				continue
			}

			// Auto-approve: process the edit immediately.
			syncReq := &CombinerSyncRequest{
				SenderID:       senderID,
				Zone:           zone,
				ZoneClass:      msg.ZoneClass,
				Records:        msg.Records,
				Operations:     msg.Operations,
				Publish:        msg.Publish,
				DistributionID: msg.DistributionID,
				Timestamp:      msg.Time,
			}

			// Only apply protected-namespace checks to remote agents.
			// Our own agents are trusted to use our namespaces.
			nsGuard := protectedNamespaces
			if localAgents[senderID] {
				nsGuard = nil
			}
			resp := CombinerProcessUpdate(syncReq, nsGuard, localAgents, kdb, tm)
			resp.Nonce = msg.Nonce // Echo nonce for confirmation
			if resp.Zone != "" {
				zone = resp.Zone // Update zone from combiner discovery (e.g. provider updates with Zone="")
			}
			if resp.Status == "error" {
				lgCombiner.Error("update failed", "sender", senderID, "zone", zone, "distrib", msg.DistributionID, "reason", resp.Message)
				recordCombinerError(errorJournal, msg.DistributionID, senderID, "update", resp.Message, "")
			}

			// Split results into approved and rejected record maps and persist.
			if kdb != nil && editID > 0 {
				approved := rrStringsToOwnerMap(resp.AppliedRecords)
				// Store removals with ClassNONE so the audit trail preserves ADD/DEL intent
				for owner, rrs := range rrStringsToClassNONE(resp.RemovedRecords) {
					approved[owner] = append(approved[owner], rrs...)
				}
				rejected := make(map[string][]string)
				var reasons []string
				for _, ri := range resp.RejectedItems {
					owner := zone // default for operation-level rejections
					rr, err := dns.NewRR(ri.Record)
					if err == nil {
						owner = rr.Header().Name
					}
					rejected[owner] = append(rejected[owner], ri.Record)
					reasons = append(reasons, ri.Reason)
				}
				reason := ""
				if len(reasons) > 0 {
					reason = reasons[0]
					if len(reasons) > 1 {
						reason = fmt.Sprintf("%s (and %d more)", reason, len(reasons)-1)
					}
				}
				if err := kdb.ResolvePendingEdit(editID, approved, rejected, reason); err != nil {
					lgCombiner.Error("failed to resolve edit", "editID", editID, "err", err)
				}
			}

			lgCombiner.Info("update processed", "sender", senderID, "zone", zone, "status", resp.Status, "applied", len(resp.AppliedRecords), "removed", len(resp.RemovedRecords), "rejected", len(resp.RejectedItems))

			// Send detailed confirmation back to the delivering agent via DNSTransport.Confirm()
			combinerSendConfirmation(tm, deliveredBy, resp)

			// Notify downstream servers (e.g. signer) about the zone change
			// so they can fetch the updated zone promptly instead of waiting
			// for the next periodic SOA refresh.
			// Run async to avoid blocking the message handler on network I/O.
			if resp.Status != "error" {
				if zd, ok := Zones.Get(dns.Fqdn(zone)); ok && len(zd.Downstreams) > 0 {
					go zd.NotifyDownstreams()
				}
			}
		}
	}
}

// combinerSendConfirmation sends the detailed SYNC confirmation back to the originating agent.
// Uses the same DNSTransport.Confirm() mechanism as sendRemoteConfirmation in hsync_transport.go.
func combinerSendConfirmation(tm *TransportManager, senderID string, resp *CombinerSyncResponse) {
	if tm == nil || tm.DNSTransport == nil {
		lgCombiner.Warn("cannot send confirmation, no DNSTransport", "sender", senderID, "distrib", resp.DistributionID)
		return
	}

	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		lgCombiner.Warn("cannot send confirmation, peer not in registry", "sender", senderID)
		return
	}

	// Map combiner status strings to transport ConfirmStatus
	status := transport.ConfirmSuccess
	switch resp.Status {
	case "ok":
		status = transport.ConfirmSuccess
	case "partial":
		status = transport.ConfirmPartial
	case "error":
		status = transport.ConfirmFailed
	case "pending":
		status = transport.ConfirmPending
	}

	var rejItems []transport.RejectedItemDTO
	for _, ri := range resp.RejectedItems {
		rejItems = append(rejItems, transport.RejectedItemDTO{Record: ri.Record, Reason: ri.Reason})
	}

	confirmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(confirmCtx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           resp.Zone,
		DistributionID: resp.DistributionID,
		Nonce:          resp.Nonce,
		Status:         status,
		Message:        resp.Message,
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  rejItems,
		Truncated:      false, // No truncation needed when sending as separate CONFIRM NOTIFY
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgCombiner.Error("failed to send confirmation", "distrib", resp.DistributionID, "sender", senderID, "err", err)
	} else {
		lgCombiner.Debug("sent confirmation", "distrib", resp.DistributionID, "sender", senderID, "status", resp.Status, "applied", len(resp.AppliedRecords), "removed", len(resp.RemovedRecords), "rejected", len(resp.RejectedItems))
	}
}

// rrStringsToOwnerMap parses RR strings and groups them by owner name.
func rrStringsToOwnerMap(rrStrings []string) map[string][]string {
	result := make(map[string][]string)
	for _, rrStr := range rrStrings {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			continue
		}
		owner := rr.Header().Name
		result[owner] = append(result[owner], rrStr)
	}
	return result
}

// sendEditsToAgent looks up the agent's current contributions for the zone and sends
// them back via DNSTransport.Edits(). Called asynchronously from CombinerMsgHandler
// when an RFI EDITS is received.
// Modeled on sendKeystateInventoryToAgent in signer_msg_handler.go.
func sendEditsToAgent(conf *Config, tm *TransportManager, agentID string, zone string) {
	zd, exists := Zones.Get(dns.Fqdn(zone))
	if !exists {
		lgCombiner.Warn("RFI EDITS: zone not found", "zone", zone, "agent", agentID)
		return
	}

	// Extract this agent's contributions (may be nil if no prior edits)
	records := contributionsToRecords(zd.AgentContributions[agentID])

	lgCombiner.Debug("RFI EDITS: preparing response", "zone", zone, "agent", agentID, "owners", len(records))

	if tm == nil || tm.DNSTransport == nil {
		lgCombiner.Warn("RFI EDITS: no DNSTransport available", "agent", agentID)
		return
	}

	peer, peerExists := tm.PeerRegistry.Get(agentID)
	if !peerExists || peer == nil {
		lgCombiner.Warn("RFI EDITS: agent not in PeerRegistry", "agent", agentID)
		return
	}

	req := &transport.EditsRequest{
		SenderID:  conf.MultiProvider.Identity,
		Zone:      zone,
		Records:   records,
		Timestamp: time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.DNSTransport.Edits(sendCtx, peer, req)
	if err != nil {
		lgCombiner.Error("RFI EDITS: failed to send", "agent", agentID, "zone", zone, "err", err)
		return
	}

	lgCombiner.Info("RFI EDITS: sent contributions to agent", "agent", agentID, "zone", zone, "owners", len(records), "accepted", resp.Accepted)
}

// contributionsToRecords converts an agent's contributions map to the flat
// map[string][]string format used by sync/update messages.
func contributionsToRecords(contributions map[string]map[uint16]core.RRset) map[string][]string {
	result := make(map[string][]string)
	if contributions == nil {
		return result
	}
	for owner, rrtypeMap := range contributions {
		for _, rrset := range rrtypeMap {
			for _, rr := range rrset.RRs {
				result[owner] = append(result[owner], rr.String())
			}
		}
	}
	return result
}

// rrStringsToClassNONE parses RR strings, converts them to ClassNONE (to mark
// as deletions in the audit trail), and groups them by owner name.
func rrStringsToClassNONE(rrStrings []string) map[string][]string {
	result := make(map[string][]string)
	for _, rrStr := range rrStrings {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			continue
		}
		owner := rr.Header().Name
		rr.Header().Class = dns.ClassNONE
		result[owner] = append(result[owner], rr.String())
	}
	return result
}
