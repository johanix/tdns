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
	"log"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/miekg/dns"
)

// CombinerMsgHandler consumes beat, hello, ping, and sync messages from MsgQs.
// Updates PeerRegistry liveness on beats and logs hello/ping messages.
// Processes sync messages asynchronously: applies zone updates via CombinerProcessUpdate
// and sends detailed confirmation back to the agent via DNSTransport.Confirm().
func CombinerMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs,
	protectedNamespaces []string, errorJournal *ErrorJournal) {
	if msgQs == nil {
		log.Printf("CombinerMsgHandler: No MsgQs configured, exiting")
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
	if conf.Combiner != nil {
		for _, a := range conf.Combiner.Agents {
			if a != nil && a.Identity != "" {
				localAgents[a.Identity] = true
			}
		}
	}

	log.Printf("CombinerMsgHandler: Starting (peerRegistry=%v, tm=%v, localAgents=%d)",
		peerRegistry != nil, tm != nil, len(localAgents))

	for {
		select {
		case <-ctx.Done():
			log.Printf("CombinerMsgHandler: Context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			log.Printf("CombinerMsgHandler: Beat from %s (interval=%d, distrib=%s)",
				senderID, report.BeatInterval, report.DistributionID)

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
			log.Printf("CombinerMsgHandler: Hello from %s", senderID)

			// Update PeerRegistry on hello
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.SetState(transport.PeerStateOperational, "hello received")
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			log.Printf("CombinerMsgHandler: Ping from %s (distrib=%s)",
				string(report.Identity), report.DistributionID)

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
			log.Printf("CombinerMsgHandler: Processing async update from %s (delivered by %s) zone %s (distrib=%s)",
				senderID, deliveredBy, zone, msg.DistributionID)

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
					log.Printf("CombinerMsgHandler: Failed to persist edit for zone %s: %v", zone, err)
				} else {
					log.Printf("CombinerMsgHandler: Persisted edit #%d from %s for zone %s", editID, senderID, zone)
				}
			}

			// Manual approval gate: if zone has mp-manual-approval, keep the
			// edit pending for operator review.
			if zd, exists := Zones.Get(dns.Fqdn(zone)); exists && zd.Options[OptMPManualApproval] {
				log.Printf("CombinerMsgHandler: Zone %s has mp-manual-approval, edit #%d awaits operator action",
					zone, editID)
				// Send PENDING confirmation to the delivering agent
				combinerSendConfirmation(tm, deliveredBy, &CombinerSyncResponse{
					DistributionID: msg.DistributionID,
					Zone:           zone,
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
				Records:        msg.Records,
				DistributionID: msg.DistributionID,
				Timestamp:      msg.Time,
			}

			// Only apply protected-namespace checks to remote agents.
			// Our own agents are trusted to use our namespaces.
			nsGuard := protectedNamespaces
			if localAgents[senderID] {
				nsGuard = nil
			}
			resp := CombinerProcessUpdate(syncReq, nsGuard)
			if resp.Status == "error" {
				recordCombinerError(errorJournal, msg.DistributionID, senderID, "update", resp.Message, "")
			}

			// Split results into approved and rejected record maps and persist.
			if kdb != nil && editID > 0 {
				approved := rrStringsToOwnerMap(resp.AppliedRecords)
				// Removals were also successfully processed
				for owner, rrs := range rrStringsToOwnerMap(resp.RemovedRecords) {
					approved[owner] = append(approved[owner], rrs...)
				}
				rejected := make(map[string][]string)
				var reasons []string
				for _, ri := range resp.RejectedItems {
					rr, err := dns.NewRR(ri.Record)
					if err != nil {
						continue
					}
					owner := rr.Header().Name
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
					log.Printf("CombinerMsgHandler: Failed to resolve edit #%d: %v", editID, err)
				}
			}

			log.Printf("CombinerMsgHandler: Update processed from %s zone %s: status=%s applied=%d removed=%d rejected=%d",
				senderID, zone, resp.Status, len(resp.AppliedRecords), len(resp.RemovedRecords), len(resp.RejectedItems))

			// Send detailed confirmation back to the delivering agent via DNSTransport.Confirm()
			combinerSendConfirmation(tm, deliveredBy, resp)
		}
	}
}

// combinerSendConfirmation sends the detailed SYNC confirmation back to the originating agent.
// Uses the same DNSTransport.Confirm() mechanism as sendRemoteConfirmation in hsync_transport.go.
func combinerSendConfirmation(tm *TransportManager, senderID string, resp *CombinerSyncResponse) {
	if tm == nil || tm.DNSTransport == nil {
		log.Printf("CombinerMsgHandler: Cannot send confirmation — no DNSTransport (sender=%s, distrib=%s)",
			senderID, resp.DistributionID)
		return
	}

	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		log.Printf("CombinerMsgHandler: Cannot send confirmation — peer %s not in registry", senderID)
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
		Status:         status,
		Message:        resp.Message,
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  rejItems,
		Truncated:      false, // No truncation needed when sending as separate CONFIRM NOTIFY
		Timestamp:      time.Now(),
	})

	if err != nil {
		log.Printf("CombinerMsgHandler: Failed to send confirmation for %s to %s: %v",
			resp.DistributionID, senderID, err)
	} else {
		log.Printf("CombinerMsgHandler: Sent confirmation for %s to %s (status=%s applied=%d removed=%d rejected=%d)",
			resp.DistributionID, senderID, resp.Status,
			len(resp.AppliedRecords), len(resp.RemovedRecords), len(resp.RejectedItems))
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
