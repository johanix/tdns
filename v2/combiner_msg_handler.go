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
	"log"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
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

	log.Printf("CombinerMsgHandler: Starting (peerRegistry=%v, tm=%v)", peerRegistry != nil, tm != nil)

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
			senderID := string(msg.MyIdentity)
			zone := string(msg.Zone)
			log.Printf("CombinerMsgHandler: Processing async update from %s zone %s (distrib=%s)",
				senderID, zone, msg.DistributionID)

			// Build CombinerSyncRequest from AgentMsgPostPlus
			syncReq := &CombinerSyncRequest{
				SenderID:       senderID,
				Zone:           zone,
				Records:        msg.Records,
				DistributionID: msg.DistributionID,
				Timestamp:      msg.Time,
			}

			resp := CombinerProcessUpdate(syncReq, protectedNamespaces)
			if resp.Status == "error" {
				recordCombinerError(errorJournal, msg.DistributionID, senderID, "update", resp.Message, "")
			}

			log.Printf("CombinerMsgHandler: Update processed from %s zone %s: status=%s applied=%d removed=%d rejected=%d",
				senderID, zone, resp.Status, len(resp.AppliedRecords), len(resp.RemovedRecords), len(resp.RejectedItems))

			// Send detailed confirmation back to agent via DNSTransport.Confirm()
			combinerSendConfirmation(tm, senderID, resp)
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
