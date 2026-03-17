package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	agenttransport "github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var lgEngine = Logger("engine")
var lgConnRetryEngine = Logger("conn-retry")

type SyncRequest struct {
	Command      string
	ZoneName     ZoneName
	ZoneData     *ZoneData
	SyncStatus   *HsyncStatus
	OldDnskeys   *core.RRset
	NewDnskeys   *core.RRset
	DnskeyStatus *DnskeyStatus // Local DNSKEY adds/removes (Phase 5)
	Response     chan SyncResponse
}

type SyncResponse struct {
	Status   bool
	Error    bool
	ErrorMsg string
	Msg      string
}

type SyncStatus struct {
	Identity AgentId
	Agents   map[AgentId]*Agent
	Error    bool
	Response chan SyncStatus
}

// Define task struct for deferred operations
type DeferredTask struct {
	Action      string
	Target      string
	ZoneName    string
	RetryCount  int
	MaxRetries  int
	LastAttempt time.Time
}

func HsyncEngine(ctx context.Context, conf *Config, msgQs *MsgQs) {
	ourId := AgentId(conf.MultiProvider.Identity)

	helloQ := msgQs.Hello
	heartbeatQ := msgQs.Beat
	msgQ := msgQs.Msg
	commandQ := msgQs.Command
	debugCommandQ := msgQs.DebugCommand
	synchedDataUpdateQ := msgQs.SynchedDataUpdate
	registry := conf.Internal.AgentRegistry
	registry.LocalAgent.Identity = string(ourId) // Make sure registry knows our identity

	var syncitem SyncRequest
	syncQ := conf.Internal.SyncQ

	var msgReport *AgentMsgReport
	var mgmtPost *AgentMgmtPostPlus
	var msgPost *AgentMsgPostPlus
	conf.Internal.SyncStatusQ = make(chan SyncStatus, 10)

	// Configure intervals
	heartbeatInterval := configureInterval("agent.remote.beatinterval", 15, 1800)

	lgEngine.Info("starting", "heartbeat_interval", heartbeatInterval)

	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("context cancelled, stopping")
			HBticker.Stop()
			return
		case syncitem = <-syncQ:
			registry.SyncRequestHandler(ourId, syncitem, synchedDataUpdateQ)

		case msgReport = <-helloQ:
			registry.HelloHandler(msgReport)

		case msgReport = <-heartbeatQ:
			registry.HeartbeatHandler(msgReport)

		case msgPost = <-msgQ:
			registry.MsgHandler(msgPost, synchedDataUpdateQ, msgQs.SynchedDataCmd)

		case mgmtPost = <-commandQ:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ)

		// debug stuff arrive on separate channel, but use the same format and handler
		case mgmtPost = <-debugCommandQ:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ)

		case <-HBticker.C:
			registry.SendHeartbeats()

		case req := <-conf.Internal.SyncStatusQ:
			registry.HandleStatusRequest(req)

		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg == nil {
				break
			}
			lgEngine.Info("STATUS-UPDATE received", "zone", statusMsg.Zone, "subtype", statusMsg.SubType, "sender", statusMsg.SenderID)
			switch statusMsg.SubType {
			case "ns-changed", "ksk-changed":
				// Only the leader agent should sync delegation with parent
				lem := conf.Internal.LeaderElectionManager
				if lem != nil && !lem.IsLeader(ZoneName(statusMsg.Zone)) {
					lgEngine.Info("STATUS-UPDATE: not the delegation sync leader, ignoring", "zone", statusMsg.Zone, "subtype", statusMsg.SubType)
					break
				}
				zd, exists := Zones.Get(statusMsg.Zone)
				if !exists {
					lgEngine.Warn("STATUS-UPDATE: zone not found", "zone", statusMsg.Zone)
					break
				}
				lgEngine.Info("STATUS-UPDATE: enqueuing EXPLICIT-SYNC-DELEGATION", "zone", statusMsg.Zone, "subtype", statusMsg.SubType)
				zd.DelegationSyncQ <- DelegationSyncRequest{
					Command:  "EXPLICIT-SYNC-DELEGATION",
					ZoneName: statusMsg.Zone,
					ZoneData: zd,
				}
			case "parentsync-done":
				lgEngine.Info("STATUS-UPDATE: parent sync completed by leader", "zone", statusMsg.Zone, "result", statusMsg.Result, "msg", statusMsg.Msg)
			default:
				lgEngine.Warn("STATUS-UPDATE: unknown subtype", "zone", statusMsg.Zone, "subtype", statusMsg.SubType)
			}

		case inventoryMsg := <-msgQs.KeystateInventory:
			// Proactive KEYSTATE inventory push from signer.
			// Store the inventory and check for DNSKEY changes.
			zd, exists := Zones.Get(inventoryMsg.Zone)
			if !exists {
				lgEngine.Warn("proactive inventory: zone not found", "zone", inventoryMsg.Zone)
				break
			}
			zd.SetLastKeyInventory(&KeyInventorySnapshot{
				SenderID:  inventoryMsg.SenderID,
				Zone:      inventoryMsg.Zone,
				Inventory: inventoryMsg.Inventory,
				Received:  time.Now(),
			})
			changed, ds, err := zd.LocalDnskeysFromKeystate()
			if err != nil {
				lgEngine.Error("proactive inventory: LocalDnskeysFromKeystate failed", "zone", inventoryMsg.Zone, "err", err)
				break
			}
			if !changed {
				lgEngine.Debug("proactive inventory: no DNSKEY changes", "zone", inventoryMsg.Zone)
				break
			}
			lgEngine.Info("proactive inventory: DNSKEY changes detected, triggering sync", "zone", inventoryMsg.Zone, "adds", len(ds.LocalAdds), "removes", len(ds.LocalRemoves))
			registry.SyncRequestHandler(ourId, SyncRequest{
				ZoneName:     ZoneName(inventoryMsg.Zone),
				Command:      "SYNC-DNSKEY-RRSET",
				DnskeyStatus: ds,
			}, synchedDataUpdateQ)
		}
	}
}

// DiscoveryRetrierNG continuously attempts to discover agents in NEEDED state.
// It runs in its own goroutine with a configurable retry interval and only
// attempts discovery when the IMR engine is available.
func (ar *AgentRegistry) DiscoveryRetrierNG(ctx context.Context) {
	discoveryRetryInterval := configureInterval("agent.syncengine.intervals.discoveryretry", 15, 1800)
	lgEngine.Info("discovery retrier starting", "interval", discoveryRetryInterval)

	ticker := time.NewTicker(time.Duration(discoveryRetryInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("discovery retrier context cancelled, stopping")
			return
		case <-ticker.C:
			ar.retryPendingDiscoveries()
		}
	}
}

// retryPendingDiscoveries attempts discovery for all agents in NEEDED state.
// Skips the iteration if IMR engine is not yet available (will retry next tick).
func (ar *AgentRegistry) retryPendingDiscoveries() {
	// Get IMR engine - skip iteration if not ready yet (will retry next tick)
	imr := Conf.Internal.ImrEngine
	if imr == nil {
		lgEngine.Debug("IMR engine not ready, will retry next interval")
		return
	}

	// Find all agents in NEEDED state
	neededCount := 0
	for _, agent := range ar.S.Items() {
		agent.mu.RLock()
		apiNeeded := agent.ApiMethod && agent.ApiDetails.State == AgentStateNeeded
		dnsNeeded := agent.DnsMethod && agent.DnsDetails.State == AgentStateNeeded
		agent.mu.RUnlock()

		if !apiNeeded && !dnsNeeded {
			continue
		}

		neededCount++
		// Spawn async discovery attempt — only discover the transports
		// that are actually in NEEDED state (non-blocking)
		go ar.attemptDiscovery(agent, imr, apiNeeded, dnsNeeded)
	}

	if neededCount > 0 {
		lgEngine.Info("attempting discovery for agents in NEEDED state", "count", neededCount)
	}
}

func configureInterval(key string, min, max int) int {
	interval := viper.GetInt(key)
	if interval > max {
		interval = max
	}
	if interval < min {
		interval = min
	}
	viper.Set(key, interval)
	return interval
}

func (ar *AgentRegistry) SyncRequestHandler(ourId AgentId, req SyncRequest, synchedDataUpdateQ chan *SynchedDataUpdate) {
	lgEngine.Debug("sync request received", "zone", req.ZoneName)
	switch req.Command {
	case "HSYNC-UPDATE":
		lgEngine.Info("HSYNC RRset changed, updating agents", "zone", req.ZoneName)
		// Run UpdateAgents without waiting for completion
		go func() {
			err := ar.UpdateAgents(ourId, req, req.ZoneName, synchedDataUpdateQ)
			if err != nil {
				lgEngine.Error("error updating agents", "zone", req.ZoneName, "err", err)
			}
			// Send response if needed
			if req.Response != nil {
				req.Response <- SyncResponse{
					Status: err == nil,
					Error:  err != nil,
					ErrorMsg: func() string {
						if err != nil {
							return err.Error()
						}
						return ""
					}(),
					Msg: "Agent updates processed",
				}
			}
		}()

	case "SYNC-DNSKEY-RRSET":
		lgEngine.Info("DNSKEY RRset changed", "zone", req.ZoneName)

		if req.DnskeyStatus == nil {
			lgEngine.Warn("SYNC-DNSKEY-RRSET but no DnskeyStatus, ignoring", "zone", req.ZoneName)
			break
		}

		ds := req.DnskeyStatus
		totalChanges := len(ds.LocalAdds) + len(ds.LocalRemoves)
		if totalChanges == 0 {
			lgEngine.Debug("DNSKEY changed but no local key changes (remote keys only), ignoring", "zone", req.ZoneName)
			break
		}

		lgEngine.Info("local DNSKEY changes, feeding into SynchedDataEngine", "zone", req.ZoneName, "adds", len(ds.LocalAdds), "removes", len(ds.LocalRemoves))

		// Build RR list for local SDE storage: adds use ClassINET, removes use ClassNONE.
		// Extract key tags from both adds and removes for DNSKEY propagation tracking.
		var rrs []dns.RR
		var keyTags []uint16
		for _, rr := range ds.LocalAdds {
			rrs = append(rrs, dns.Copy(rr))
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				keyTags = append(keyTags, dnskey.KeyTag())
			}
		}
		for _, rr := range ds.LocalRemoves {
			rrCopy := dns.Copy(rr)
			rrCopy.Header().Class = dns.ClassNONE
			rrs = append(rrs, rrCopy)
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				keyTags = append(keyTags, dnskey.KeyTag())
			}
		}

		// Build REPLACE operation: the complete current set of local DNSKEYs.
		// Remote agents receive "here are all our DNSKEYs — make yours match"
		// instead of individual add/delete instructions.
		var dnskeyRRStrings []string
		for _, rr := range ds.CurrentLocalKeys {
			dnskeyRRStrings = append(dnskeyRRStrings, rr.String())
		}
		ops := []core.RROperation{{
			Operation: "replace",
			RRtype:    "DNSKEY",
			Records:   dnskeyRRStrings,
		}}

		zu := &ZoneUpdate{
			Zone:       req.ZoneName,
			RRs:        rrs,
			RRsets:     make(map[uint16]core.RRset),
			Operations: ops,
		}
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			rrset := zu.RRsets[rrtype]
			rrset.RRs = append(rrset.RRs, rr)
			zu.RRsets[rrtype] = rrset
		}

		// Feed into SynchedDataEngine as local data — same path as "agent zone addrr".
		// SynchedDataEngine stores the data and distributes to remote agents.
		// SkipCombiner: local DNSKEYs don't need to go to the combiner — the signer
		// adds its own keys during signing. Only remote agents need our DNSKEY changes.
		// DnskeyKeyTags: enables propagation tracking so the agent sends KEYSTATE
		// "propagated" back to the signer when all remote agents confirm.
		synchedDataUpdateQ <- &SynchedDataUpdate{
			Zone:          req.ZoneName,
			AgentId:       ourId,
			UpdateType:    "local",
			Update:        zu,
			SkipCombiner:  true,
			DnskeyKeyTags: keyTags,
		}

	default:
		lgEngine.Warn("unknown command", "command", req.Command)
	}
}

// Handler for messages received from other agents
func (ar *AgentRegistry) MsgHandler(ampp *AgentMsgPostPlus, synchedDataUpdateQ chan *SynchedDataUpdate, synchedDataCmdQ chan *SynchedDataCmd) {
	lgEngine.Info("received message", "type", AgentMsgToString[ampp.MessageType], "from", ampp.OriginatorID)

	// var resp = SynchedDataResponse{
	var resp = AgentMsgResponse{
		Time:        time.Now(),
		Status:      "ok",
		Msg:         "Message received",
		RfiResponse: map[AgentId]*RfiData{},
	}

	defer func() {
		if ampp.Response != nil {
			select {
			case ampp.Response <- &resp:
				// log.Printf("MsgHandler: Response %+v sent to API handler", resp, ampp.OriginatorID)
			default:
				lgEngine.Warn("response channel blocked, skipping response")
			}
		}
	}()

	// Check if the zone exists (i.e. we have this zone under management)
	_, exists := Zones.Get(string(ampp.Zone))
	if !exists {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown zone: %s", ar.LocalAgent.Identity, ampp.Zone)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown zone: %s", ar.LocalAgent.Identity, ampp.Zone)
		return
	}

	// Check if we are present in the zone HSYNC RRset (i.e. we have an agent role in this zone)
	zad, err := ar.GetZoneAgentData(ampp.Zone)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Zone %s does not have a HSYNC RRset", ar.LocalAgent.Identity, ampp.Zone)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Zone %s does not have a HSYNC RRset", ar.LocalAgent.Identity, ampp.Zone)
		return
	}

	switch ampp.MessageType {
	case AgentMsgNotify:
		// if amp, ok := ampp.Msg.(*AgentMsgPost); ok {
		//	log.Printf("MsgHandler: Contained AgentMsgPost struct from %s: %+v", amp.OriginatorID, amp)

		var zu = &ZoneUpdate{
			Zone:    ampp.Zone,
			AgentId: ampp.OriginatorID,
			RRsets:  map[uint16]core.RRset{},
		}

		// Prefer Operations over Records when both are present
		if len(ampp.Operations) > 0 {
			zu.Operations = ampp.Operations
		}

		// Parse Records into RRsets (used for legacy path and local SDE storage)
		for _, rrStrs := range ampp.Records {
			for _, rrstr := range rrStrs {
				rr, err := dns.NewRR(rrstr)
				if err != nil {
					lgEngine.Error("error parsing RR", "rr", rrstr, "err", err)
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Error parsing RR %q: %v", rrstr, err)
					return
				}
				var rrset core.RRset
				var ok bool
				rrtype := rr.Header().Rrtype
				if rrset, ok = zu.RRsets[rrtype]; !ok {
					rrset = core.RRset{}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
				lgEngine.Debug("parsed RR", "rr", rr)
			}
		}

		var cresp = make(chan *AgentMsgResponse, 1)
		synchedDataUpdateQ <- &SynchedDataUpdate{
			Zone:              ampp.Zone,
			AgentId:           ampp.OriginatorID,
			UpdateType:        "remote",
			Update:            zu,
			OriginatingDistID: ampp.DistributionID,
			Response:          cresp,
		}
		select {
		case r := <-cresp:
			if r.Error {
				lgEngine.Error("error processing update", "from", ampp.OriginatorID, "err", r.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = r.ErrorMsg
			}
		case <-time.After(3 * time.Second):
			lgEngine.Warn("no response from SynchedDataEngine after 3s", "from", ampp.OriginatorID)
		}

	case AgentMsgRfi:
		// Process the RFI
		lgEngine.Info("received RFI request", "from", ampp.OriginatorID, "type", ampp.RfiType, "subtype", ampp.RfiSubtype, "zone", ampp.Zone)

		switch ampp.RfiType {
		case "SYNC":
			// Remote agent asks us to re-send all our local data.
			lgEngine.Info("RFI SYNC triggering local resync", "from", ampp.OriginatorID, "zone", ampp.Zone)
			sdcmd := &SynchedDataCmd{
				Cmd:      "resync",
				Zone:     ZoneName(ampp.Zone),
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			synchedDataCmdQ <- sdcmd
			select {
			case sdResp := <-sdcmd.Response:
				if sdResp.Error {
					resp.Error = true
					resp.ErrorMsg = sdResp.ErrorMsg
				} else {
					resp.Msg = fmt.Sprintf("Resync triggered: %s", sdResp.Msg)
				}
			case <-time.After(10 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "Timeout waiting for resync"
			}

		case "AUDIT":
			// Remote agent wants audit data for this zone.
			// Two-phase: gather audit data, then send as separate AUDIT message.
			lgEngine.Info("RFI AUDIT request", "from", ampp.OriginatorID, "zone", ampp.Zone)
			tm := ar.TransportManager
			if tm == nil {
				lgEngine.Error("RFI AUDIT: TransportManager not available", "zone", ampp.Zone, "originator", ampp.OriginatorID)
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available"
				resp.Msg = "AUDIT request failed: transport unavailable"
				return
			}
			sdcmd := &SynchedDataCmd{
				Cmd:      "dump-zonedatarepo",
				Zone:     ZoneName(ampp.Zone),
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			synchedDataCmdQ <- sdcmd
			go func() {
				select {
				case sdResp := <-sdcmd.Response:
					if sdResp.Error {
						lgEngine.Error("RFI AUDIT: failed to get audit data", "zone", ampp.Zone, "err", sdResp.ErrorMsg)
						return
					}
					sendAuditToAgent(tm, ar, string(ampp.OriginatorID), string(ampp.Zone), sdResp.ZDR)
				case <-time.After(5 * time.Second):
					lgEngine.Error("RFI AUDIT: timeout getting audit data", "zone", ampp.Zone)
				}
			}()
			resp.Msg = "AUDIT request received, response pending"

		case "ELECT-CALL", "ELECT-VOTE", "ELECT-CONFIRM":
			// Log election-specific details from records
			electionDetails := []interface{}{"from", ampp.OriginatorID, "zone", ampp.Zone}
			if terms, ok := ampp.Records["_term"]; ok && len(terms) > 0 {
				electionDetails = append(electionDetails, "term", terms[0])
			}
			if votes, ok := ampp.Records["_vote"]; ok && len(votes) > 0 {
				electionDetails = append(electionDetails, "vote", votes[0])
			}
			if winners, ok := ampp.Records["_winner"]; ok && len(winners) > 0 {
				electionDetails = append(electionDetails, "winner", winners[0])
			}
			lgEngine.Info("election message "+ampp.RfiType, electionDetails...)
			if ar.LeaderElectionManager != nil {
				ar.LeaderElectionManager.HandleMessage(ampp.Zone, ampp.OriginatorID, ampp.RfiType, ampp.Records)
			}

		case "CONFIG":
			if ampp.RfiSubtype == "" {
				lgEngine.Error("CONFIG RFI missing subtype", "from", ampp.OriginatorID, "zone", ampp.Zone)
				resp.Error = true
				resp.ErrorMsg = "CONFIG RFI missing subtype"
				return
			}

			// Gather config data for the requested subtype.
			var configData map[string]string
			var configErr string

			switch ampp.RfiSubtype {
			case "upstream":
				// Remote agent has us as upstream — return our outgoing XFR config.
				found := false
				for _, aid := range zad.MyDownstreams {
					if aid == ampp.OriginatorID {
						found = true
						break
					}
				}
				if !found {
					configErr = fmt.Sprintf("%s: CONFIG upstream request, but remote agent %q is not a downstream agent", ar.LocalAgent.Identity, ampp.OriginatorID)
				} else if len(ar.LocalAgent.Xfr.Outgoing.Addresses) == 0 {
					configErr = fmt.Sprintf("%s: CONFIG upstream request, but no outgoing XFR config", ar.LocalAgent.Identity)
				} else {
					lgEngine.Info("CONFIG upstream: returning XFR config to peer", "from", ampp.OriginatorID)
					configData = map[string]string{
						"xfr_srcs": strings.Join(ar.LocalAgent.Xfr.Outgoing.Addresses, ","),
						"xfr_auth": strings.Join(ar.LocalAgent.Xfr.Outgoing.Auth, ","),
					}
				}

			case "downstream":
				// Remote agent has us as downstream — return our incoming XFR config.
				if zad.MyUpstream != ampp.OriginatorID {
					configErr = fmt.Sprintf("%s: CONFIG downstream request, but remote agent %q is not our upstream agent", ar.LocalAgent.Identity, ampp.OriginatorID)
				} else if len(ar.LocalAgent.Xfr.Incoming.Addresses) == 0 {
					configErr = fmt.Sprintf("%s: CONFIG downstream request, but no incoming XFR config", ar.LocalAgent.Identity)
				} else {
					lgEngine.Info("CONFIG downstream: returning XFR config to peer", "from", ampp.OriginatorID)
					configData = map[string]string{
						"xfr_dsts": strings.Join(ar.LocalAgent.Xfr.Incoming.Addresses, ","),
						"xfr_auth": strings.Join(ar.LocalAgent.Xfr.Incoming.Auth, ","),
					}
				}

			case "sig0key":
				// Verify the requestor is an authorized peer (upstream or downstream) before
				// returning private key material.
				isAuthorized := false
				if zad.MyUpstream == ampp.OriginatorID {
					isAuthorized = true
				} else {
					for _, aid := range zad.MyDownstreams {
						if aid == ampp.OriginatorID {
							isAuthorized = true
							break
						}
					}
				}
				if !isAuthorized {
					configErr = fmt.Sprintf("%s: CONFIG sig0key request denied — %q is not an authorized peer for zone %s", ar.LocalAgent.Identity, ampp.OriginatorID, ampp.Zone)
				} else if zd, ok := Zones.Get(string(ampp.Zone)); !ok || zd == nil || zd.KeyDB == nil {
					configErr = "zone or KeyDB not available"
				} else {
					algorithm, privatekey, keyrr, found, err := zd.KeyDB.GetSig0KeyRaw(string(ampp.Zone), Sig0StateActive)
					if err != nil {
						configErr = fmt.Sprintf("error looking up SIG(0) key: %v", err)
					} else if !found {
						configData = map[string]string{"status": "no sig0 key for zone"}
					} else {
						lgEngine.Info("CONFIG sig0key: returning key to peer", "zone", ampp.Zone, "peer", ampp.OriginatorID)
						configData = map[string]string{
							"algorithm":  algorithm,
							"privatekey": privatekey,
							"keyrr":      keyrr,
						}
					}
				}

			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown CONFIG subtype: %s", ampp.RfiSubtype)
				return
			}

			if configErr != "" {
				resp.Error = true
				resp.ErrorMsg = configErr
				resp.Msg = configErr
				return
			}

			// Send config data back as a separate CONFIG message (two-phase pattern).
			tm := ar.TransportManager
			if tm == nil {
				lgEngine.Error("RFI CONFIG: TransportManager not available", "zone", ampp.Zone, "originator", ampp.OriginatorID)
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available"
				resp.Msg = "CONFIG request failed: transport unavailable"
				return
			}
			go sendConfigToAgent(tm, ar, string(ampp.OriginatorID), string(ampp.Zone), ampp.RfiSubtype, configData)
			resp.Msg = fmt.Sprintf("CONFIG %s request received, response pending", ampp.RfiSubtype)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown RFI type: %s", ar.LocalAgent.Identity, ampp.RfiType)
			resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown RFI type: %s", ar.LocalAgent.Identity, ampp.RfiType)
		}

	default:
		lgEngine.Warn("unknown message type", "type", ampp.MessageType)
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown message type: %+v", ar.LocalAgent.Identity, ampp.MessageType)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown message type: %+v", ar.LocalAgent.Identity, ampp.MessageType)
	}
}

// Handler for local commands from CLI or other components in the same organization
func (ar *AgentRegistry) CommandHandler(msg *AgentMgmtPostPlus, synchedDataUpdateQ chan *SynchedDataUpdate) {

	lgEngine.Info("received mgmt command", "command", msg.Command, "zone", msg.Zone)
	resp := AgentMgmtResponse{
		Identity:    AgentId(ar.LocalAgent.Identity), // Our identity, sent back to the originator (typically a CLI command)
		Time:        time.Now(),
		Msg:         "Command received",
		RfiResponse: map[AgentId]*RfiData{},
	}

	defer func() {
		if resp.ErrorMsg != "" {
			lgEngine.Error("command handler error", "err", resp.ErrorMsg)
		}
		if msg.Response != nil {
			select {
			case msg.Response <- &resp:
			default:
				lgEngine.Warn("command handler response channel blocked, skipping response")
			}
		}
	}()

	// Extract zone from message
	if msg.Zone == "" {
		resp.Error = true
		resp.ErrorMsg = "No zone specified in mgmt command"
		// log.Printf("CommandHandler: No zone specified in mgmt command")
		return
	}

	for _, rrstr := range msg.RRs {
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error parsing RR: %s", err)
			// log.Printf("CommandHandler: Error parsing RR: %s", err)
			return
		}
		lgEngine.Debug("command handler parsed RR", "rr", rr)
	}

	// Find remote agents for this zone
	// zad, err := ar.GetZoneAgentData(msg.Zone)
	// if err != nil {
	// 	resp.Error = true
	// 	resp.ErrorMsg = fmt.Sprintf("Error getting zone agent data for zone %s: %v", msg.Zone, err)
	// 	// log.Printf("CommandHandler: Error getting remote agents for zone %s: %v", msg.Zone, err)
	// 	return
	// }
	// if len(zad.Agents) == 0 {
	// 	resp.Error = true
	// 	resp.ErrorMsg = fmt.Sprintf("No remote agents found for zone %s", msg.Zone)
	// 	// log.Printf("CommandHandler: No remote agents found for zone %s", msg.Zone)
	// 	return
	// }

	// Get all remote agents for this zone (no operational state filtering).
	// The ReliableMessageQueue handles delivery deferral for non-operational agents.
	zad, err := ar.GetZoneAgentData(msg.Zone)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Error getting remote agents for zone %s: %v", msg.Zone, err)
		return
	}

	var errstrs []string

	switch msg.Command { // msg.MessageType {

	case "send-notify":
		lgEngine.Info("sending notify to agents", "type", AgentMsgToString[msg.MessageType], "agents", len(zad.Agents))

		// Send message to each agent (use TransportManager fallback when available)
		for _, agent := range zad.Agents {
			var syncErr error
			var syncMsg string
			var syncFailed bool

			if ar.TransportManager != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				peer := ar.TransportManager.SyncPeerFromAgent(agent)
				syncReq := &agenttransport.SyncRequest{
					SenderID:    ar.LocalAgent.Identity,
					Zone:        string(msg.Zone),
					SyncType:    agenttransport.SyncTypeNS,
					Records:     groupRRStringsByOwner(msg.RRs),
					Timestamp:   time.Now(),
					MessageType: "sync",
				}
				syncResp, err := ar.TransportManager.SendSyncWithFallback(ctx, peer, syncReq)
				cancel()
				if err != nil {
					syncErr = err
					syncFailed = true
					syncMsg = err.Error()
				} else if syncResp != nil && syncResp.Status != agenttransport.ConfirmSuccess {
					syncFailed = true
					syncMsg = syncResp.Message
				} else if syncResp != nil {
					syncMsg = syncResp.Message
				}
			} else {
				amr, err := agent.SendApiMsg(&AgentMsgPost{
					MessageType:  AgentMsgNotify,
					OriginatorID: AgentId(ar.LocalAgent.Identity),
					YourIdentity: agent.Identity,
					Zone:         msg.Zone,
					Records:      groupRRStringsByOwner(msg.RRs),
					Time:         time.Now(),
				})
				if err != nil {
					syncErr = err
					syncFailed = true
					syncMsg = err.Error()
				} else {
					syncMsg = amr.Msg
					syncFailed = amr.Error
					if amr.ErrorMsg != "" {
						syncMsg = amr.ErrorMsg
					}
				}
			}

			if syncErr != nil {
				lgEngine.Error("error sending message to agent", "agent", agent.Identity, "err", syncErr)
				errstrs = append(errstrs, fmt.Sprintf("Error sending message to agent %s: %v", agent.Identity, syncErr))
				continue
			}
			resp.Msg = syncMsg
			resp.Error = syncFailed
			if syncFailed {
				resp.ErrorMsg = syncMsg
			}
		}
		if len(errstrs) > 0 {
			resp.Error = true
			resp.ErrorMsg = strings.Join(errstrs, "\n")
		}

	case "send-rfi":
		lgEngine.Info("sending RFI message to agents", "rfiType", msg.RfiType, "subtype", msg.RfiSubtype, "agents", len(zad.Agents))
		switch msg.RfiType {
		case "CONFIG":
			// CONFIG RFI uses two-phase: send RFI, wait for CONFIG response on channel.
			switch msg.RfiSubtype {
			case "upstream":
				agent, exists := ar.S.Get(zad.MyUpstream)
				if !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q: upstream agent %q not found", msg.Zone, zad.MyUpstream)
					return
				}
				if !agent.IsAnyTransportOperational() {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q: upstream agent %s is not operational (state: %s)", msg.Zone, zad.MyUpstream, AgentStateToString[agent.EffectiveState()])
					return
				}
				configResp := RequestAndWaitForConfig(ar, agent, string(msg.Zone), "upstream")
				if configResp == nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q: CONFIG upstream to agent %q: no response (timeout)", msg.Zone, agent.Identity)
					return
				}
				resp.RfiResponse[agent.Identity] = &RfiData{
					Status:     "ok",
					ConfigData: configResp.ConfigData,
				}

			case "downstream":
				for _, aid := range zad.MyDownstreams {
					agent, exists := ar.S.Get(aid)
					if !exists {
						resp.RfiResponse[aid] = &RfiData{Error: true, ErrorMsg: fmt.Sprintf("agent %q not found", aid)}
						continue
					}
					if !agent.IsAnyTransportOperational() {
						resp.RfiResponse[aid] = &RfiData{Error: true, ErrorMsg: fmt.Sprintf("agent %q not operational (%s)", aid, AgentStateToString[agent.EffectiveState()])}
						continue
					}
					configResp := RequestAndWaitForConfig(ar, agent, string(msg.Zone), "downstream")
					if configResp == nil {
						resp.RfiResponse[aid] = &RfiData{Error: true, ErrorMsg: "no response (timeout)"}
						continue
					}
					resp.RfiResponse[aid] = &RfiData{
						Status:     "ok",
						ConfigData: configResp.ConfigData,
					}
				}

			case "sig0key":
				for _, agent := range zad.Agents {
					if !agent.IsAnyTransportOperational() {
						resp.RfiResponse[agent.Identity] = &RfiData{Error: true, ErrorMsg: fmt.Sprintf("agent %q not operational (%s)", agent.Identity, AgentStateToString[agent.EffectiveState()])}
						continue
					}
					configResp := RequestAndWaitForConfig(ar, agent, string(msg.Zone), "sig0key")
					if configResp == nil {
						resp.RfiResponse[agent.Identity] = &RfiData{Error: true, ErrorMsg: "no response (timeout)"}
						continue
					}
					resp.RfiResponse[agent.Identity] = &RfiData{
						Status:     "ok",
						ConfigData: configResp.ConfigData,
					}
				}

			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Unknown CONFIG subtype: %q", msg.RfiSubtype)
				return
			}
			resp.Msg = fmt.Sprintf("CONFIG %s RFI sent for zone %s", msg.RfiSubtype, msg.Zone)

		case "SYNC":
			// Send RFI SYNC to all remote agents for this zone.
			lgEngine.Info("sending SYNC RFI to agents", "agents", len(zad.Agents), "zone", msg.Zone)
			for _, agent := range zad.Agents {
				if !agent.IsAnyTransportOperational() {
					resp.RfiResponse[agent.Identity] = &RfiData{
						Error:    true,
						ErrorMsg: fmt.Sprintf("agent %q not operational (%s)", agent.Identity, AgentStateToString[agent.EffectiveState()]),
					}
					continue
				}
				amr, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
					MessageType:  AgentMsgRfi,
					OriginatorID: AgentId(ar.LocalAgent.Identity),
					YourIdentity: agent.Identity,
					Zone:         msg.Zone,
					RfiType:      "SYNC",
				})
				if err != nil {
					resp.RfiResponse[agent.Identity] = &RfiData{Error: true, ErrorMsg: err.Error()}
					continue
				}
				resp.RfiResponse[agent.Identity] = &RfiData{Status: "ok", Msg: amr.Msg}
			}
			resp.Msg = fmt.Sprintf("SYNC RFI sent to %d agents for zone %s", len(zad.Agents), msg.Zone)

		case "AUDIT":
			// Send RFI AUDIT to all remote agents for this zone using two-phase pattern.
			lgEngine.Info("sending AUDIT RFI to agents", "agents", len(zad.Agents), "zone", msg.Zone)
			for _, agent := range zad.Agents {
				if !agent.IsAnyTransportOperational() {
					resp.RfiResponse[agent.Identity] = &RfiData{
						Error:    true,
						ErrorMsg: fmt.Sprintf("agent %q not operational (%s)", agent.Identity, AgentStateToString[agent.EffectiveState()]),
					}
					continue
				}
				auditResp := RequestAndWaitForAudit(ar, agent, string(msg.Zone))
				if auditResp == nil {
					resp.RfiResponse[agent.Identity] = &RfiData{
						Error:    true,
						ErrorMsg: "timeout or error waiting for AUDIT response",
					}
					continue
				}
				rfiData := &RfiData{
					Status: "ok",
					Msg:    "AUDIT data received",
				}
				if typed, ok := auditResp.AuditData.(map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo); ok {
					rfiData.AuditData = typed
				}
				resp.RfiResponse[agent.Identity] = rfiData
			}
			resp.Msg = fmt.Sprintf("AUDIT RFI sent to %d agents for zone %s", len(zad.Agents), msg.Zone)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown RFI type: %q", msg.RfiType)
			return
		}

	case "update-local-zonedata":
		// Update the local zone data for the zone
		var zu = &ZoneUpdate{
			Zone:    msg.Zone,
			AgentId: AgentId(ar.LocalAgent.Identity),
			RRsets:  map[uint16]core.RRset{},
		}
		for _, rrstr := range msg.RRs {
			rr, err := dns.NewRR(rrstr)
			if err != nil {
				lgEngine.Error("error parsing RR in local update", "rr", rrstr, "err", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error parsing RR %q: %v", rrstr, err)
				return
			}
			var rrset core.RRset
			var ok bool
			rrtype := rr.Header().Rrtype
			if rrset, ok = zu.RRsets[rrtype]; !ok {
				rrset = core.RRset{}
			}
			rrset.RRs = append(rrset.RRs, rr)
			zu.RRsets[rrtype] = rrset
			lgEngine.Debug("parsed RR for local update", "rr", rr)
		}

		// var cresp = make(chan *SynchedDataResponse, 1)
		var cresp = make(chan *AgentMsgResponse, 1)
		synchedDataUpdateQ <- &SynchedDataUpdate{
			Zone:       msg.Zone,
			AgentId:    AgentId(ar.LocalAgent.Identity),
			UpdateType: "local",
			Update:     zu,
			Response:   cresp,
		}
		select {
		case r := <-cresp:
			if r.Error {
				lgEngine.Error("error processing local update", "err", r.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = r.ErrorMsg
			}
			resp.Msg = r.Msg
		case <-time.After(2 * time.Second):
			lgEngine.Warn("no response from SynchedDataEngine for local update after 2s")
		}

	default:
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Unknown message type: %+v", msg.MessageType)
	}
}

// sendRfiToAgent sends an RFI message to a remote agent using the best available
// transport. DNS is tried first (primary transport), with API as fallback.
func (ar *AgentRegistry) sendRfiToAgent(agent *Agent, msg *AgentMsgPost) (*AgentMsgResponse, error) {
	// Try DNS transport first via TransportManager (primary transport)
	if ar.TransportManager != nil {
		peer := ar.TransportManager.SyncPeerFromAgent(agent)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		syncReq := &agenttransport.SyncRequest{
			SenderID:    ar.LocalAgent.Identity,
			Zone:        string(msg.Zone),
			Records:     msg.Records,
			Timestamp:   time.Now(),
			MessageType: string(msg.MessageType),
			RfiType:     msg.RfiType,
			RfiSubtype:  msg.RfiSubtype,
		}

		syncResp, err := ar.TransportManager.SendSyncWithFallback(ctx, peer, syncReq)
		if err == nil {
			return &AgentMsgResponse{
				Status: string(syncResp.Status),
				Msg:    syncResp.Message,
				Zone:   msg.Zone,
			}, nil
		}
		lgConnRetryEngine.Warn("DNS transport failed, trying API", "agent", agent.Identity, "err", err)
	}

	// Fall back to API transport (synchronous request-response)
	if agent.Api != nil {
		return agent.SendApiMsg(msg)
	}

	return nil, fmt.Errorf("no transport available for agent %q", agent.Identity)
}

// XXX: Not used at the moment.
func (ar *AgentRegistry) HandleStatusRequest(req SyncStatus) {
	lgEngine.Debug("received STATUS request")
	if req.Response == nil {
		lgEngine.Warn("STATUS request has no response channel")
		return
	}

	// Get current agents without waiting for any pending operations
	agents := map[AgentId]*Agent{}
	for _, agent := range ar.S.Items() {
		// Make a clean copy of the agent for the response
		// Pass pointer to avoid copying the mutex
		saneAgent := SanitizeForJSON(agent)
		if foo, ok := saneAgent.(*Agent); ok {
			agents[agent.Identity] = foo
		} else {
			lgEngine.Error("failed to sanitize agent for JSON", "agent", agent.Identity)
		}
	}

	// var saneAr *AgentRegistry
	// if foo, ok := SanitizeForJSON(*ar).(*AgentRegistry); ok {
	// 	saneAr = foo
	// }

	// Send the response immediately with a timeout to avoid blocking
	select {
	case req.Response <- SyncStatus{
		Agents: agents,
		// AgentRegistry: saneAr,
		Identity: AgentId(ar.LocalAgent.Identity),
		Error:    false,
	}:
	case <-time.After(1 * time.Second): // Don't block forever
		lgEngine.Warn("STATUS response timed out")
	}
}

// Helper methods for SendBeat
func (agent *Agent) SendApiMsg(msg *AgentMsgPost) (*AgentMsgResponse, error) {
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %q", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/msg", msg, false)
	if err != nil {
		return nil, fmt.Errorf("API msg failed: %v", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("API msg returned status %d (%s)", status, http.StatusText(status))
	}

	// log.Printf("SendApiMsg: response: %s", string(resp))

	var amr AgentMsgResponse
	err = json.Unmarshal(resp, &amr)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling message response: %v", err)
	}

	//	if amr.Status == "ok" {
	//		log.Printf("SendApiMsg: message to agent %q for zone %q returned status OK: %s", agent.Identity, msg.Zone, amr.Msg)
	//	} else {
	//		return nil, fmt.Errorf("SendApiMsg: message to agent %q for zone %q returned status %d: %s, ErrorMsg: %q. Full response: %+v", agent.Identity, msg.Zone, status, amr.Msg, amr.ErrorMsg, amr)
	//	}
	return &amr, nil
}

func (agent *Agent) SendDnsMsg(msg *AgentMsgPost) (int, []byte, error) {
	// TODO: Implement DNS-based heartbeat
	// This would involve creating a signed DNS message
	// containing the heartbeat information
	return 0, nil, fmt.Errorf("DNS transport not yet implemented")
}
