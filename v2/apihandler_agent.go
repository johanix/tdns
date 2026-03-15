/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// doPeerPing pings any known peer via DNS CHUNK or API.
// Role-agnostic: works for agent, auth/signer, or any role with a TransportManager.
// The peer must be in the PeerRegistry or have static config (combiner, signer, multi-provider agent).
// useAPI true = HTTPS API ping; false = CHUNK-based DNS ping.
func doPeerPing(conf *Config, peerID string, useAPI bool) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}
	peerID = dns.Fqdn(peerID)

	tm := conf.Internal.TransportManager
	if tm == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not configured"
		return resp
	}
	resp.Identity = AgentId(tm.LocalID)

	peer, ok := tm.PeerRegistry.Get(peerID)
	if !ok {
		// Peer not in registry — try static config fallbacks for all roles
		peer = conf.lookupStaticPeer(peerID)
		if peer == nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %q not found in registry (run discovery first)", peerID)
			return resp
		}
	}

	if useAPI {
		if peer.APIEndpoint == "" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %q has no API endpoint configured", peerID)
			return resp
		}
		url := strings.TrimSuffix(peer.APIEndpoint, "/") + "/ping"
		body := PingPost{Msg: fmt.Sprintf("peer ping %s", peerID), Pings: 1}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("build request: %v", err)
			return resp
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		res, err := client.Do(req)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("apiping to %s failed: %v", peerID, err)
			return resp
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %s API returned %d", peerID, res.StatusCode)
			return resp
		}
		var pr PingResponse
		if err := json.NewDecoder(res.Body).Decode(&pr); err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("decode ping response from %s: %v", peerID, err)
			return resp
		}
		resp.Msg = fmt.Sprintf("ping ok (api transport): %s responded", peerID)
		return resp
	}

	// DNS CHUNK ping
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pingResp, err := tm.SendPing(ctx, peer)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("ping to %s failed: %v", peerID, err)
		return resp
	}
	if !pingResp.OK {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("peer %s did not acknowledge (responder: %s)", peerID, pingResp.ResponderID)
		return resp
	}
	resp.Msg = fmt.Sprintf("ping ok (dns transport): %s echoed nonce %s", pingResp.ResponderID, pingResp.Nonce)
	return resp
}

// lookupStaticPeer checks all static peer configurations (agent-side: combiner, signer;
// signer-side: multi-provider.agent) and returns a temporary Peer if found. Returns nil if not found.
func (conf *Config) lookupStaticPeer(peerID string) *transport.Peer {
	// Agent-side: combiner
	if conf.Agent != nil && conf.Agent.Combiner != nil &&
		dns.Fqdn(conf.Agent.Combiner.Identity) == peerID && conf.Agent.Combiner.Address != "" {
		if peer := peerFromAddress(peerID, conf.Agent.Combiner.Address); peer != nil {
			if conf.Agent.Combiner.ApiBaseUrl != "" {
				peer.APIEndpoint = conf.Agent.Combiner.ApiBaseUrl
			}
			return peer
		}
	}

	// Agent-side: signer
	if conf.Agent != nil && conf.Agent.Signer != nil &&
		dns.Fqdn(conf.Agent.Signer.Identity) == peerID && conf.Agent.Signer.Address != "" {
		return peerFromAddress(peerID, conf.Agent.Signer.Address)
	}

	// Signer-side: multi-provider agents
	if conf.MultiProvider != nil {
		for _, agentConf := range conf.MultiProvider.Agents {
			if agentConf != nil && dns.Fqdn(agentConf.Identity) == peerID && agentConf.Address != "" {
				return peerFromAddress(peerID, agentConf.Address)
			}
		}
	}

	return nil
}

// peerFromAddress creates a temporary transport.Peer from a host:port address string.
func peerFromAddress(peerID string, address string) *transport.Peer {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		lgApi.Warn("invalid address for static peer", "address", address, "peer", peerID, "err", err)
		return nil
	}
	port, _ := strconv.Atoi(portStr)
	peer := transport.NewPeer(peerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})
	return peer
}

func (conf *Config) APIagent(refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding agent command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Identity: AgentId(conf.Agent.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "err", err)
			}
		}()

		// XXX: hsync cmds should move to its own endpoint, not be mixed with agent
		var zd *ZoneData
		var exist bool
		noZoneCommands := map[string]bool{
			"config": true, "hsync-agentstatus": true, "peer-ping": true, "peer-apiping": true,
			"discover": true, "hsync-locate": true,
			"router-list": true, "router-describe": true, "router-metrics": true, "router-walk": true, "router-reset": true,
		}
		if !noZoneCommands[amp.Command] {
			amp.Zone = ZoneName(dns.Fqdn(string(amp.Zone)))
			zd, exist = Zones.Get(string(amp.Zone))
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", amp.Zone)
				return
			}
		}

		rch := make(chan *AgentMgmtResponse, 1)

		switch amp.Command {
		case "config":
			tmp := SanitizeForJSON(conf.Agent)
			resp.AgentConfig = tmp.(LocalAgentConf)
			resp.AgentConfig.Api.CertData = ""
			resp.AgentConfig.Api.KeyData = ""

		case "peer-ping":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for peer-ping"
				return
			}
			pingResp := doPeerPing(conf, string(amp.AgentId), false)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "peer-apiping":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for peer-apiping"
				return
			}
			pingResp := doPeerPing(conf, string(amp.AgentId), true)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "update-local-zonedata":
			lgApi.Debug("update-local-zonedata", "addedRRs", amp.AddedRRs, "removedRRs", amp.RemovedRRs)

			conf.Internal.MsgQs.Command <- &AgentMgmtPostPlus{
				amp,
				rch,
			}
			select {
			case r := <-rch:
				// log.Printf("APIagent: Received response from msg handler: %+v", r)
				resp = *r
				// resp.Status = "ok"

			case <-time.After(10 * time.Second):
				lgApi.Warn("no response from CommandHandler after 10 seconds")
				resp.Error = true
				resp.ErrorMsg = "No response from CommandHandler after 10 seconds, state unknown"
			}

		case "hsync-zonestatus":
			// Get the apex owner object
			owner, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s error: %v", amp.Zone, err)
				return
			}

			// Get the HSYNC RRset from the apex
			hsyncRRset := owner.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC3 RRset", amp.Zone)
				return
			}

			// Convert the RRs to strings for transmission
			hsyncStrs := make([]string, len(hsyncRRset.RRs))
			for i, rr := range hsyncRRset.RRs {
				hsyncStrs[i] = rr.String()
			}
			resp.HsyncRRs = hsyncStrs

			// Get the actual agents from the registry
			resp.ZoneAgentData, err = conf.Internal.AgentRegistry.GetZoneAgentData(amp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting remote agents: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", amp.Zone)

		case "hsync-agentstatus":
			// Get the apex owner object
			agent, err := conf.Internal.AgentRegistry.GetAgentInfo(amp.AgentId)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting agent info: %v", err)
				return
			}
			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Data for remote agent %q", amp.AgentId)

		case "discover":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			amp.AgentId = AgentId(dns.Fqdn(string(amp.AgentId)))

			// Check authorization before discovery (DNS-38)
			if conf.Internal.AgentRegistry.TransportManager != nil {
				authorized, reason := conf.Internal.AgentRegistry.TransportManager.IsPeerAuthorized(string(amp.AgentId), string(amp.Zone))
				if !authorized {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("agent %q is not authorized (not in agent.authorized_peers config or HSYNC): %s", amp.AgentId, reason)
					return
				}
			}

			// Trigger discovery (always starts fresh discovery)
			conf.Internal.AgentRegistry.DiscoverAgentAsync(amp.AgentId, amp.Zone, nil)
			resp.Msg = fmt.Sprintf("Discovery started for agent %s", amp.AgentId)

		case "hsync-locate":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			amp.AgentId = AgentId(dns.Fqdn(string(amp.AgentId)))
			agent, err := conf.Internal.AgentRegistry.GetAgentInfo(amp.AgentId)
			if err != nil {
				// Start async lookup and return a message that lookup is in progress
				conf.Internal.AgentRegistry.DiscoverAgentAsync(amp.AgentId, "", nil)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent lookup in progress for %s", amp.AgentId)
				return
			}

			// If agent info is incomplete, start a new lookup
			if agent.State == AgentStateNeeded {
				conf.Internal.AgentRegistry.DiscoverAgentAsync(amp.AgentId, "", nil)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent information is incomplete for %s, lookup in progress", amp.AgentId)
				return
			}

			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Found existing agent %s", amp.AgentId)

		// HSYNC debug commands (Phase 5)
		case "hsync-peer-status":
			if kdb == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not configured"
				return
			}

			state := ""
			if amp.AgentId != "" {
				// Filter by specific peer
				peer, err := kdb.GetPeer(string(amp.AgentId))
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("error getting peer: %v", err)
					return
				}
				if peer != nil {
					resp.HsyncPeers = []*HsyncPeerInfo{PeerRecordToInfo(peer)}
				}
			} else {
				// List all peers
				peers, err := kdb.ListPeers(state)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("error listing peers: %v", err)
					return
				}
				for _, peer := range peers {
					resp.HsyncPeers = append(resp.HsyncPeers, PeerRecordToInfo(peer))
				}
			}
			resp.Msg = fmt.Sprintf("Found %d peers", len(resp.HsyncPeers))

		case "hsync-sync-ops":
			if kdb == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not configured"
				return
			}

			ops, err := kdb.ListSyncOperations(string(amp.Zone), 50)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing sync operations: %v", err)
				return
			}
			for _, op := range ops {
				resp.HsyncSyncOps = append(resp.HsyncSyncOps, SyncOpRecordToInfo(op))
			}
			resp.Msg = fmt.Sprintf("Found %d sync operations", len(resp.HsyncSyncOps))

		case "hsync-confirmations":
			if kdb == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not configured"
				return
			}

			confs, err := kdb.ListSyncConfirmations("", 50)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing confirmations: %v", err)
				return
			}
			for _, conf := range confs {
				resp.HsyncConfirmations = append(resp.HsyncConfirmations, ConfirmRecordToInfo(conf))
			}
			resp.Msg = fmt.Sprintf("Found %d confirmations", len(resp.HsyncConfirmations))

		case "hsync-transport-events":
			if kdb == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not configured"
				return
			}

			events, err := kdb.ListTransportEvents(string(amp.AgentId), 100)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing transport events: %v", err)
				return
			}
			resp.HsyncEvents = events
			resp.Msg = fmt.Sprintf("Found %d transport events", len(resp.HsyncEvents))

		case "hsync-metrics":
			if kdb == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not configured"
				return
			}

			metrics, err := kdb.GetAggregatedMetrics()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting metrics: %v", err)
				return
			}
			resp.HsyncMetrics = metrics
			resp.Msg = "Aggregated metrics"

			//		case "list-known-agents":
			//			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)

		// Router introspection commands
		case "router-list":
			if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
				resp.Error = true
				resp.ErrorMsg = "Router not available (DNS transport not configured)"
				return
			}
			routerResp := handleRouterList(conf.Internal.TransportManager.Router)
			resp = *routerResp
			resp.Identity = AgentId(conf.Agent.Identity)

		case "router-describe":
			if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
				resp.Error = true
				resp.ErrorMsg = "Router not available (DNS transport not configured)"
				return
			}
			routerResp := handleRouterDescribe(conf.Internal.TransportManager.Router)
			resp = *routerResp
			resp.Identity = AgentId(conf.Agent.Identity)

		case "router-metrics":
			if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
				resp.Error = true
				resp.ErrorMsg = "Router not available (DNS transport not configured)"
				return
			}
			routerResp := handleRouterMetrics(conf.Internal.TransportManager.Router)
			resp = *routerResp
			resp.Identity = AgentId(conf.Agent.Identity)

		case "router-walk":
			if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
				resp.Error = true
				resp.ErrorMsg = "Router not available (DNS transport not configured)"
				return
			}
			routerResp := handleRouterWalk(conf.Internal.TransportManager.Router)
			resp = *routerResp
			resp.Identity = AgentId(conf.Agent.Identity)

		case "router-reset":
			if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
				resp.Error = true
				resp.ErrorMsg = "Router not available (DNS transport not configured)"
				return
			}
			routerResp := handleRouterReset(conf.Internal.TransportManager.Router)
			resp = *routerResp
			resp.Identity = AgentId(conf.Agent.Identity)

		case "refresh-keys":
			zd.RequestAndWaitForKeyInventory()
			if !zd.GetKeystateOK() {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("KEYSTATE exchange failed for zone %s: %s", amp.Zone, zd.GetKeystateError())
			} else {
				inv := zd.GetLastKeyInventory()
				nForeign := 0
				for _, entry := range inv.Inventory {
					if entry.State == DnskeyStateForeign {
						nForeign++
					}
				}
				// Derive local DNSKEYs from KEYSTATE and feed changes into SDE
				changed, dskeyStatus, err := zd.LocalDnskeysFromKeystate()
				if err != nil {
					lgApi.Error("LocalDnskeysFromKeystate failed", "err", err)
				}
				if changed && dskeyStatus != nil {
					zd.SyncQ <- SyncRequest{
						Command:      "SYNC-DNSKEY-RRSET",
						ZoneName:     ZoneName(zd.ZoneName),
						ZoneData:     zd,
						DnskeyStatus: dskeyStatus,
					}
				}
				resp.Msg = fmt.Sprintf("Key inventory refreshed for zone %s: %d keys (%d local, %d foreign)",
					amp.Zone, len(inv.Inventory),
					len(inv.Inventory)-nForeign, nForeign)
				if changed {
					resp.Msg += fmt.Sprintf(", SDE updated (%d adds, %d removes)",
						len(dskeyStatus.LocalAdds), len(dskeyStatus.LocalRemoves))
				}
			}

		case "resync":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			sdcmd := &SynchedDataCmd{
				Cmd:      "resync",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.Internal.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.Error = response.Error
				resp.ErrorMsg = response.ErrorMsg
			case <-time.After(10 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for resync"
			}
			resp.Status = "ok"

		case "send-rfi":
			switch amp.MessageType {
			case AgentMsgRfi:
				conf.Internal.MsgQs.Command <- &AgentMgmtPostPlus{
					amp,
					rch,
				}
				select {
				case r := <-rch:
					resp = *r
					resp.Status = "ok"
				case <-time.After(30 * time.Second):
					resp.Error = true
					resp.ErrorMsg = "timeout waiting for RFI response"
				}
			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("send-rfi requires MessageType RFI, got %q", AgentMsgToString[amp.MessageType])
			}

		case "parentsync-status":
			lem := conf.Internal.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			status := lem.GetParentSyncStatus(amp.Zone, zd, kdb, conf.Internal.ImrEngine, conf.Internal.AgentRegistry)
			resp.Data = status
			resp.Msg = fmt.Sprintf("Parent sync status for zone %s", amp.Zone)

		case "parentsync-election":
			lem := conf.Internal.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			configured := lem.configuredPeers(amp.Zone)
			operational := 0
			if lem.operationalPeersFunc != nil {
				operational = lem.operationalPeersFunc(amp.Zone)
			}
			if configured > 0 && operational < configured {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("cannot start election: only %d of %d configured peers are operational", operational, configured)
				return
			}
			lem.StartElection(amp.Zone, configured)
			resp.Msg = fmt.Sprintf("Election started for zone %s with %d peers", amp.Zone, configured)

		case "parentsync-inquire":
			imr := conf.Internal.ImrEngine
			if imr == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			sak, err := kdb.GetSig0Keys(string(amp.Zone), Sig0StateActive)
			if err != nil || len(sak.Keys) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("no active SIG(0) key for zone %s", amp.Zone)
				return
			}
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			keyState, extra, err := queryParentKeyStateDetailed(kdb, imr, string(amp.Zone), keyid)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("KeyState inquiry failed: %v", err)
				return
			}
			resp.Data = map[string]interface{}{
				"zone":       string(amp.Zone),
				"keyid":      keyid,
				"state":      keyState,
				"state_name": edns0.KeyStateToString(keyState),
				"extra_text": extra,
			}
			resp.Msg = fmt.Sprintf("Parent says: %s", edns0.KeyStateToString(keyState))

		case "parentsync-bootstrap":
			lem := conf.Internal.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			if !lem.IsLeader(amp.Zone) {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("this agent is not the delegation sync leader for %s", amp.Zone)
				return
			}
			sak, err := kdb.GetSig0Keys(string(amp.Zone), Sig0StateActive)
			if err != nil || len(sak.Keys) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("no active SIG(0) key for zone %s", amp.Zone)
				return
			}
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			algorithm := sak.Keys[0].KeyRR.Algorithm
			go conf.parentSyncAfterKeyPublication(amp.Zone, string(amp.Zone), keyid, algorithm)
			resp.Msg = fmt.Sprintf("Bootstrap triggered for zone %s (keyid %d), running async", amp.Zone, keyid)

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", amp.Command)
			resp.Error = true
		}
	}
}

func (conf *Config) APIagentDebug() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.MsgQs.DebugCommand == nil {
		lgApi.Error("DebugCommand channel is not set, cannot forward debug commands, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Msg:      "Hi there! Using debug commands are we?",
			Identity: AgentId(conf.Agent.Identity),
		}
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("error encoding agent debug response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /agent/debug post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		lgApi.Debug("received /agent/debug request", "command", amp.Command, "messagetype", AgentMsgToString[amp.MessageType], "from", r.RemoteAddr)

		rch := make(chan *AgentMgmtResponse, 1)

		switch amp.Command {
		case "send-notify", "send-rfi":
			// XXX: this is a bit bass-ackwards, in the debug case we're not using
			// amp.Command but rather amp.MessageType.
			switch amp.MessageType {
			case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
				resp.Status = "ok"
				conf.Internal.MsgQs.DebugCommand <- &AgentMgmtPostPlus{
					amp,
					rch,
				}
				select {
				case r := <-rch:
					// log.Printf("APIagentDebug: Received response from msg handler: %+v", r)
					resp = *r
					resp.Status = "ok"

				case <-time.After(10 * time.Second):
					lgApi.Warn("no response from send-notify after 10 seconds")
					resp.Error = true
					resp.ErrorMsg = "No response from CommandHandler after 10 seconds, state unknown"
				}

			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Unknown debug message type: %q", AgentMsgToString[amp.MessageType])
			}

		// johani 20250324: This does not work, crashes in IterBuffered() with shards=0 for unknown reason
		case "dump-agentregistry":
			resp.Status = "ok"
			// resp.Msg = fmt.Sprintf("Agent registry: %+v", conf.Internal.AgentRegistry)
			// resp.AgentRegistry = conf.Internal.AgentRegistry
			ar := conf.Internal.AgentRegistry
			keys := ar.S.Keys()
			lgApi.Debug("dump-agentregistry", "keys", keys)
			for _, key := range keys {
				if agent, exists := ar.S.Get(key); exists {
					lgApi.Debug("agent registry entry", "identity", agent.Identity)
				}
			}
			lgApi.Debug("dump-agentregistry", "numShards", ar.S.NumShards())
			// dump.P(ar.S)
			// tmpar := &AgentRegistry{
			// RegularS:
			// make(map[AgentId]*Agent),
			// }

			regs := map[AgentId]*Agent{}
			for _, key := range keys {
				if agent, exists := ar.S.Get(key); exists {
					tmp := SanitizeForJSON(agent)
					regs[key] = tmp.(*Agent)
				}
			}
			// foo := SanitizeForJSON(ar.S)
			resp.AgentRegistry = &AgentRegistry{
				// S: foo.(ConcurrentMap[AgentId, *Agent]),
				// S:              nil,
				RegularS:       regs,
				RemoteAgents:   ar.RemoteAgents,
				LocalAgent:     ar.LocalAgent,
				LocateInterval: ar.LocateInterval,
			}

		case "dump-zonedatarepo":
			sdcmd := &SynchedDataCmd{
				Cmd:      "dump-zonedatarepo",
				Zone:     "",
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.Internal.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.ZoneDataRepo = response.ZDR

				// Include per-zone KEYSTATE health status
				ksStatus := make(map[ZoneName]KeystateInfo)
				for zone := range response.ZDR {
					if zd, exists := Zones.Get(string(zone)); exists {
						ksStatus[zone] = KeystateInfo{
							OK:        zd.GetKeystateOK(),
							Error:     zd.GetKeystateError(),
							Timestamp: zd.GetKeystateTime().Format(time.RFC3339),
						}
					}
				}
				resp.KeystateStatus = ksStatus
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "No response from SynchedDataCmd after 2 seconds, state unknown"
			}

		case "show-key-inventory":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required for show-key-inventory"
				return
			}
			zd, exists := Zones.Get(string(amp.Zone))
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %q not found", amp.Zone)
				return
			}
			inv := zd.GetLastKeyInventory()
			if inv == nil {
				resp.Msg = fmt.Sprintf("No key inventory received yet for zone %s", amp.Zone)
			} else {
				resp.Data = inv
				resp.Msg = fmt.Sprintf("Key inventory for zone %s: %d keys (received %s from %s)",
					amp.Zone, len(inv.Inventory),
					inv.Received.Format("15:04:05"),
					inv.SenderID)
			}

		case "resync":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			sdcmd := &SynchedDataCmd{
				Cmd:      "resync",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.Internal.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.Error = response.Error
				resp.ErrorMsg = response.ErrorMsg
			case <-time.After(10 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for resync"
			}
			resp.Status = "ok"

		// HSYNC debug commands (Phase 5)
		case "hsync-chunk-send":
			// TODO: Implement CHUNK send for DNS transport testing
			// This requires access to the TransportManager and DNS transport
			resp.Msg = "CHUNK send not yet implemented - requires DNS transport setup"
			resp.Status = "ok"

		case "hsync-chunk-recv":
			// TODO: Show recently received CHUNKs
			// This would require a ring buffer of received messages
			resp.Msg = "CHUNK receive log not yet implemented - requires message logging"
			resp.Status = "ok"

		case "hsync-init-db":
			if conf.Internal.KeyDB == nil {
				resp.Error = true
				resp.ErrorMsg = "KeyDB not available"
				return
			}
			if err := conf.Internal.KeyDB.InitHsyncTables(); err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("InitHsyncTables failed: %v", err)
				return
			}
			resp.Msg = "HSYNC database tables initialized successfully"
			resp.Status = "ok"

		case "hsync-inject-sync":
			// Inject a simulated sync from a remote agent for testing
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "sender agent ID is required"
				return
			}
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Parse the RRs
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				parsedRRs = append(parsedRRs, rr)
			}

			// Create the ZoneUpdate with RRs (not RRsets, as these are individual RRs to be added)
			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: amp.AgentId,
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			// Also populate RRsets for the current processing logic
			// (The SynchedDataEngine currently uses RRsets)
			for _, rr := range parsedRRs {
				rrtype := rr.Header().Rrtype
				rrset, exists := zu.RRsets[rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
			}

			lgApi.Info("injecting sync", "rrs", len(parsedRRs), "from", amp.AgentId, "zone", amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine
			conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    amp.AgentId,
				UpdateType: "remote",
				Update:     zu,
				Response:   cresp,
			}

			// Wait for response
			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("Sync injection failed: %s", r.ErrorMsg)
				} else {
					resp.Msg = fmt.Sprintf("Sync injected successfully: %d RRs processed from %q", len(parsedRRs), amp.AgentId)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
				}
				resp.Status = "ok"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for SynchedDataEngine response"
				resp.Status = "timeout"
			}

		case "hsync-force-sync":
			// Force sync with a specific peer
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "peer agent ID is required"
				return
			}
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Check if TransportManager is available
			if conf.Internal.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
				return
			}

			// Get peer from agent registry
			agent, exists := conf.Internal.AgentRegistry.S.Get(amp.AgentId)
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("peer agent %q not found in registry", amp.AgentId)
				return
			}

			// Convert agent to transport peer
			peer := conf.Internal.TransportManager.SyncPeerFromAgent(agent)

			// Create sync request with provided RRs (or empty for test sync)
			// RRs are already strings in amp.RRs, just validate they parse
			for _, rrStr := range amp.RRs {
				_, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
			}

			syncReq := &transport.SyncRequest{
				Zone:           string(amp.Zone),
				Records:        groupRRStringsByOwner(amp.RRs),
				DistributionID: fmt.Sprintf("debug-force-sync-%d", time.Now().Unix()),
				MessageType:    "sync",
			}

			lgApi.Info("forcing sync to peer", "peer", amp.AgentId, "zone", amp.Zone)

			// Send sync with fallback
			ctx := context.Background()
			syncResp, err := conf.Internal.TransportManager.SendSyncWithFallback(ctx, peer, syncReq)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("sync failed: %v", err)
			} else {
				resp.Msg = fmt.Sprintf("Sync sent successfully to %q (distribution: %s)", amp.AgentId, syncReq.DistributionID)
				resp.Data = map[string]interface{}{
					"distribution_id": syncReq.DistributionID,
					"peer_id":         amp.AgentId,
					"zone":            amp.Zone,
					"status":          syncResp.Status,
					"message":         syncResp.Message,
				}
			}
			resp.Status = "ok"

		case "hsync-sync-state":
			// Show sync state for a zone
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Get sync state from ZoneDataRepo via SynchedDataCmd
			sdcmd := &SynchedDataCmd{
				Cmd:      "get-zone-state",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.Internal.MsgQs.SynchedDataCmd <- sdcmd

			select {
			case response := <-sdcmd.Response:
				if response.Error {
					resp.Error = true
					resp.ErrorMsg = response.ErrorMsg
				} else {
					resp.Msg = fmt.Sprintf("Sync state for zone %q", amp.Zone)
					resp.Data = map[string]interface{}{
						"zone":           amp.Zone,
						"zone_data_repo": response.ZDR,
						"message":        response.Msg,
					}
				}
				resp.Status = "ok"
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for sync state response"
				resp.Status = "timeout"
			}

		case "hsync-send-to-combiner":
			// Send test data to combiner (via SynchedDataUpdate)
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			if amp.AgentId == "" {
				// Default to local agent
				amp.AgentId = AgentId(conf.Agent.Identity)
			}
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}

			// Parse the RRs
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				parsedRRs = append(parsedRRs, rr)
			}

			// Create ZoneUpdate
			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: amp.AgentId,
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			// Populate RRsets
			for _, rr := range parsedRRs {
				rrtype := rr.Header().Rrtype
				rrset, exists := zu.RRsets[rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
			}

			lgApi.Info("sending to combiner", "rrs", len(parsedRRs), "from", amp.AgentId, "zone", amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine (which forwards to combiner)
			conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    amp.AgentId,
				UpdateType: "local", // "local" means from this agent to combiner
				Update:     zu,
				Response:   cresp,
			}

			// Wait for response
			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("Send to combiner failed: %s", r.ErrorMsg)
				} else {
					resp.Msg = fmt.Sprintf("Data sent to combiner successfully: %d RRs from %q", len(parsedRRs), amp.AgentId)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
				}
				resp.Status = "ok"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for combiner response"
				resp.Status = "timeout"
			}

		case "hsync-test-chain":
			// Run full end-to-end test chain
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required for test"
				return
			}

			scenario := "add" // default scenario
			if amp.Data != nil {
				if s, ok := amp.Data["scenario"].(string); ok {
					scenario = s
				}
			}

			lgApi.Info("running test chain", "scenario", scenario, "zone", amp.Zone)

			// Parse the RRs
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				parsedRRs = append(parsedRRs, rr)
			}

			// Step 1: Create local zone update
			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: AgentId(conf.Agent.Identity),
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			for _, rr := range parsedRRs {
				rrtype := rr.Header().Rrtype
				rrset, exists := zu.RRsets[rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
			}

			testResults := make(map[string]interface{})
			testResults["scenario"] = scenario
			testResults["zone"] = amp.Zone
			testResults["rrs_count"] = len(parsedRRs)

			// Step 2: Send to local SynchedDataEngine
			cresp := make(chan *AgentMsgResponse, 1)
			conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    AgentId(conf.Agent.Identity),
				UpdateType: "local",
				Update:     zu,
				Response:   cresp,
			}

			select {
			case r := <-cresp:
				if r.Error {
					testResults["step1_local_update"] = map[string]interface{}{
						"success": false,
						"error":   r.ErrorMsg,
					}
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Step 1 (local update) failed: %s", r.ErrorMsg)
					resp.Data = testResults
					return
				}
				testResults["step1_local_update"] = map[string]interface{}{
					"success": true,
					"message": r.Msg,
				}
			case <-time.After(5 * time.Second):
				testResults["step1_local_update"] = map[string]interface{}{
					"success": false,
					"error":   "timeout",
				}
				resp.Error = true
				resp.ErrorMsg = "Step 1 (local update) timed out"
				resp.Data = testResults
				return
			}

			// Step 3: Sync to remote peers (if TransportManager available)
			if conf.Internal.TransportManager != nil && conf.Internal.AgentRegistry != nil {
				peerCount := 0
				syncResults := make(map[string]interface{})

				// Get all remote agents
				keys := conf.Internal.AgentRegistry.S.Keys()
				for _, key := range keys {
					if agent, exists := conf.Internal.AgentRegistry.S.Get(key); exists {
						if agent.Identity == AgentId(conf.Agent.Identity) {
							continue // Skip self
						}

						peerCount++
						peer := conf.Internal.TransportManager.SyncPeerFromAgent(agent)
						syncReq := &transport.SyncRequest{
							Zone:           string(amp.Zone),
							Records:        groupRRStringsByOwner(amp.RRs),
							DistributionID: fmt.Sprintf("test-chain-%d-%s", time.Now().Unix(), agent.Identity),
							MessageType:    "sync",
						}

						ctx := context.Background()
						syncResp, err := conf.Internal.TransportManager.SendSyncWithFallback(ctx, peer, syncReq)
						if err != nil {
							syncResults[string(agent.Identity)] = map[string]interface{}{
								"success": false,
								"error":   err.Error(),
							}
						} else {
							syncResults[string(agent.Identity)] = map[string]interface{}{
								"success":         syncResp.Status == transport.ConfirmSuccess,
								"message":         syncResp.Message,
								"distribution_id": syncReq.DistributionID,
							}
						}
					}
				}

				testResults["step2_peer_sync"] = map[string]interface{}{
					"peers_synced": peerCount,
					"results":      syncResults,
				}
			} else {
				testResults["step2_peer_sync"] = map[string]interface{}{
					"skipped": true,
					"reason":  "TransportManager not available",
				}
			}

			resp.Msg = fmt.Sprintf("Test chain completed for zone %q (scenario: %s)", amp.Zone, scenario)
			resp.Data = testResults
			resp.Status = "ok"

		case "show-combiner-data":
			// Show combiner's local modifications store
			zone := amp.Zone
			combinerData := make(map[string]map[string]map[string][]string)

			if zone != "" {
				// Single zone
				zd, exists := Zones.Get(string(zone))
				if !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q not found", zone)
					return
				}
				if zd.CombinerData != nil {
					zoneData := make(map[string]map[string][]string)
					for item := range zd.CombinerData.IterBuffered() {
						ownerName := item.Key
						ownerData := item.Val
						rrTypeData := make(map[string][]string)
						for _, rrtype := range ownerData.RRtypes.Keys() {
							rrset, _ := ownerData.RRtypes.Get(rrtype)
							var rrs []string
							for _, rr := range rrset.RRs {
								rrs = append(rrs, rr.String())
							}
							rrTypeData[dns.TypeToString[rrtype]] = rrs
						}
						zoneData[ownerName] = rrTypeData
					}
					combinerData[string(zone)] = zoneData
				}
			} else {
				// All zones
				for _, zd := range Zones.Items() {
					if zd.CombinerData != nil {
						zoneData := make(map[string]map[string][]string)
						for item := range zd.CombinerData.IterBuffered() {
							ownerName := item.Key
							ownerData := item.Val
							rrTypeData := make(map[string][]string)
							for _, rrtype := range ownerData.RRtypes.Keys() {
								rrset, _ := ownerData.RRtypes.Get(rrtype)
								var rrs []string
								for _, rr := range rrset.RRs {
									rrs = append(rrs, rr.String())
								}
								rrTypeData[dns.TypeToString[rrtype]] = rrs
							}
							zoneData[ownerName] = rrTypeData
						}
						combinerData[zd.ZoneName] = zoneData
					}
				}
			}

			resp.Data = map[string]interface{}{
				"combiner_data": combinerData,
			}
			resp.Msg = fmt.Sprintf("Combiner data retrieved for %d zone(s)", len(combinerData))
			resp.Status = "ok"

		case "fake-sync-from":
			// Inject a fake SYNC from a remote agent (same as hsync-inject-sync)
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "source agent ID (--from) is required"
				return
			}
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Parse the RRs
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				parsedRRs = append(parsedRRs, rr)
			}

			// Create the ZoneUpdate with RRs
			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: amp.AgentId,
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			// Also populate RRsets
			for _, rr := range parsedRRs {
				rrtype := rr.Header().Rrtype
				rrset, exists := zu.RRsets[rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
			}

			lgApi.Info("injecting fake sync", "rrs", len(parsedRRs), "from", amp.AgentId, "zone", amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine
			conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    amp.AgentId,
				UpdateType: "remote",
				Update:     zu,
				Response:   cresp,
			}

			// Wait for response
			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("Fake sync injection failed: %s", r.ErrorMsg)
				} else {
					resp.Msg = fmt.Sprintf("Fake sync injected successfully: %d RRs processed from %q", len(parsedRRs), amp.AgentId)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
				}
				resp.Status = "ok"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for SynchedDataEngine response"
				resp.Status = "timeout"
			}

		case "add-rr", "del-rr":
			// Add or delete an RR of any allowed type: store locally + sync to peers + send to combiner
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}

			isAdd := amp.Command == "add-rr"

			// Parse and validate the RRs (must be an allowed type at the zone apex)
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				if !AllowedLocalRRtypes[rr.Header().Rrtype] {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("RR type %s is not allowed", dns.TypeToString[rr.Header().Rrtype])
					return
				}
				if isAdd {
					rr.Header().Class = dns.ClassINET
				} else {
					rr.Header().Class = dns.ClassNONE
				}
				parsedRRs = append(parsedRRs, rr)
			}

			// Create the ZoneUpdate with RRs and RRsets
			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: AgentId(conf.Agent.Identity),
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			// Populate RRsets (needed by ProcessUpdate)
			for _, rr := range parsedRRs {
				rrtype := rr.Header().Rrtype
				rrset, exists := zu.RRsets[rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
			}

			action := "Adding"
			if !isAdd {
				action = "Removing"
			}
			// Collect RR type names for logging
			rrtypeNames := make(map[string]bool)
			for _, rr := range parsedRRs {
				rrtypeNames[dns.TypeToString[rr.Header().Rrtype]] = true
			}
			var typeList []string
			for name := range rrtypeNames {
				typeList = append(typeList, name)
			}
			lgApi.Info("RR operation", "cmd", amp.Command, "action", action, "count", len(parsedRRs), "types", strings.Join(typeList, ", "), "zone", amp.Zone)

			force := false
			if amp.Data != nil {
				if f, ok := amp.Data["force"].(bool); ok {
					force = f
				}
			}
			cresp := make(chan *AgentMsgResponse, 1)
			conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    AgentId(conf.Agent.Identity),
				UpdateType: "local",
				Update:     zu,
				Force:      force,
				Response:   cresp,
			}

			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("%s RR(s) failed: %s", amp.Command, r.ErrorMsg)
				} else {
					resp.Msg = fmt.Sprintf("%s %d RR(s) for zone %q", action, len(parsedRRs), amp.Zone)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
				}
				resp.Status = "ok"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for SynchedDataEngine response"
				resp.Status = "timeout"
			}

		case "send-sync-to":
			// Send a real SYNC to a remote agent
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "target agent ID (--to) is required"
				return
			}
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Check if TransportManager is available
			if conf.Internal.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
				return
			}

			// Get peer from agent registry
			agent, exists := conf.Internal.AgentRegistry.S.Get(amp.AgentId)
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("target agent %q not found in registry", amp.AgentId)
				return
			}

			// Validate RRs
			for _, rrStr := range amp.RRs {
				_, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
			}

			// Convert agent to transport peer
			peer := conf.Internal.TransportManager.SyncPeerFromAgent(agent)

			// Create sync request
			syncReq := &transport.SyncRequest{
				SenderID:       conf.Agent.Identity,
				Zone:           string(amp.Zone),
				SyncType:       transport.SyncTypeNS, // Default to NS, could be detected from RRs
				Records:        groupRRStringsByOwner(amp.RRs),
				DistributionID: fmt.Sprintf("debug-send-sync-%d", time.Now().Unix()),
				MessageType:    "sync",
			}

			lgApi.Info("sending sync to agent", "target", amp.AgentId, "zone", amp.Zone, "rrs", len(amp.RRs))

			// Send sync with fallback
			ctx := context.Background()
			syncResp, err := conf.Internal.TransportManager.SendSyncWithFallback(ctx, peer, syncReq)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("sync failed: %v", err)
			} else {
				resp.Msg = fmt.Sprintf("SYNC sent successfully to %q (distribution: %s)", amp.AgentId, syncReq.DistributionID)
				resp.Data = map[string]interface{}{
					"distribution_id": syncReq.DistributionID,
					"target":          amp.AgentId,
					"zone":            amp.Zone,
					"rr_count":        len(amp.RRs),
					"status":          syncResp.Status,
					"message":         syncResp.Message,
				}
			}
			resp.Status = "ok"

		case "queue-status":
			// Show reliable message queue status and pending messages
			if conf.Internal.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available"
				return
			}

			stats := conf.Internal.TransportManager.GetQueueStats()
			pending := conf.Internal.TransportManager.GetQueuePendingMessages()

			resp.Data = map[string]interface{}{
				"stats":    stats,
				"messages": pending,
			}
			resp.Msg = fmt.Sprintf("Queue: %d pending, %d delivered, %d failed, %d expired",
				stats.TotalPending, stats.TotalDelivered, stats.TotalFailed, stats.TotalExpired)
			resp.Status = "ok"

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown debug command: %q", amp.Command)
		}
	}
}

func (conf *Config) APIbeat() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.MsgQs.Beat == nil {
		lgApi.Error("AgentBeatQ channel is not set, cannot forward heartbeats, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentBeatResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		decoder := json.NewDecoder(r.Body)
		var abp AgentBeatPost
		err := decoder.Decode(&abp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("error encoding beat response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding beat post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		resp.YourIdentity = abp.MyIdentity
		resp.MyIdentity = AgentId(conf.LocalIdentity())

		// log.Printf("APIbeat: received /beat request from %s (identity: %s).\n", r.RemoteAddr, abp.MyIdentity)

		switch abp.MessageType {
		case AgentMsgBeat:
			resp.Status = "ok"
			conf.Internal.MsgQs.Beat <- &AgentMsgReport{
				Transport:    "API",
				MessageType:  abp.MessageType,
				Identity:     abp.MyIdentity,
				BeatInterval: abp.MyBeatInterval,
				Msg:          &abp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %q from %s", AgentMsgToString[abp.MessageType], abp.MyIdentity)
		}
	}
}

// This is the agent-to-agent sync API hello handler.
func (conf *Config) APIhello() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.MsgQs.Hello == nil {
		lgApi.Error("HelloQ channel is not set, cannot forward HELLO msgs, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		lgApi.Debug("received /hello request", "from", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var ahp AgentHelloPost
		err := decoder.Decode(&ahp)

		resp := AgentHelloResponse{
			Time:       time.Now(),
			MyIdentity: AgentId(conf.LocalIdentity()),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("error encoding hello response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /hello post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		// Cannot use ahp.MyIdentity until we know that the JSON unmarshalling has succeeded.
		resp.YourIdentity = ahp.MyIdentity

		needed, errmsg, err := conf.Internal.AgentRegistry.EvaluateHello(&ahp)
		if err != nil {
			lgApi.Warn("error evaluating hello", "err", err)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		if needed {
			lgApi.Info("hello accepted, HSYNC RRset includes both identities", "zone", ahp.Zone)
			resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q and we do share responsibility for zone %q",
				ahp.MyIdentity, conf.LocalIdentity(), ahp.Zone)
		} else {
			lgApi.Warn("hello rejected, HSYNC RRset does not include both identities", "zone", ahp.Zone)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		switch ahp.MessageType {
		case AgentMsgHello:
			resp.Status = "ok" // important
			conf.Internal.MsgQs.Hello <- &AgentMsgReport{
				Transport:   "API",
				MessageType: ahp.MessageType,
				Identity:    ahp.MyIdentity,
				Msg:         &ahp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %q from %s", AgentMsgToString[ahp.MessageType], ahp.MyIdentity)
		}
	}
}

// APIsyncPing is the HSYNC peer ping handler on the sync API router (/sync/ping).
// This is separate from the management /ping (APIping in api_utils.go) which returns
// boot time and version info. This handler echoes the nonce for round-trip verification
// and routes the ping to MsgQs.Ping for state tracking.
func (conf *Config) APIsyncPing() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentPingResponse{
			Time:       time.Now(),
			MyIdentity: AgentId(conf.LocalIdentity()),
		}
		decoder := json.NewDecoder(r.Body)
		var app AgentPingPost
		err := decoder.Decode(&app)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
				lgApi.Error("error encoding ping response", "err", encErr)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /sync/ping post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		if app.Nonce == "" {
			resp.Error = true
			resp.ErrorMsg = "ping nonce must not be empty"
			return
		}

		resp.YourIdentity = app.MyIdentity
		resp.Nonce = app.Nonce
		resp.Status = "ok"

		if conf.Internal.MsgQs != nil && conf.Internal.MsgQs.Ping != nil {
			conf.Internal.MsgQs.Ping <- &AgentMsgReport{
				Transport:   "API",
				MessageType: AgentMsgPing,
				Identity:    app.MyIdentity,
				Msg:         &app,
			}
		}
	}
}

func (conf *Config) APImsg() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.MsgQs.Msg == nil {
		lgApi.Error("msgQ channel is not set, cannot forward API msgs, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMsgResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		decoder := json.NewDecoder(r.Body)
		var amp AgentMsgPost
		err := decoder.Decode(&amp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			lgApi.Debug("encoding msg response", "resp", resp)
			respData, err := json.Marshal(resp)
			if err != nil {
				lgApi.Error("error marshaling msg response", "err", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error marshaling response: %v", err)
				respData, _ = json.Marshal(resp) // Attempt to marshal the error response
			}
			lgApi.Debug("msg response data", "data", string(respData))
			_, err = w.Write(respData)
			if err != nil {
				lgApi.Error("error writing msg response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /msg post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		lgApi.Debug("received /msg request", "messageType", amp.MessageType, "from", r.RemoteAddr, "originator", amp.OriginatorID)

		switch amp.MessageType {
		case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
			resp.Status = "ok"
			// var cresp = make(chan *SynchedDataResponse, 1)
			var cresp = make(chan *AgentMsgResponse, 1)

			select {
			case conf.Internal.MsgQs.Msg <- &AgentMsgPostPlus{
				AgentMsgPost: amp,
				Response:     cresp,
			}:
				select {
				case r := <-cresp:
					lgApi.Debug("received response from msg handler", "resp", r)
					if r.Error {
						lgApi.Warn("error processing message", "originator", amp.OriginatorID, "err", r.ErrorMsg)
						resp.Error = true
						resp.ErrorMsg = r.ErrorMsg
						resp.Status = "error"
					} else {
						resp = *r
						resp.Status = "ok"
					}
					return

				case <-time.After(2 * time.Second):
					lgApi.Warn("no response received for message within timeout", "originator", amp.OriginatorID)
					resp.Error = true
					resp.ErrorMsg = "No response received within timeout period"
				}
			default:
				lgApi.Warn("msg response channel is blocked, skipping message", "originator", amp.OriginatorID)
				resp.Error = true
				resp.ErrorMsg = "Msg channel is blocked"
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown message type: %q from %s", AgentMsgToString[amp.MessageType], amp.OriginatorID)
		}
	}
}
