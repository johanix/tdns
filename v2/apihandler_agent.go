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
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// doCombinerPing runs a ping to the configured combiner (DNS CHUNK or API).
// useAPI true = HTTPS API ping; false = CHUNK-based DNS ping.
// Returns an AgentMgmtResponse with Msg/Error/ErrorMsg set.
func doCombinerPing(conf *Config, useAPI bool) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Identity: AgentId(conf.Agent.Identity),
		Time:     time.Now(),
	}
	if conf.Agent == nil || conf.Agent.Combiner == nil {
		resp.Error = true
		resp.ErrorMsg = "agent.combiner not configured"
		return resp
	}
	if useAPI {
		if conf.Agent.Combiner.ApiBaseUrl == "" {
			resp.Error = true
			resp.ErrorMsg = "agent.combiner.api_base_url not configured"
			return resp
		}
		url := strings.TrimSuffix(conf.Agent.Combiner.ApiBaseUrl, "/") + "/ping"
		body := PingPost{Msg: "agent combiner ping", Pings: 1}
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
			resp.ErrorMsg = fmt.Sprintf("apiping failed: %v", err)
			return resp
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("combiner API returned %d", res.StatusCode)
			return resp
		}
		var pr PingResponse
		if err := json.NewDecoder(res.Body).Decode(&pr); err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("decode combiner ping response: %v", err)
			return resp
		}
		resp.Msg = fmt.Sprintf("apiping ok: %s", pr.Msg)
		return resp
	}
	// DNS CHUNK ping
	if conf.Agent.Combiner.Address == "" {
		resp.Error = true
		resp.ErrorMsg = "agent.combiner.address not configured"
		return resp
	}
	if conf.Internal.TransportManager == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not configured (DNS transport disabled?)"
		return resp
	}
	host, portStr, err := net.SplitHostPort(conf.Agent.Combiner.Address)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("invalid agent.combiner.address %q: %v", conf.Agent.Combiner.Address, err)
		return resp
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("invalid port in agent.combiner.address %q", conf.Agent.Combiner.Address)
		return resp
	}
	peer := transport.NewPeer("combiner")
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pingResp, err := conf.Internal.TransportManager.SendPing(ctx, peer)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("dnsping failed: %v", err)
		return resp
	}
	if !pingResp.OK {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("combiner did not acknowledge (responder: %s)", pingResp.ResponderID)
		return resp
	}
	resp.Msg = fmt.Sprintf("dnsping ok: %s echoed nonce", pingResp.ResponderID)
	return resp
}

func (conf *Config) APIagent(refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			log.Println("APIagent: error decoding agent command post:", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("API: received /agent request (cmd: %s) from %s.", amp.Command, r.RemoteAddr)

		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Identity: AgentId(conf.Agent.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		// XXX: hsync cmds should move to its own endpoint, not be mixed with agent
		var zd *ZoneData
		var exist bool
		noZoneCommands := map[string]bool{
			"config": true, "hsync-agentstatus": true, "combiner-dnsping": true, "combiner-apiping": true,
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

		case "combiner-dnsping":
			pingResp := doCombinerPing(conf, false)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "combiner-apiping":
			pingResp := doCombinerPing(conf, true)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "update-local-zonedata":
			log.Printf("API: update-local-zonedata: added RRs: %+v", amp.AddedRRs)
			log.Printf("API: update-local-zonedata: removed RRs: %+v", amp.RemovedRRs)

			conf.Internal.AgentQs.Command <- &AgentMgmtPostPlus{
				amp,
				rch,
			}
			select {
			case r := <-rch:
				// log.Printf("APIagent: Received response from msg handler: %+v", r)
				resp = *r
				// resp.Status = "ok"

			case <-time.After(10 * time.Second):
				log.Printf("APIagent: no response from CommandHandler after 10 seconds")
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
			hsyncRRset := owner.RRtypes.GetOnlyRRSet(core.TypeHSYNC)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC RRset", amp.Zone)
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
				authorized, reason := conf.Internal.AgentRegistry.TransportManager.IsAgentAuthorized(string(amp.AgentId), string(amp.Zone))
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", amp.Command)
			resp.Error = true
		}
	}
}

func (conf *Config) APIagentDebug() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.DebugCommand == nil {
		log.Println("APIagentDebug: DebugCommand channel is not set. Cannot forward debug commands. This is a fatal error.")
		log.Printf("APIagentDebug: AgentQs: %+v", conf.Internal.AgentQs)
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
				log.Printf("APIagentDebug: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APIagentDebug: error decoding /agent/debugpost: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		log.Printf("APIagentDebug: received /agent/debug request (command: %q, messagetype: %q) from %s.\n", amp.Command, AgentMsgToString[amp.MessageType], r.RemoteAddr)

		rch := make(chan *AgentMgmtResponse, 1)

		switch amp.Command {
		case "send-notify", "send-rfi":
			// XXX: this is a bit bass-ackwards, in the debug case we're not using
			// amp.Command but rather amp.MessageType.
			switch amp.MessageType {
			case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
				resp.Status = "ok"
				conf.Internal.AgentQs.DebugCommand <- &AgentMgmtPostPlus{
					amp,
					rch,
				}
				select {
				case r := <-rch:
					// log.Printf("APIagentDebug: Received response from msg handler: %+v", r)
					resp = *r
					resp.Status = "ok"

				case <-time.After(10 * time.Second):
					log.Printf("APIagentDebug: no response from send-notify after 10 seconds")
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
			log.Printf("APIagentDebug: dump-agentregistry: keys: %+v", keys)
			for _, key := range keys {
				if agent, exists := ar.S.Get(key); exists {
					log.Printf("Agent registry: %s", agent.Identity)
				}
			}
			log.Printf("APIagentDebug: dump-agentregistry: num shards: %d", ar.S.NumShards())
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
			// johani 20250324: This does not work, crashes in IterBuffered() with shards=0 for unknown reason
			// resp.Msg = fmt.Sprintf("Zone data repo: %+v", conf.Internal.ZoneDataRepo)
			// resp.ZoneDataRepo = conf.Internal.ZoneDataRepo
			sdcmd := &SynchedDataCmd{
				Cmd:      "dump-zonedatarepo",
				Zone:     "",
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.Internal.AgentQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.ZoneDataRepo = response.ZDR
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "No response from SynchedDataCmd after 2 seconds, state unknown"
			}

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

			log.Printf("hsync-inject-sync: Injecting %d RRs from %q for zone %q", len(parsedRRs), amp.AgentId, amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine
			conf.Internal.AgentQs.SynchedDataUpdate <- &SynchedDataUpdate{
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
				Zone:          string(amp.Zone),
				Records:       amp.RRs, // Use strings directly
				DistributionID: fmt.Sprintf("debug-force-sync-%d", time.Now().Unix()),
			}

			log.Printf("hsync-force-sync: Forcing sync to peer %q for zone %q", amp.AgentId, amp.Zone)

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
					"peer_id":        amp.AgentId,
					"zone":           amp.Zone,
					"status":         syncResp.Status,
					"message":        syncResp.Message,
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
			conf.Internal.AgentQs.SynchedDataCmd <- sdcmd

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

			log.Printf("hsync-send-to-combiner: Sending %d RRs from %q for zone %q to combiner", len(parsedRRs), amp.AgentId, amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine (which forwards to combiner)
			conf.Internal.AgentQs.SynchedDataUpdate <- &SynchedDataUpdate{
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

			log.Printf("hsync-test-chain: Running %q scenario for zone %q", scenario, amp.Zone)

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
			conf.Internal.AgentQs.SynchedDataUpdate <- &SynchedDataUpdate{
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
							Zone:          string(amp.Zone),
							Records:       amp.RRs, // Use string records directly
							DistributionID: fmt.Sprintf("test-chain-%d-%s", time.Now().Unix(), agent.Identity),
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
								"success":        syncResp.Status == transport.ConfirmSuccess,
								"message":        syncResp.Message,
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

			log.Printf("fake-sync-from: Injecting %d RRs from %q for zone %q", len(parsedRRs), amp.AgentId, amp.Zone)

			// Create response channel
			cresp := make(chan *AgentMsgResponse, 1)

			// Send to SynchedDataEngine
			conf.Internal.AgentQs.SynchedDataUpdate <- &SynchedDataUpdate{
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
				SenderID:      conf.Agent.Identity,
				Zone:          string(amp.Zone),
				SyncType:      transport.SyncTypeNS, // Default to NS, could be detected from RRs
				Records:       amp.RRs,
				DistributionID: fmt.Sprintf("debug-send-sync-%d", time.Now().Unix()),
			}

			log.Printf("send-sync-to: Sending sync to agent %q for zone %q (%d RRs)", amp.AgentId, amp.Zone, len(amp.RRs))

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
					"target":         amp.AgentId,
					"zone":           amp.Zone,
					"rr_count":       len(amp.RRs),
					"status":         syncResp.Status,
					"message":        syncResp.Message,
				}
			}
			resp.Status = "ok"

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown debug command: %q", amp.Command)
		}
	}
}

func (conf *Config) APIbeat() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.Beat == nil {
		log.Println("APIbeat: AgentBeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
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
				log.Printf("APIbeat: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APIbeat: error decoding beat post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		resp.YourIdentity = abp.MyIdentity
		resp.MyIdentity = AgentId(conf.Agent.Identity)

		// log.Printf("APIbeat: received /beat request from %s (identity: %s).\n", r.RemoteAddr, abp.MyIdentity)

		switch abp.MessageType {
		case AgentMsgBeat:
			resp.Status = "ok"
			conf.Internal.AgentQs.Beat <- &AgentMsgReport{
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
	if conf.Internal.AgentQs.Hello == nil {
		log.Println("APIhello: HelloQ channel is not set. Cannot forward HELLO msgs. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var ahp AgentHelloPost
		err := decoder.Decode(&ahp)

		resp := AgentHelloResponse{
			Time:       time.Now(),
			MyIdentity: AgentId(conf.Agent.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APIhello: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APIhello: error decoding /hello post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		// Cannot use ahp.MyIdentity until we know that the JSON unmarshalling has succeeded.
		resp.YourIdentity = ahp.MyIdentity

		needed, errmsg, err := conf.Internal.AgentRegistry.EvaluateHello(&ahp)
		if err != nil {
			log.Printf("APIhello: error evaluating hello: %+v", err)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		if needed {
			log.Printf("APIhello: Success: Zone %q HSYNC RRset includes both our identities. Sending nice response", ahp.Zone)
			resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q and we do share responsibility for zone %q",
				ahp.MyIdentity, conf.Agent.Identity, ahp.Zone)
		} else {
			log.Printf("APIhello: Error: Zone %q HSYNC RRset does not include both our identities", ahp.Zone)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		switch ahp.MessageType {
		case AgentMsgHello:
			resp.Status = "ok" // important
			conf.Internal.AgentQs.Hello <- &AgentMsgReport{
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

func (conf *Config) APImsg() func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.Msg == nil {
		log.Println("APImsg: msgQ channel is not set. Cannot forward API msgs. This is a fatal error.")
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
			log.Printf("APImsg: encoding response: %+v", resp)
			respData, err := json.Marshal(resp)
			if err != nil {
				log.Printf("APImsg: error marshaling response: %v\n", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error marshaling response: %v", err)
				respData, _ = json.Marshal(resp) // Attempt to marshal the error response
			}
			log.Printf("APImsg: response data: %s", string(respData))
			_, err = w.Write(respData)
			if err != nil {
				log.Printf("APImsg: error writing response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APImsg: error decoding /msg post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		log.Printf("APImsg: received /msg %q request from %s (identity: %s).\n", amp.MessageType, r.RemoteAddr, amp.MyIdentity)

		switch amp.MessageType {
		case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
			resp.Status = "ok"
			// var cresp = make(chan *SynchedDataResponse, 1)
			var cresp = make(chan *AgentMsgResponse, 1)

			select {
			case conf.Internal.AgentQs.Msg <- &AgentMsgPostPlus{
				AgentMsgPost: amp,
				Response:     cresp,
			}:
				select {
				case r := <-cresp:
					log.Printf("APImsg: Received response from msg handler: %+v", r)
					if r.Error {
						log.Printf("APImsg: Error processing message from %s: %s", amp.MyIdentity, r.ErrorMsg)
						resp.Error = true
						resp.ErrorMsg = r.ErrorMsg
						resp.Status = "error"
					} else {
						resp = *r
						resp.Status = "ok"
					}
					return

				case <-time.After(2 * time.Second):
					log.Printf("APImsg: No response received for message from %s after waiting 2 seconds", amp.MyIdentity)
					resp.Error = true
					resp.ErrorMsg = "No response received within timeout period"
				}
			default:
				log.Printf("APImsg: Msg response channel is blocked, skipping message from %s", amp.MyIdentity)
				resp.Error = true
				resp.ErrorMsg = "Msg channel is blocked"
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown message type: %q from %s", AgentMsgToString[amp.MessageType], amp.MyIdentity)
		}
	}
}
