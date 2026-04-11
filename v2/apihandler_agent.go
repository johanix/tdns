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

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// doPeerPing pings any known peer via DNS CHUNK or API.
// Role-agnostic helper retained in tdns for use by the
// distrib op ping --to combiner legacy path (apihandler_agent_distrib.go).
// The MP /peer endpoint uses the tdns-mp copy of this function.
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
	resp.Msg = fmt.Sprintf("ping ok (dns transport): %s echoed nonce %s rtt=%s", pingResp.ResponderID, pingResp.Nonce, pingResp.RTT.Round(time.Microsecond))
	return resp
}

// lookupStaticPeer checks all static peer configurations and returns a temporary
// Peer if found. Retained alongside doPeerPing for the legacy distrib op path.
func (conf *Config) lookupStaticPeer(peerID string) *transport.Peer {
	// Agent-side: combiner
	if conf.MultiProvider != nil && conf.MultiProvider.Role == "agent" && conf.MultiProvider.Combiner != nil &&
		dns.Fqdn(conf.MultiProvider.Combiner.Identity) == peerID && conf.MultiProvider.Combiner.Address != "" {
		if peer := peerFromAddress(peerID, conf.MultiProvider.Combiner.Address); peer != nil {
			if conf.MultiProvider.Combiner.ApiBaseUrl != "" {
				peer.APIEndpoint = conf.MultiProvider.Combiner.ApiBaseUrl
			}
			return peer
		}
	}

	// Agent-side: signer
	if conf.MultiProvider != nil && conf.MultiProvider.Role == "agent" && conf.MultiProvider.Signer != nil &&
		dns.Fqdn(conf.MultiProvider.Signer.Identity) == peerID && conf.MultiProvider.Signer.Address != "" {
		return peerFromAddress(peerID, conf.MultiProvider.Signer.Address)
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
			Identity: AgentId(conf.MultiProvider.Identity),
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
			"config": true, "hsync-agentstatus": true,
			"discover": true, "hsync-locate": true,
			"imr-query": true, "imr-flush": true, "imr-reset": true, "imr-show": true,
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
			tmp := SanitizeForJSON(conf.MultiProvider)
			if p, ok := tmp.(*MultiProviderConf); ok && p != nil {
				resp.AgentConfig = *p
			}
			resp.AgentConfig.Api.CertData = ""
			resp.AgentConfig.Api.KeyData = ""

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

		case "add-rr", "del-rr":
			// Add or delete an RR: store locally + sync to peers + send to combiner
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}
			if zd != nil && zd.Options[OptMPDisallowEdits] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %s is signed but this provider is not a signer; modifications not allowed", amp.Zone)
				return
			}

			isAdd := amp.Command == "add-rr"
			apex := dns.Fqdn(string(amp.Zone))
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				if dns.Fqdn(rr.Header().Name) != apex {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("record owner %q is not the zone apex %q", rr.Header().Name, apex)
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

			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: AgentId(conf.MultiProvider.Identity),
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			opStr := "add"
			if !isAdd {
				opStr = "delete"
			}
			opsMap := make(map[uint16][]string)
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
				inetRR := dns.Copy(rr)
				inetRR.Header().Class = dns.ClassINET
				opsMap[rrtype] = append(opsMap[rrtype], inetRR.String())
			}
			for rrtype, records := range opsMap {
				zu.Operations = append(zu.Operations, core.RROperation{
					Operation: opStr,
					RRtype:    dns.TypeToString[rrtype],
					Records:   records,
				})
			}

			action := "Adding"
			if !isAdd {
				action = "Removing"
			}
			lgApi.Info("RR operation", "cmd", amp.Command, "action", action, "count", len(parsedRRs), "zone", amp.Zone)

			force := false
			if amp.Data != nil {
				if f, ok := amp.Data["force"].(bool); ok {
					force = f
				}
			}
			cresp := make(chan *AgentMsgResponse, 1)
			select {
			case conf.Internal.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    AgentId(conf.MultiProvider.Identity),
				UpdateType: "local",
				Update:     zu,
				Force:      force,
				Response:   cresp,
			}:
				// enqueued successfully
			case <-r.Context().Done():
				resp.Error = true
				resp.ErrorMsg = "request cancelled"
				resp.Status = "fail"
				return
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "SynchedDataUpdate queue full, try again later"
				resp.Status = "fail"
				return
			}

			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("%s RR(s) failed: %s", amp.Command, r.ErrorMsg)
					resp.Status = "fail"
				} else {
					resp.Msg = fmt.Sprintf("%s %d RR(s) for zone %q", action, len(parsedRRs), amp.Zone)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
					resp.Status = "ok"
				}
			case <-r.Context().Done():
				resp.Error = true
				resp.ErrorMsg = "request cancelled"
				resp.Status = "fail"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for SynchedDataEngine response"
				resp.Status = "timeout"
			}

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
				authorized, reason := conf.Internal.AgentRegistry.MPTransport.IsPeerAuthorized(string(amp.AgentId), string(amp.Zone))
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

		case "refresh-keys":
			zd.RequestAndWaitForKeyInventory(r.Context())
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
			// Route to group election if zone belongs to a provider group
			ar := conf.Internal.AgentRegistry
			if ar != nil && ar.ProviderGroupManager != nil {
				pg := ar.ProviderGroupManager.GetGroupForZone(amp.Zone)
				if pg != nil {
					lem.StartGroupElection(pg.GroupHash, pg.Members, pg.Zones)
					resp.Msg = fmt.Sprintf("Group election started for zone %s (group %s)", amp.Zone, pg.GroupHash[:8])
					return
				}
			}
			// No provider group — per-zone election
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
			keyState, extra, err := QueryParentKeyStateDetailed(kdb, imr, string(amp.Zone), keyid)
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
			go conf.ParentSyncAfterKeyPublication(amp.Zone, string(amp.Zone), keyid, algorithm)
			resp.Msg = fmt.Sprintf("Bootstrap triggered for zone %s (keyid %d), running async", amp.Zone, keyid)

		case "imr-query":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			qtypeStr, _ := amp.Data["qtype"].(string)
			if qname == "" || qtypeStr == "" {
				resp.Error = true
				resp.ErrorMsg = "qname and qtype are required"
				return
			}
			qname = dns.Fqdn(qname)
			qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown RR type: %s", qtypeStr)
				return
			}
			crrset := imr.Cache.Get(qname, qtype)
			if crrset == nil {
				resp.Msg = fmt.Sprintf("No cache entry for %s %s", qname, qtypeStr)
				return
			}
			// Build response with cache metadata
			entry := map[string]interface{}{
				"name":       crrset.Name,
				"rrtype":     dns.TypeToString[crrset.RRtype],
				"rcode":      dns.RcodeToString[int(crrset.Rcode)],
				"ttl":        crrset.Ttl,
				"expiration": crrset.Expiration.Format(time.RFC3339),
				"expires_in": time.Until(crrset.Expiration).Truncate(time.Second).String(),
				"context":    fmt.Sprintf("%d", crrset.Context),
				"state":      fmt.Sprintf("%d", crrset.State),
			}
			if crrset.RRset != nil {
				var rrs []string
				for _, rr := range crrset.RRset.RRs {
					rrs = append(rrs, rr.String())
				}
				entry["records"] = rrs
			}
			resp.Data = entry
			resp.Msg = fmt.Sprintf("Cache entry for %s %s", qname, dns.TypeToString[qtype])

		case "imr-flush":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			if qname == "" {
				resp.Error = true
				resp.ErrorMsg = "qname is required"
				return
			}
			qname = dns.Fqdn(qname)
			removed, err := imr.Cache.FlushDomain(qname, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("flush failed: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("Flushed %d cache entries at and below %s", removed, qname)

		case "imr-reset":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			removed := imr.Cache.FlushAll()
			resp.Msg = fmt.Sprintf("IMR cache reset: flushed %d entries (root NS and glue preserved)", removed)

		case "imr-show":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			identity := string(amp.AgentId)
			if identity == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id (--id) is required"
				return
			}
			identity = dns.Fqdn(identity)

			// Collect all cache entries related to this identity's discovery names
			// Discovery names are subdomains of identity: _https._tcp.<id>, api.<id>,
			// _dns._tcp.<id>, dns.<id>, and <id> itself
			var entries []map[string]interface{}
			idCanon := strings.ToLower(identity)
			for item := range imr.Cache.RRsets.IterBuffered() {
				cr := item.Val
				name := strings.ToLower(cr.Name)
				// Match: name equals identity or is a subdomain of identity
				if name != idCanon && !strings.HasSuffix(name, "."+idCanon) {
					continue
				}
				entry := map[string]interface{}{
					"name":       cr.Name,
					"rrtype":     dns.TypeToString[cr.RRtype],
					"rcode":      dns.RcodeToString[int(cr.Rcode)],
					"ttl":        cr.Ttl,
					"expiration": cr.Expiration.Format(time.RFC3339),
					"expires_in": time.Until(cr.Expiration).Truncate(time.Second).String(),
				}
				if cr.RRset != nil {
					var rrs []string
					for _, rr := range cr.RRset.RRs {
						rrs = append(rrs, rr.String())
					}
					entry["records"] = rrs
				}
				entries = append(entries, entry)
			}
			resp.Data = entries
			resp.Msg = fmt.Sprintf("Found %d cache entries for identity %s", len(entries), identity)

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
			Identity: AgentId(conf.MultiProvider.Identity),
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
				Zone:     amp.Zone,
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
				if zd.MP != nil && zd.MP.CombinerData != nil {
					zoneData := make(map[string]map[string][]string)
					for item := range zd.MP.CombinerData.IterBuffered() {
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
					if zd.MP != nil && zd.MP.CombinerData != nil {
						zoneData := make(map[string]map[string][]string)
						for item := range zd.MP.CombinerData.IterBuffered() {
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
			peer := conf.Internal.MPTransport.SyncPeerFromAgent(agent)

			// Create sync request
			syncReq := &transport.SyncRequest{
				SenderID:       conf.MultiProvider.Identity,
				Zone:           string(amp.Zone),
				SyncType:       transport.SyncTypeNS, // Default to NS, could be detected from RRs
				Records:        groupRRStringsByOwner(amp.RRs),
				DistributionID: fmt.Sprintf("debug-send-sync-%d", time.Now().Unix()),
				MessageType:    "sync",
			}

			lgApi.Info("sending sync to agent", "target", amp.AgentId, "zone", amp.Zone, "rrs", len(amp.RRs))

			// Send sync with fallback
			ctx := context.Background()
			syncResp, err := conf.Internal.MPTransport.SendSyncWithFallback(ctx, peer, syncReq)
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

			stats := conf.Internal.MPTransport.GetQueueStats()
			pending := conf.Internal.MPTransport.GetQueuePendingMessages()

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
