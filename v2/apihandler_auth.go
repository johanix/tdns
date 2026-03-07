/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API handlers for tdns-auth peer management (multi-provider DNSSEC).
 * /auth/peer:    peer-ping, status commands.
 * /auth/distrib: peer listing (same pattern as agent/combiner distrib).
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// AuthPeerPost is the request body for /auth/peer.
type AuthPeerPost struct {
	Command string `json:"command"`
	PeerID  string `json:"peer_id,omitempty"` // Target peer for ping (default: configured agent)
}

// AuthPeerResponse is the response body for /auth/peer.
type AuthPeerResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
}

// APIauthPeer handles /auth/peer requests for multi-provider peer management.
func APIauthPeer(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := AuthPeerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "authPeer", "err", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var dp AuthPeerPost
		err := decoder.Decode(&dp)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("error decoding request: %v", err)
			return
		}

		lgApi.Debug("received /auth/peer request", "cmd", dp.Command, "from", r.RemoteAddr)

		switch dp.Command {
		case "peer-ping":
			// Determine target peer: use --id if provided, otherwise default to first configured agent
			targetID := dp.PeerID
			if targetID == "" {
				if conf.MultiProvider == nil || len(conf.MultiProvider.Agents) == 0 {
					resp.Error = true
					resp.ErrorMsg = "multi-provider.agents not configured and no --id specified"
					return
				}
				targetID = conf.MultiProvider.Agents[0].Identity
			}

			// Use the shared doPeerPing — same function as agent uses
			pingResp := doPeerPing(conf, targetID, false)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "status":
			tm := conf.Internal.TransportManager
			if tm == nil {
				resp.Msg = "multi-provider: not active (TransportManager not initialized)"
				return
			}
			mp := conf.MultiProvider
			var agentIDs []string
			if mp != nil {
				for _, a := range mp.Agents {
					agentIDs = append(agentIDs, a.Identity)
				}
			}
			agentList := "none"
			if len(agentIDs) > 0 {
				agentList = strings.Join(agentIDs, ", ")
			}
			resp.Msg = fmt.Sprintf("multi-provider: active, identity: %s, agents: [%s]", tm.LocalID, agentList)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown auth peer command: %q", dp.Command)
		}
	}
}

// AuthDistribPost is the request body for /auth/distrib.
type AuthDistribPost struct {
	Command string `json:"command"`
}

// APIauthDistrib handles /auth/distrib requests — peer listing for the signer.
// Uses the same JSON response format as agent/combiner distrib so that
// listDistribPeers/displayPeers works identically.
func APIauthDistrib(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AuthDistribPost
		if err := decoder.Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":      time.Now(),
				"error":     true,
				"error_msg": fmt.Sprintf("error decoding request: %v", err),
			})
			return
		}

		lgApi.Debug("received /auth/distrib request", "cmd", req.Command, "from", r.RemoteAddr)

		switch req.Command {
		case "peer-list":
			tm := conf.Internal.TransportManager
			if tm == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"time":      time.Now(),
					"error":     true,
					"error_msg": "multi-provider not active (TransportManager not initialized)",
				})
				return
			}

			// Enumerate peers from PeerRegistry — same serialization as agent/combiner
			allPeers := tm.PeerRegistry.All()
			peerMaps := make([]map[string]interface{}, len(allPeers))
			for i, peer := range allPeers {
				peerMaps[i] = map[string]interface{}{
					"peer_id":     dns.Fqdn(peer.ID),
					"peer_type":   "agent",
					"transport":   "DNS",
					"crypto_type": "JOSE",
					"state":       peer.GetState().String(),
				}
				if addr := peer.CurrentAddress(); addr != nil {
					peerMaps[i]["address"] = fmt.Sprintf("dns://%s:%d/", addr.Host, addr.Port)
					peerMaps[i]["dns_uri"] = fmt.Sprintf("dns://%s:%d/", addr.Host, addr.Port)
					peerMaps[i]["port"] = addr.Port
					peerMaps[i]["addresses"] = []string{addr.Host}
				}
				lastUsed, _, _, _, _, _, _, pingSent, pingRecv, totalSent, totalRecv := peer.Stats.GetDetailedStats()
				peerMaps[i]["distrib_sent"] = int(totalSent)
				peerMaps[i]["ping_sent"] = pingSent
				peerMaps[i]["ping_received"] = pingRecv
				peerMaps[i]["total_sent"] = totalSent
				peerMaps[i]["total_received"] = totalRecv
				if !lastUsed.IsZero() {
					peerMaps[i]["last_used"] = lastUsed.Format(time.RFC3339)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":  time.Now(),
				"msg":   fmt.Sprintf("Found %d peer(s) with working keys", len(allPeers)),
				"error": false,
				"peers": peerMaps,
			})

		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":      time.Now(),
				"error":     true,
				"error_msg": fmt.Sprintf("unknown auth distrib command: %q", req.Command),
			})
		}
	}
}
