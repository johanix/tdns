/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	// "encoding/json"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

func (conf *Config) APIagent(refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp AgentPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIagent: error decoding agent command post:", err)
		}

		log.Printf("API: received /agent request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := AgentResponse{
			Time:     time.Now(),
			Identity: conf.Agent.Identity,
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
		cp.Zone = dns.Fqdn(cp.Zone)
		if cp.Command != "config" {
			zd, exist = Zones.Get(cp.Zone)
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", cp.Zone)
				return
			}
		}

		switch cp.Command {
		case "config":
			tmp := SanitizeForJSON(conf.Agent)
			resp.AgentConfig = tmp.(LocalAgentConf)
			resp.AgentConfig.Api.CertData = ""
			resp.AgentConfig.Api.KeyData = ""

		case "hsync-status":
			// Get the apex owner object
			owner, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s error: %v", cp.Zone, err)
				return
			}

			// Get the HSYNC RRset from the apex
			hsyncRRset := owner.RRtypes.GetOnlyRRSet(TypeHSYNC)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC RRset", cp.Zone)
				return
			}

			// Convert the RRs to strings for transmission
			hsyncStrs := make([]string, len(hsyncRRset.RRs))
			for i, rr := range hsyncRRset.RRs {
				hsyncStrs[i] = rr.String()
			}
			resp.HsyncRRs = hsyncStrs

			// Get the actual agents from the registry
			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting remote agents: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", cp.Zone)

		case "hsync-locate":
			if cp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			cp.AgentId = dns.Fqdn(cp.AgentId)
			agent, err := conf.Internal.Registry.GetAgentInfo(cp.AgentId)
			if err != nil {
				// Start async lookup and return a message that lookup is in progress
				conf.Internal.Registry.LocateAgent(cp.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent lookup in progress for %s", cp.AgentId)
				return
			}

			// If agent info is incomplete, start a new lookup
			if agent.State == AgentStateNeeded {
				conf.Internal.Registry.LocateAgent(cp.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent information is incomplete for %s, lookup in progress", cp.AgentId)
				return
			}

			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Found existing agent %s", cp.AgentId)

			//		case "list-known-agents":
			//			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", cp.Command)
			resp.Error = true
		}
	}
}

func APIbeat(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.HeartbeatQ == nil {
		log.Println("APIbeat: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentBeatResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		decoder := json.NewDecoder(r.Body)
		var bp AgentBeatPost
		err := decoder.Decode(&bp)

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

		log.Printf("APIbeat: received /beat request from %s (identity: %s).\n", r.RemoteAddr, bp.MyIdentity)

		switch bp.MessageType {
		case "BEAT", "FULLBEAT":
			resp.Status = "ok"
			conf.Internal.HeartbeatQ <- AgentMsgReport{
				Transport:   "api",
				MessageType: bp.MessageType,
				Identity:    bp.MyIdentity,
				Msg:         &bp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %q from %s", bp.MessageType, bp.MyIdentity)
		}
	}
}

// This is the agent-to-agent sync API hello handler.
func APIhello(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.HelloQ == nil {
		log.Println("APIhello: HelloQ channel is not set. Cannot forward HELLO msgs. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentHelloResponse{
			Time: time.Now(),
		}
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var hp AgentHelloPost
		err := decoder.Decode(&hp)

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

		// Now let's check if we need to know this agent
		if hp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "Error: No zone specified in HELLO message"
			return
		}

		// Check if we have this zone
		zd, exists := Zones.Get(hp.Zone)
		if !exists {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", hp.Zone)
			return
		}

		// Check if zone has HSYNC RRset
		hsyncRR, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error trying to retrieve HSYNC RRset for zone %q: %v", hp.Zone, err)
			return
		}
		if hsyncRR == nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error: Zone %q has no HSYNC RRset", hp.Zone)
			return
		}

		// Check if both our identity and remote agent are in HSYNC RRset
		foundUs := false
		foundThem := false
		for _, rr := range hsyncRR.RRs {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if hsync, ok := prr.Data.(*HSYNC); ok {
					if hsync.Identity == conf.Agent.Identity {
						foundUs = true
					}
					if hsync.Identity == hp.Identity {
						foundThem = true
					}
				}
			}
		}

		if !foundUs || !foundThem {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error: Zone %q HSYNC RRset does not include both our identities", hp.Zone)
			return
		}

		resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q and we do share responsibility for zone %q",
			hp.Identity, conf.Agent.Identity, hp.Zone)

		switch hp.MessageType {
		case "HELLO":
			resp.Status = "ok" // important
			conf.Internal.HelloQ <- AgentMsgReport{
				Transport:   "api",
				MessageType: "HELLO",
				Identity:    hp.Identity,
				Msg:         &hp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %q from %s", hp.MessageType, hp.Identity)
		}
	}
}
