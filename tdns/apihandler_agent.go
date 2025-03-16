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
		var ap AgentPost
		err := decoder.Decode(&ap)
		if err != nil {
			log.Println("APIagent: error decoding agent command post:", err)
		}

		log.Printf("API: received /agent request (cmd: %s) from %s.\n",
			ap.Command, r.RemoteAddr)

		resp := AgentResponse{
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
		ap.Zone = ZoneName(dns.Fqdn(string(ap.Zone)))
		if ap.Command != "config" {
			zd, exist = Zones.Get(string(ap.Zone))
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", ap.Zone)
				return
			}
		}

		if Globals.Debug {
			log.Printf("APIagent: debug mode, also checking for debug commands: received /agent debug request (cmd: %s) from %s.\n",
				ap.Command, r.RemoteAddr)
			var debugcmd bool = true
			switch ap.Command {
			case "send-notify-dnskey":
				log.Printf("APIagent: received debug command send-notify-dnskey, will synthesize an API NOTIFY(DNSKEY) for the given zone: %+v\n", ap)

				conf.Internal.AgentQs.Command <- AgentMsgPost{
					// Transport:   "API",
					MessageType: "NOTIFY",
					Zone:        ZoneName(ap.Zone),
					// Msg:         &ap,
				}

			case "send-notify-ns":
				log.Printf("APIagent: received debug command send-notify-ns, will synthesize an API NOTIFY(NS) for the given zone: %+v\n", ap)

				conf.Internal.AgentQs.Command <- AgentMsgPost{
					//Transport:   "API",
					MessageType: "NOTIFY",
					Zone:        ZoneName(ap.Zone),
					// Identity:    ap.MyIdentity,
					// Msg:         &ap,
				}
			default:
				debugcmd = false
			}
			if debugcmd {
				return
			}
		}

		switch ap.Command {
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
				resp.ErrorMsg = fmt.Sprintf("Zone %s error: %v", ap.Zone, err)
				return
			}

			// Get the HSYNC RRset from the apex
			hsyncRRset := owner.RRtypes.GetOnlyRRSet(TypeHSYNC)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC RRset", ap.Zone)
				return
			}

			// Convert the RRs to strings for transmission
			hsyncStrs := make([]string, len(hsyncRRset.RRs))
			for i, rr := range hsyncRRset.RRs {
				hsyncStrs[i] = rr.String()
			}
			resp.HsyncRRs = hsyncStrs

			// Get the actual agents from the registry
			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(ap.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting remote agents: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", ap.Zone)

		case "hsync-locate":
			if ap.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			ap.AgentId = AgentId(dns.Fqdn(string(ap.AgentId)))
			agent, err := conf.Internal.Registry.GetAgentInfo(ap.AgentId)
			if err != nil {
				// Start async lookup and return a message that lookup is in progress
				conf.Internal.Registry.LocateAgent(ap.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent lookup in progress for %s", ap.AgentId)
				return
			}

			// If agent info is incomplete, start a new lookup
			if agent.State == AgentStateNeeded {
				conf.Internal.Registry.LocateAgent(ap.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent information is incomplete for %s, lookup in progress", ap.AgentId)
				return
			}

			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Found existing agent %s", ap.AgentId)

			//		case "list-known-agents":
			//			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", ap.Command)
			resp.Error = true
		}
	}
}

func APIbeat(conf *Config) func(w http.ResponseWriter, r *http.Request) {
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
		case "BEAT", "FULLBEAT":
			resp.Status = "ok"
			conf.Internal.AgentQs.Beat <- AgentMsgReport{
				Transport:   "API",
				MessageType: abp.MessageType,
				Identity:    abp.MyIdentity,
				Msg:         &abp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %q from %s", abp.MessageType, abp.MyIdentity)
		}
	}
}

// This is the agent-to-agent sync API hello handler.
func APIhello(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.Hello == nil {
		log.Println("APIhello: HelloQ channel is not set. Cannot forward HELLO msgs. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentHelloResponse{
			Time: time.Now(),
		}
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var ahp AgentHelloPost
		err := decoder.Decode(&ahp)

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

		resp.YourIdentity = ahp.MyIdentity
		resp.MyIdentity = AgentId(conf.Agent.Identity)

		// Now let's check if we need to know this agent
		if ahp.Zone == "" {
			log.Printf("APIhello: Error: No zone specified in HELLO message")
			resp.Error = true
			resp.ErrorMsg = "Error: No zone specified in HELLO message"
			return
		}

		// Check if we have this zone
		zd, exists := Zones.Get(string(ahp.Zone))
		if !exists {
			log.Printf("APIhello: Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone)
			return
		}

		// Check if zone has HSYNC RRset
		hsyncRR, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
		if err != nil {
			log.Printf("APIhello: Error: Error trying to retrieve HSYNC RRset for zone %q: %v", ahp.Zone, err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error trying to retrieve HSYNC RRset for zone %q: %v", ahp.Zone, err)
			return
		}
		if hsyncRR == nil {
			log.Printf("APIhello: Error: Zone %q has no HSYNC RRset", ahp.Zone)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error: Zone %q has no HSYNC RRset", ahp.Zone)
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
					if AgentId(hsync.Identity) == ahp.MyIdentity {
						foundThem = true
					}
				}
			}
		}

		if !foundUs || !foundThem {
			resp.Error = true
			log.Printf("APIhello: Error: Zone %q HSYNC RRset does not include both our identities", ahp.Zone)
			log.Printf("APIhello: HSYNC RRset: %+v", hsyncRR)
			log.Printf("APIhello: your identity: %s, my identity: %s", ahp.MyIdentity, conf.Agent.Identity)
			resp.ErrorMsg = fmt.Sprintf("Error: Zone %q HSYNC RRset does not include both our identities", ahp.Zone)
			return
		}

		log.Printf("APIhello: Success: Zone %q HSYNC RRset includes both our identities. Sending nice response", ahp.Zone)
		resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q and we do share responsibility for zone %q",
			ahp.MyIdentity, conf.Agent.Identity, ahp.Zone)

		switch ahp.MessageType {
		case "HELLO":
			resp.Status = "ok" // important
			resp.YourIdentity = ahp.MyIdentity
			resp.MyIdentity = AgentId(conf.Agent.Identity)
			conf.Internal.AgentQs.Hello <- AgentMsgReport{
				Transport:   "API",
				MessageType: "HELLO",
				Identity:    ahp.MyIdentity,
				Msg:         &ahp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %q from %s", ahp.MessageType, ahp.MyIdentity)
		}
	}
}

func APImsg(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.Msg == nil {
		log.Println("APImsg: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
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
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APImsg: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APImsg: error decoding beat post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		log.Printf("APImsg: received /beat request from %s (identity: %s).\n", r.RemoteAddr, amp.MyIdentity)

		switch amp.MessageType {
		case "NOTIFY", "QUERY", "STATUS":
			resp.Status = "ok"
			conf.Internal.AgentQs.Msg <- AgentMsgReport{
				Transport:   "API",
				MessageType: amp.MessageType,
				Identity:    amp.MyIdentity,
				Msg:         &amp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown message type: %q from %s", amp.MessageType, amp.MyIdentity)
		}
	}
}

func APIagentDebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.AgentQs.Msg == nil {
		log.Println("APImsg: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
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
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APImsg: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APImsg: error decoding beat post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		log.Printf("APImsg: received /beat request from %s (identity: %s).\n", r.RemoteAddr, amp.MyIdentity)

		switch amp.MessageType {
		case "NOTIFY", "QUERY", "STATUS":
			resp.Status = "ok"
			conf.Internal.AgentQs.Msg <- AgentMsgReport{
				Transport:   "API",
				MessageType: amp.MessageType,
				Identity:    amp.MyIdentity,
				Msg:         &amp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown message type: %q from %s", amp.MessageType, amp.MyIdentity)
		}
	}
}
