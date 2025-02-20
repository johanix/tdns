/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	//	"github.com/DNSSEC-Provisioning/music/music"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

type MSAs struct {
	S cmap.ConcurrentMap[string, *MSA]
}

func MusicSyncEngine(mconf *Config, stopch chan struct{}) {
	ourMSAId := mconf.MSA.Identity

	sidecars := &MSAs{
		S: cmap.New[*MSA](),
	}

	// wannabe_sidecars is a map of sidecars that we have received
	// a HELLO message from, but have not yet verified that they are
	// correct
	wannabe_sidecars := map[string]*MSA{}

	// mszones is a map of zones and the remote sidecars that share them with us
	mszones := map[string][]*MSA{}

	var missing []string
	var zonename string
	var syncitem tdns.MusicSyncRequest
	syncQ := mconf.Internal.MusicSyncQ

	var sbr MSABeatReport
	beatQ := make(chan MSABeatReport, 10)
	mconf.Internal.HeartbeatQ = beatQ

	mconf.Internal.MusicSyncStatusQ = make(chan MusicSyncStatus, 10)

	if !viper.GetBool("syncengine.active") {
		log.Printf("MusicSyncEngine is NOT active. No detection of of communication with other music-sidecars will be done.")
		for range syncQ {
			log.Printf("MusicSyncEngine: NOT active, but received a sync request: %+v", syncitem)
			continue // ensure that we keep reading to keep the channel open (otherwise other parts of MUSIC may block)
		}
	}

	// hello_eval_interval is the interval between evaluations of
	// whether a claimed remote sidecar really shares any zones with us
	hello_eval_interval := viper.GetInt("syncengine.intervals.helloeval")
	if hello_eval_interval > 1800 {
		hello_eval_interval = 1800
	}
	if hello_eval_interval < 300 {
		hello_eval_interval = 300
	}
	viper.Set("syncengine.intervals.helloeval", hello_eval_interval)

	// hbinterval is the interval between the outgoing heartbeat messages
	hbinterval := viper.GetInt("syncengine.intervals.heartbeat")
	if hbinterval > 1800 {
		hbinterval = 1800
	}
	if hbinterval < 15 {
		hbinterval = 15
	}
	viper.Set("syncengine.intervals.heartbeat", 15)

	// fullhbinterval is the interval between the outgoing full heartbeat messages
	// NOTE: unclear if we need this, or if it is useful
	fullhbinterval := viper.GetInt("syncengine.intervals.fullheartbeat")
	if fullhbinterval > 3600 {
		fullhbinterval = 3600
	}
	if fullhbinterval < 60 {
		fullhbinterval = 60
	}
	viper.Set("syncengine.intervals.fullheartbeat", fullhbinterval)

	log.Printf("Starting MusicSyncEngine (heartbeat will run once every %d seconds)", hbinterval)

	HelloEvalTicker := time.NewTicker(time.Duration(hello_eval_interval) * time.Second)
	HBticker := time.NewTicker(time.Duration(hbinterval) * time.Second)
	fullHBticker := time.NewTicker(time.Duration(fullhbinterval) * time.Second)

	ReportProgress := func() {
		allok := true
		sidecarids := []string{}
		for _, s := range sidecars.S.Items() {
			sidecarids = append(sidecarids, s.Identity)
		}
		if allok {
			log.Printf("MusicSyncEngine: received heartbeats from these sidecars: %s (the expected result)", strings.Join(sidecarids, ", "))
		} else {
			log.Printf("MusicSyncEngine: received heartbeats from these sidecars: %+v (missing some sidecars: %+v)",
				sidecars, missing)
		}
	}

	for {
		select {
		case syncitem = <-syncQ:
			cmd := syncitem.Command
			zonename = syncitem.ZoneName
			switch cmd {
			case "RESET-MSIGNER-GROUP":
				log.Printf("MusicSyncEngine: Zone %s MSIGNER RRset has changed. Resetting MSIGNER group. Removed MSIGNER RRs:\n", zonename)
				// log.Printf("MusicSyncEngine: Removed MSIGNER RRs:\n")
				for _, rr := range syncitem.MusicSyncStatus.MsignerRemoves {
					log.Printf("  %s", rr.String())
				}

				err := sidecars.UpdateMSAs(ourMSAId, wannabe_sidecars, syncitem, mszones, zonename)
				if err != nil {
					// XXX: Handle error.
					log.Printf("MusicSyncEngine: Error sending HELLO message: %v", err)
				}

				log.Printf("MusicSyncEngine: Added MSIGNER RRs:\n")
				for _, rr := range syncitem.MusicSyncStatus.MsignerAdds {
					log.Printf("  %s", rr.String())
				}

			case "SYNC-DNSKEY-RRSET":
				log.Printf("MusicSyncEngine: Zone %s DNSKEY RRset has changed. Should send NOTIFY(DNSKEY) to other sidecars.", zonename)

			default:
				log.Printf("MusicSyncEngine: Unknown command: %s in request: %+v", cmd, syncitem)
			}
			ReportProgress()

		case sbr = <-beatQ:
			log.Printf("MusicSyncEngine: Received heartbeat from %s", sbr.Beat.Identity)
			switch sbr.Beat.MessageType {
			case "HELLO":
				log.Printf("MusicSyncEngine: Received initial hello from %s", sbr.Beat.Identity)
			case "BEAT":
				log.Printf("MusicSyncEngine: Received heartbeat from %s", sbr.Beat.Identity)
			case "FULLBEAT":
				log.Printf("MusicSyncEngine: Received full heartbeat from %s", sbr.Beat.Identity)
			default:
				log.Printf("MusicSyncEngine: Unknown heartbeat type: %s in beat from %s", sbr.Beat.MessageType, sbr.Beat.Identity)
			}

		case <-HBticker.C:
			log.Printf("MusicSyncEngine: Heartbeat ticker. Contacting other known music-sidecars.")
			ReportProgress()

		case <-fullHBticker.C:
			log.Printf("MusicSyncEngine: Full Heartbeat ticker. Contacting other known music-sidecars with complete zone lists.")
			ReportProgress()

		case <-HelloEvalTicker.C:
			log.Printf("MusicSyncEngine: Hello evaluation ticker. Evaluating sidecars that claim to share zones with us.")
			err := EvaluateMSAHello(sidecars, wannabe_sidecars, mszones)
			if err != nil {
				log.Printf("MusicSyncEngine: Hello evaluation ticker. Error evaluating sidecars: %v", err)
			}
			ReportProgress()

		case req := <-mconf.Internal.MusicSyncStatusQ:
			log.Printf("MusicSyncEngine: Received STATUS request")
			if req.Response == nil {
				log.Printf("MusicSyncEngine: STATUS request has no response channel")
				continue
			}

			cleaned := map[string]*MSA{}
			for _, s := range sidecars.S.Items() {
				log.Printf("MusicSyncEngine: MSA %s: %+v", s.Identity, s.Details)
				cleaned[s.Identity] = s.CleanCopy()
			}

			select {
			case req.Response <- MusicSyncStatus{
				MSAs: cleaned,
				Error:    false,
			}:
			case <-time.After(5 * time.Second):
				log.Printf("MusicSyncEngine: STATUS response timed out")
			}

		case <-stopch:
			HBticker.Stop()
			fullHBticker.Stop()
			log.Println("MusicSyncEngine: stop signal received.")
			return
		}
	}
}

func (ss *MSAs) UpdateMSAs(ourMSAId string, wannabe_sidecars map[string]*MSA,
	syncitem tdns.MusicSyncRequest, mszones map[string][]*MSA, zonename string) error {

	for _, remoteMSARR := range syncitem.MusicSyncStatus.MsignerAdds {
		if prr, ok := remoteMSARR.(*dns.PrivateRR); ok {
			if prr.Header().Rrtype != tdns.TypeMSIGNER {
				log.Printf("UpdateMSAs: Unknown RR type in MSIGNER RRset: %s", remoteMSARR.String())
				continue
			}
			msrr, ok := prr.Data.(*tdns.MSIGNER)
			if !ok {
				log.Printf("UpdateMSAs: MSIGNER RRset contains non-MSIGNER RR: %s", remoteMSARR.String())
				continue
			}
			remoteMethod := msrr.Method
			remoteMSA := msrr.Target
			// log.Printf("MaybeSendHello: remoteMSA: %s, remoteMechanism: %s, sidecarId: %s", remoteMSA, tdns.MsignerMethodToString[remoteMethod], sidecarId)
			if remoteMSA == ourMSAId {
				// we don't need to send a hello to ourselves
				log.Printf("UpdateMSAs: remoteMSA [%s][%s] is ourselves (%s), no need to talk to ourselves",
					tdns.MsignerMethodToString[remoteMethod], remoteMSA, ourMSAId)
				continue
			}

			// is this a new sidecar
			new, s, err := ss.LocateMSA(remoteMSA, remoteMethod)
			if err != nil {
				log.Printf("UpdateMSAs: Error locating sidecar %s: %v", remoteMSA, err)
				continue
			}

			if new {
				if _, exists := s.Details[remoteMethod]; !exists {
					log.Printf("UpdateMSAs: MSA %s does not have a %s method configured", remoteMSA, tdns.MsignerMethodToString[remoteMethod])
					continue
				} else {
					err := s.NewMusicSyncApiClient(remoteMSA, s.Details[remoteMethod].BaseUri, "", "", "tlsa")
					if err != nil {
						log.Printf("UpdateMSAs: Error creating MUSIC SyncAPI client for remote sidecar %s: %v", remoteMSA, err)
						continue
					}
					// Schedule sending an HELLO message to the new sidecar
					log.Printf("MaybeSendHello: Scheduling HELLO message to remote %s sidecar %s",
						tdns.MsignerMethodToString[remoteMethod], remoteMSA)
					// Add code to send HELLO message here
					err = s.SendHello()
					if err != nil {
						log.Printf("UpdateMSAs: Error sending HELLO message to %s: %v", remoteMSA, err)
					}
				}
			}

		}
	}

	return nil
}

func EvaluateMSAHello(sidecars *MSAs, wannabe_sidecars map[string]*MSA, zones map[string][]*MSA) error {

	// for each sidecar in wannabe_sidecars, check if it is already in sidecars
	// if it is, add it to sidecars and remove it from wannabe_sidecars
	// if it is not, check whether it should be

	for _, ws := range wannabe_sidecars {
		if _, ok := sidecars.S.Get(ws.Identity); ok {
			// already in sidecars
			delete(wannabe_sidecars, ws.Identity)
		} else {
			// check if it should be in the set of known sidecars
			log.Printf("EvaluateMSAHello: MSA %s is not in sidecars, but claims to share zones with us.",
				ws.Identity)
		}
	}

	return nil
}

func (s *MSA) SendHello() error {

	log.Printf("Sending HELLO message to sidecar %s", MSAToString(s))

	// dump.P(s)
	if s.Methods["API"] {
		if _, exists := s.Details[tdns.MsignerMethodAPI]; !exists {
			log.Printf("SendHello: Details for API method is nil for sidecar %s", s.Identity)
			return fmt.Errorf("API details not available for sidecar %s", s.Identity)
		}
		log.Printf("Sending HELLO message to sidecar %s via API method (baseuri: %s)", s.Identity, s.Details[tdns.MsignerMethodAPI].BaseUri)
		// Create the MSAHelloPost struct
		helloPost := MSAHelloPost{
			MessageType: "HELLO",
			Identity:    s.Identity,
			Addresses:   s.Details[tdns.MsignerMethodAPI].Addrs,
			Port:        s.Details[tdns.MsignerMethodAPI].Port,
		}

		// Send the HTTPS POST request
		status, resp, err := s.Api.RequestNG("POST", "/hello", helloPost, false)
		if err != nil {
			return fmt.Errorf("failed to send HTTPS POST request: %v", err)
		}
		if status != http.StatusOK {
			return fmt.Errorf("received HTTP status %d from sidecar %s: %s", status, s.Identity, string(resp))
		}
		// defer resp.Body.Close()

		var shr MSAHelloResponse
		err = json.Unmarshal(resp, &shr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response: %v", err)
		}

		fmt.Printf("Received response (status %d): %s\n", status, string(resp))
	}

	if s.Methods["DNS"] {
		log.Printf("Sending HELLO message to sidecar %s via DNS method", s.Identity)
		// TODO: implement DNS-based hello
		log.Printf("Warning: DNS-based hello not implemented")
	}

	return nil
}
