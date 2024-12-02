/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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

type Sidecars struct {
	S cmap.ConcurrentMap[string, *Sidecar]
}

func MusicSyncEngine(mconf *Config, stopch chan struct{}) {
	ourSidecarId := mconf.Sidecar.Identity

	// sidecars is a map of known "remote" sidecars that we
	// have received HELLO messages from.
	//	sidecars := map[tdns.MsignerMethod]map[string]*Sidecar{
	//		tdns.MsignerMethodAPI: map[string]*Sidecar{},
	//		tdns.MsignerMethodDNS: map[string]*Sidecar{},
	//	}

	sidecars := &Sidecars{
		S: cmap.New[*Sidecar](),
	}

	// wannabe_sidecars is a map of sidecars that we have received
	// a HELLO message from, but have not yet verified that they are
	// correct
	wannabe_sidecars := map[string]*Sidecar{}

	// zones is a map of zones and the remote sidecars that share them with us
	zones := map[string][]*Sidecar{}

	var missing []string
	var zonename string
	var syncitem tdns.MusicSyncRequest
	syncQ := mconf.Internal.MusicSyncQ

	var beatitem Heartbeat
	beatQ := mconf.Internal.HeartbeatQ

	if !viper.GetBool("syncengine.active") {
		log.Printf("MusicSyncEngine is NOT active. No detection of of communication with other music-sidecars will be done.")
		for {
			select {
			case <-syncQ: // ensure that we keep reading to keep the
				log.Printf("MusicSyncEngine: NOT active, butreceived a sync request: %+v", syncitem)
				continue // channel open (otherwise other parts of MUSIC
			} // may block)
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

				err := sidecars.UpdateSidecars(ourSidecarId, wannabe_sidecars, syncitem, zones, zonename)
				if err != nil {
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

		case beatitem = <-beatQ:
			log.Printf("MusicSyncEngine: Received heartbeat from %s", beatitem.Name)
			switch beatitem.Type {
			case "HELLO":
				log.Printf("MusicSyncEngine: Received initial hello from %s", beatitem.Name)
			case "BEAT":
				log.Printf("MusicSyncEngine: Received heartbeat from %s", beatitem.Name)
			case "FULLBEAT":
				log.Printf("MusicSyncEngine: Received full heartbeat from %s", beatitem.Name)
			default:
				log.Printf("MusicSyncEngine: Unknown heartbeat type: %s in beat from %s", beatitem.Type, beatitem.Name)
			}

		case <-HBticker.C:
			log.Printf("MusicSyncEngine: Heartbeat ticker. Contacting other known music-sidecars.")
			ReportProgress()

		case <-fullHBticker.C:
			log.Printf("MusicSyncEngine: Full Heartbeat ticker. Contacting other known music-sidecars with complete zone lists.")
			ReportProgress()

		case <-HelloEvalTicker.C:
			log.Printf("MusicSyncEngine: Hello evaluation ticker. Evaluating sidecars that claim to share zones with us.")
			err := EvaluateSidecarHello(sidecars, wannabe_sidecars, zones)
			if err != nil {
				log.Printf("MusicSyncEngine: Hello evaluation ticker. Error evaluating sidecars: %v", err)
			}
			ReportProgress()

		case <-stopch:
			HBticker.Stop()
			fullHBticker.Stop()
			log.Println("MusicSyncEngine: stop signal received.")
			return
		}
	}
}

func (ss *Sidecars) UpdateSidecars(ourSidecarId string, wannabe_sidecars map[string]*Sidecar,
	syncitem tdns.MusicSyncRequest, zones map[string][]*Sidecar, zonename string) error {

	for _, remoteSidecarRR := range syncitem.MusicSyncStatus.MsignerAdds {
		if prr, ok := remoteSidecarRR.(*dns.PrivateRR); ok {
			if prr.Header().Rrtype != tdns.TypeMSIGNER {
				log.Printf("UpdateSidecars: Unknown RR type in MSIGNER RRset: %s", remoteSidecarRR.String())
				continue
			}
			msrr := prr.Data.(*tdns.MSIGNER)
			remoteMethod := msrr.Method
			remoteSidecar := msrr.Target
			// log.Printf("MaybeSendHello: remoteSidecar: %s, remoteMechanism: %s, sidecarId: %s", remoteSidecar, tdns.MsignerMethodToString[remoteMethod], sidecarId)
			if remoteSidecar == ourSidecarId {
				// we don't need to send a hello to ourselves
				log.Printf("UpdateSidecars: remoteSidecar [%s][%s] is ourselves (%s), no need to talk to ourselves",
					tdns.MsignerMethodToString[remoteMethod], remoteSidecar, ourSidecarId)
				continue
			}

			// is this a new sidecar
			new, s, err := ss.LocateSidecar(remoteSidecar, remoteMethod)
			if err != nil {
				log.Printf("UpdateSidecars: Error locating sidecar %s: %v", remoteSidecar, err)
				continue
			}

			if new {
				// Schedule sending an HELLO message to the new sidecar
				log.Printf("MaybeSendHello: Scheduling HELLO message to remote %s sidecar %s",
					tdns.MsignerMethodToString[remoteMethod], remoteSidecar)
				// Add code to send HELLO message here
				err = s.SendHello()
				if err != nil {
					log.Printf("UpdateSidecars: Error sending HELLO message to %s: %v", remoteSidecar, err)
				}
			}

		}
	}

	return nil
}

func EvaluateSidecarHello(sidecars *Sidecars, wannabe_sidecars map[string]*Sidecar, zones map[string][]*Sidecar) error {

	// for each sidecar in wannabe_sidecars, check if it is already in sidecars
	// if it is, add it to sidecars and remove it from wannabe_sidecars
	// if it is not, check whether it should be

	for _, ws := range wannabe_sidecars {
		if _, ok := sidecars.S.Get(ws.Identity); ok {
			// already in sidecars
			delete(wannabe_sidecars, ws.Identity)
		} else {
			// check if it should be in the set of known sidecars
			log.Printf("EvaluateSidecarHello: Sidecar %s is not in sidecars, but claims to share zones with us.",
				ws.Identity)
		}
	}

	return nil
}

func (s *Sidecar) SendHello() error {

	if s.ApiMethod {
		// Create the SidecarHelloPost struct
		helloPost := SidecarHelloPost{
			SidecarId: s.Identity,
			Addresses: s.Details[tdns.MsignerMethodAPI].Addrs,
			Port:      s.Details[tdns.MsignerMethodAPI].Port,
		}

		// Encode the struct as JSON
		jsonData, err := json.Marshal(helloPost)
		if err != nil {
			return fmt.Errorf("failed to marshal SidecarHelloPost: %v", err)
		}

		// Lookup the TLSA record for the target sidecar
		tlsarrset := s.Details[tdns.MsignerMethodAPI].TlsaRR

		// Use the TLSA record to authenticate the remote end securely
		// (This is a simplified example, in a real implementation you would need to configure the TLS client with the TLSA record)
		tlsConfig := &tls.Config{
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				for _, rawCert := range rawCerts {
					cert, err := x509.ParseCertificate(rawCert)
					if err != nil {
						return fmt.Errorf("failed to parse certificate: %v", err)
					}
					if cert.Subject.CommonName != s.Identity {
						return fmt.Errorf("unexpected certificate common name (should have been %s)", s.Identity)
					}

					err = tdns.VerifyCertAgainstTlsaRR(tlsarrset, rawCert)
					if err != nil {
						return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
					}
				}
				return nil
			},
		}

		// Create the HTTPS client
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		// Send the HTTPS POST request
		url := s.Details[tdns.MsignerMethodAPI].BaseUri + "/hello"
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to send HTTPS POST request: %v", err)
		}
		defer resp.Body.Close()

		// Print the response to stdout
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		fmt.Printf("Received response: %s\n", string(body))
	}

	if s.DnsMethod {
		// TODO: implement DNS-based hello
		return fmt.Errorf("DNS-based hello not implemented")
	}

	return nil
}
