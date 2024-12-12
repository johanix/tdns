/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	// "github.com/miekg/dns"
)

func (kdb *KeyDB) APIkeystore() func(w http.ResponseWriter, r *http.Request) {

	// kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var kp KeystorePost
		err := decoder.Decode(&kp)
		if err != nil {
			log.Println("APIkeystore: error decoding command post:", err)
		}

		log.Printf("API: received /keystore request (cmd: %s subcommand: %s) from %s.\n",
			kp.Command, kp.SubCommand, r.RemoteAddr)

		// resp := KeystoreResponse{
		// 	Time: time.Now(),
		// }
		var resp *KeystoreResponse

		tx, err := kdb.Begin("APIkeystore")

		defer func() {
			if tx != nil {
				if err != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		if err != nil {
			log.Printf("Error from kdb.Begin(): %v", err)
			resp = &KeystoreResponse{
				Error:    true,
				ErrorMsg: err.Error(),
			}
			return
		}

		switch kp.Command {
		case "sig0-mgmt":
			resp, err = kdb.Sig0KeyMgmt(tx, kp)
			if err != nil {
				log.Printf("Error from Sig0Mgmt(): %v", err)
				resp = &KeystoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}

		case "dnssec-mgmt":
			// log.Printf("APIkeystore: received /keystore request (cmd: %s subcommand: %s)\n",
			//	kp.Command, kp.SubCommand)
			resp, err = kdb.DnssecKeyMgmt(tx, kp)
			if err != nil {
				log.Printf("Error from DnssecKeyMgmt(): %v", err)
				resp = &KeystoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}
			// log.Printf("APIkeystore: keystore dnssec-mgmt response: %v", resp)

		default:
			log.Printf("Unknown command: %s", kp.Command)
			resp = &KeystoreResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Unknown command: %s", kp.Command),
			}
		}
	}
}

func (kdb *KeyDB) APItruststore() func(w http.ResponseWriter, r *http.Request) {

	// kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var tp TruststorePost
		err := decoder.Decode(&tp)
		if err != nil {
			log.Println("APItruststore: error decoding command post:", err)
		}

		log.Printf("API: received /truststore request (cmd: %s subcommand: %s) from %s.\n",
			tp.Command, tp.SubCommand, r.RemoteAddr)

		// resp := TruststoreResponse{}
		var resp *TruststoreResponse

		tx, err := kdb.Begin("APItruststore")

		defer func() {
			if tx != nil {
				if err != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		if err != nil {
			log.Printf("Error from kdb.Begin(): %v", err)
			resp = &TruststoreResponse{
				Error:    true,
				ErrorMsg: err.Error(),
			}
			return
		}

		switch tp.Command {
		case "list-dnskey":
			log.Printf("tdnsd truststore list-dnskey inquiry")
			tmp1 := map[string]TrustAnchor{}
			for _, key := range DnskeyCache.Map.Keys() {
				val, _ := DnskeyCache.Map.Get(key)
				tmp1[key] = TrustAnchor{
					Name:      val.Name,
					Validated: val.Validated,
					Dnskey:    val.Dnskey,
				}
			}
			resp = &TruststoreResponse{
				ChildDnskeys: tmp1,
			}

		case "child-sig0-mgmt":
			resp, err = kdb.Sig0TrustMgmt(tx, tp)
			if err != nil {
				log.Printf("Error from Sig0TrustMgmt(): %v", err)
				resp = &TruststoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}

		default:
			log.Printf("Unknown command: %s", tp.Command)
		}
	}
}

func APIcommand(stopCh chan struct{}) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := CommandResponse{
			Time: time.Now(),
		}

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp.Status = "ok" // only status we know, so far
			resp.Msg = "We're happy, but send more cookies"

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			// var done struct{}
			resp.Status = "stopping"
			resp.Msg = "Daemon was happy, but now winding down"

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			time.Sleep(500 * time.Millisecond)
			stopCh <- struct{}{}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIconfig(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp ConfigPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIconfig: error decoding config post:", err)
		}

		log.Printf("API: received /config request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := ConfigResponse{
			Time: time.Now(),
		}

		switch cp.Command {
		case "reload":
			log.Printf("APIconfig: reloading configuration")
			resp.Msg, err = conf.ReloadConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "reload-zones":
			log.Printf("APIconfig: reloading zones")
			resp.Msg, err = conf.ReloadZoneConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "status":
			log.Printf("APIconfig: config status inquiry")
			resp.Msg = fmt.Sprintf("Configuration is ok, server boot time: %s, last config reload: %s",
				conf.ServerBootTime.Format(timelayout), conf.ServerConfigTime.Format(timelayout))

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown config command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIdelegation(delsyncq chan DelegationSyncRequest) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var dp DelegationPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APIdelegation: error decoding delegation post:", err)
		}

		log.Printf("API: received /delegation request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		resp := DelegationResponse{
			Time: time.Now(),
			Zone: dp.Zone,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		var zd *ZoneData
		var exist bool
		if zd, exist = Zones.Get(dp.Zone); !exist {
			msg := fmt.Sprintf("Zone \"%s\" is unknown.", dp.Zone)
			log.Printf("APIdelegation: %s", msg)
			resp.Error = true
			resp.ErrorMsg = msg
			return
		}
		respch := make(chan DelegationSyncStatus, 1)

		syncreq := DelegationSyncRequest{
			ZoneName: dp.Zone,
			ZoneData: zd,
			Response: respch,
		}
		var syncstate DelegationSyncStatus

		switch dp.Command {
		// Find out whether delegation is in sync or not and report on details
		case "status":
			log.Printf("APIdelegation: zone %s delegation status inquiry", dp.Zone)
			syncreq.Command = "DELEGATION-STATUS"

			delsyncq <- syncreq

			select {
			case syncstate = <-respch:
				resp.SyncStatus = syncstate
			case <-time.After(4 * time.Second):
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		// Find out whether delegation is in sync or not and if not then fix it
		case "sync":
			log.Printf("APIdelegation: zone %s: will check and sync changes to delegation data\n", dp.Zone)
			syncreq.Command = "EXPLICIT-SYNC-DELEGATION"

			delsyncq <- syncreq

			select {
			case syncstate = <-respch:
				resp.SyncStatus = syncstate
				log.Printf("APIdelegation: zone %s: received response from DelegationSyncEngine: %s", dp.Zone, syncstate.Msg)
			case <-time.After(4 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "Timeout waiting for delegation sync response"
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown delegation command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func APIdebug() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		resp := DebugResponse{
			Status: "ok", // only status we know, so far
			Msg:    "We're happy, but send more cookies",
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var dp DebugPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APICdebug: error decoding debug post:", err)
		}

		log.Printf("API: received /debug request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		switch dp.Command {
		case "rrset":
			log.Printf("tdnsd debug rrset inquiry")
			if zd, ok := Zones.Get(dp.Zone); ok {
				//			        idx, _ := zd.OwnerIndex.Get(dp.Qname)
				//				if owner := &zd.Owners[idx]; owner != nil {
				owner, err := zd.GetOwner(dp.Qname)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

				if rrset, ok := owner.RRtypes.Get(dp.Qtype); ok {
					resp.RRset = rrset
				}
				log.Printf("tdnsd debug rrset: owner: %v", owner)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "validate-rrset":
			log.Printf("tdnsd debug validate-rrset")
			if zd, ok := Zones.Get(dp.Zone); ok {

				rrset, valid, err := zd.LookupAndValidateRRset(dp.Qname, dp.Qtype, true)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else if rrset == nil {
					resp.Msg = fmt.Sprintf("Found no RRset for %s %s", dp.Qname, dns.TypeToString[dp.Qtype])
				} else {
					resp.Msg = fmt.Sprintf("Found %s %s RRset (validated: %v)", dp.Qname, dns.TypeToString[dp.Qtype], valid)
					for _, rr := range rrset.RRs {
						resp.Msg += fmt.Sprintf("\n%s", rr.String())
					}
				}
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "lav":
			log.Printf("tdnsd debug lookup-and-validate inquiry")
			zd, folded := FindZone(dp.Qname)
			if zd == nil {
				resp.ErrorMsg = fmt.Sprintf("Did not find a known zone for qname %s",
					dp.Qname)
				resp.Error = true
			} else {
				if folded {
					dp.Qname = strings.ToLower(dp.Qname)
				}
				// tmp, err := zd.LookupRRset(dp.Qname, dp.Qtype, dp.Verbose)
				rrset, valid, err := zd.LookupAndValidateRRset(dp.Qname, dp.Qtype, dp.Verbose)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if rrset != nil {
						resp.RRset = *rrset
						resp.Validated = valid
					}
				}
			}

		case "show-ta":
			log.Printf("tdnsd debug show-ta")
			resp.Msg = fmt.Sprintf("TAStore: %v", DnskeyCache.Map.Keys())
			tas := []TrustAnchor{}
			for _, taname := range DnskeyCache.Map.Keys() {
				ta, ok := DnskeyCache.Map.Get(taname)
				if !ok {
					continue
				}
				tas = append(tas, ta)
			}
			resp.TrustedDnskeys = tas

		case "show-rrsetcache":
			log.Printf("tdnsd debug show-rrsetcache")
			resp.Msg = fmt.Sprintf("RRsetCache: %v", RRsetCache.Map.Keys())
			rrsets := []CachedRRset{}
			for _, rrsetkey := range RRsetCache.Map.Keys() {
				rrset, ok := RRsetCache.Map.Get(rrsetkey)
				if !ok {
					continue
				}
				rrsets = append(rrsets, rrset)
			}
			resp.CachedRRsets = rrsets

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func (kdb *KeyDB) APIkeystate() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var ksp KeyStatePost
		err := decoder.Decode(&ksp)
		if err != nil {
			log.Println("APIkeystate: error decoding keystate post:", err)
		}

		log.Printf("API: received /keystate request (cmd: %s) from %s.\n",
			ksp.Command, r.RemoteAddr)

		resp := KeyStateResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		// Hitta zonen
		zd, exist := Zones.Get(ksp.Zone)
		if !exist {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", ksp.Zone)
			return
		}

		switch ksp.Command {
		case "inquire":
			// Skapa en DNS-förfrågan med EDNS(0) KeyState option
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(ksp.Zone), dns.TypeANY)

			// Lägg till EDNS(0) KeyState option
			keyStateOpt := CreateKeyStateOption(ksp.KeyID, ksp.KeyState, ksp.ExtraText)
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.Option = []dns.EDNS0{keyStateOpt}
			m.Extra = append(m.Extra, o)

			// Hämta parent's adress för uppdateringar
			dsync_target, err := LookupDSYNCTarget(ksp.Zone, Globals.IMR, dns.TypeANY, SchemeUpdate)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to lookup DSYNC target: %v", err)
				return
			}

			// Hämta aktiv nyckel för signering
			sak, err := zd.KeyDB.GetSig0Keys(ksp.Zone, Sig0StateActive)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Could not fetch active key: %v", err)
				return
			}

			// Signera meddelandet
			signedMsg, err := SignMsg(*m, ksp.Zone, sak)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to sign message: %v", err)
				return
			}

			// Skicka det signerade meddelandet
			c := new(dns.Client)
			c.Timeout = 5 * time.Second
			r, _, err := c.Exchange(signedMsg, dsync_target.Addresses[0])
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to send DNS query: %v", err)
				return
			}

			keystate, err := ExtractKeyStateFromMsg(r)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to extract KeyState from response: %v", err)
				return
			}

			//		fmt.Printf("KeyState: %+v\n", keystate)
			resp.KeyState = keystate

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", ksp.Command)
		}
	}
}
