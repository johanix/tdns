/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

func APIzoneReplace(app *AppDetails, refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var msp MultiSignerPost
		err := decoder.Decode(&msp)
		if err != nil {
			log.Println("APImultisigner: error decoding multisigner command post:", err)
		}

		log.Printf("API: received /multisigner request (cmd: %s) from %s.\n",
			msp.Command, r.RemoteAddr)

		resp := MultiSignerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		zd, exist := Zones.Get(msp.Zone)
		if !exist && msp.Command != "list-zones" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", msp.Zone)
			return
		}

		switch msp.Command {
		case "fetch-rrset":
			rrset, err := zd.GetRRset(msp.Name, msp.Type)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.RRset = *rrset
			resp.Msg = fmt.Sprintf("Zone %s: %s %s RRset as requested", msp.Zone, msp.Name, dns.TypeToString[msp.Type])

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown multisigner command: %s", msp.Command)
			resp.Error = true
		}
	}
}

func APICombiner(app *AppDetails, refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICombiner: error decoding combiner command post:", err)
		}

		log.Printf("API: received /combiner request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := CombinerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		cp.Zone = dns.Fqdn(cp.Zone)
		zd, exist := Zones.Get(cp.Zone)
		if !exist {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", cp.Zone)
			return
		}

		switch cp.Command {
		case "add":
			err := zd.AddCombinerDataNG(cp.Data)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = fmt.Sprintf("Added local RRsets for zone %s", cp.Zone)

		case "list":
			if zd.CombinerData == nil {
				resp.Msg = fmt.Sprintf("No local data for zone %s", cp.Zone)
				return
			}

			resp.Data = zd.GetCombinerDataNG()
			resp.Msg = fmt.Sprintf("Local data for zone %s", cp.Zone)

		case "remove":
			// TODO: Implement remove functionality
			resp.Error = true
			resp.ErrorMsg = "Remove operation not yet implemented"
			return

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner command: %s", cp.Command)
			resp.Error = true
		}
	}
}
