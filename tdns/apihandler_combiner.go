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
