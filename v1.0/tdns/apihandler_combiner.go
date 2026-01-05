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

func APIcombiner(app *AppDetails, refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIcombiner: error decoding combiner command post:", err)
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
