/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

func APImultisigner(kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var msp MultiSignerPost
		err := decoder.Decode(&msp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "multisigner", "from", r.RemoteAddr, "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /multisigner request", "cmd", msp.Command, "from", r.RemoteAddr)

		resp := MultiSignerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "multisigner", "err", err)
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
				return
			}
			if rrset == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s: %s %s RRset not found", msp.Zone, msp.Name, dns.TypeToString[msp.Type])
				return
			}
			resp.RRset = *rrset
			resp.Msg = fmt.Sprintf("Zone %s: %s %s RRset as requested", msp.Zone, msp.Name, dns.TypeToString[msp.Type])

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown multisigner command: %s", msp.Command)
			resp.Error = true
		}
	}
}
