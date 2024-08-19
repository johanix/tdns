/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type PingPost struct {
	Msg   string
	Pings int
}

type PingResponse struct {
	Time       time.Time
	Client     string
	BootTime   time.Time
	Version    string
	ServerHost string // "master.dnslab"
	Daemon     string // "tdnsd"
	Msg        string
	Pings      int
	Pongs      int
}

var pongs int = 0

func APIping(appName, appVersion string, bootTime time.Time) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tls := ""
		if r.TLS != nil {
			tls = "TLS "
		}

		log.Printf("APIping: received %s/ping request from %s.\n", tls, r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIping: error decoding ping post:", err)
		}
		pongs += 1
		hostname, _ := os.Hostname()
		response := PingResponse{
			Time:       time.Now(),
			BootTime:   bootTime,
			Version:    appVersion,
			Daemon:     appName,
			ServerHost: hostname,
			Client:     r.RemoteAddr,
			Msg:        fmt.Sprintf("%spong from %s @ %s", tls, appName, hostname),
			Pings:      pp.Pings + 1,
			Pongs:      pongs,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
