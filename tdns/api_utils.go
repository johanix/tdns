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

	"github.com/gorilla/mux"
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

func walkRoutes(router *mux.Router, address string) {
	log.Printf("Defined API endpoints for router on: %s\n", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			log.Printf("%-6s %s\n", methods[m], path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		log.Panicf("Logging err: %s\n", err.Error())
	}
	//	return nil
}
