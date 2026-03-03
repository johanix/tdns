/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"fmt"
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

func APIping(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tls := ""
		if r.TLS != nil {
			tls = "TLS "
		}

		lgApi.Debug("received ping request", "tls", tls != "", "from", r.RemoteAddr, "app", Globals.App.Name)

		decoder := json.NewDecoder(r.Body)
		var pp PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			lgApi.Warn("error decoding ping request", "err", err)
		}
		pongs += 1
		hostname, _ := os.Hostname()
		response := PingResponse{
			Time:       time.Now(),
			BootTime:   Globals.App.ServerBootTime,
			Version:    Globals.App.Version,
			Daemon:     Globals.App.Name,
			ServerHost: hostname,
			Client:     r.RemoteAddr,
			Msg:        fmt.Sprintf("%spong from %s @ %s", tls, Globals.App.Name, hostname),
			Pings:      pp.Pings + 1,
			Pongs:      pongs,
		}

		// select {
		// case conf.Internal.KeyDB.UpdateQ <- UpdateRequest{Cmd: "PING", ZoneName: "whatever."}:
		//	log.Printf("APIping: sent PING to update queue")
		// case <-time.After(5 * time.Second):
		//	log.Printf("APIping: timeout sending PING to update queue")
		// }

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func walkRoutes(router *mux.Router, address string) {
	lgApi.Info("defined API endpoints", "address", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			lgApi.Debug("route", "method", methods[m], "path", path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		lgApi.Error("failed to walk routes", "err", err)
		panic(fmt.Sprintf("failed to walk routes: %s", err.Error()))
	}
}
