/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
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
	Message string
	Pings   int
}

type PingResponse struct {
	Time    time.Time
	Client  string
	Message string
	Pings   int
	Pongs   int
}

var pongs int = 0

func APIping(appName string) func(w http.ResponseWriter, r *http.Request) {
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
			Time:    time.Now(),
			Client:  r.RemoteAddr,
			Message: fmt.Sprintf("%spong from %s @ %s", tls, appName, hostname),
			Pings:   pp.Pings + 1,
			Pongs:   pongs,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
