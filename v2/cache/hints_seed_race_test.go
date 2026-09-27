/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"log"
	"os"
	"sync"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// A root refresh seeds the root servers from the hints while queries run, and
// the root servers are the shared instances every query to the root uses.
// seedFromHints used to read and write their Src and Transports without the
// server's lock, so a transport signal or a source upgrade applied to a root
// server meanwhile was a data race (#714).
func TestHintSeedingWhileRootServersChange(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", log.LstdFlags), false, false)
	rrcache.Quiet = true
	if err := rrcache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	const nsname = "a.root-servers.net."
	server, ok := rrcache.AuthServerMap.Get(nsname)
	if !ok {
		t.Fatalf("%s not in the AuthServerMap after priming", nsname)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// What a transport signal and an answer naming the server do
		// meanwhile. At least once, so the check below has a signal to find.
		defer wg.Done()
		for {
			server.SetTransportSignal([]core.Transport{core.TransportDoT, core.TransportDo53},
				[]string{"dot", "do53"}, map[core.Transport]uint8{core.TransportDoT: 50})
			server.ForceSetSrc("answer")
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	for i := 0; i < 50; i++ {
		if err := rrcache.PrimeFromHintsOnly(""); err != nil {
			t.Errorf("round %d: PrimeFromHintsOnly: %v", i, err)
			break
		}
	}
	close(stop)
	wg.Wait()

	// Seeding fills in what the server lacks; it does not replace what a
	// signal installed.
	if got := server.GetTransports(); len(got) != 2 || got[0] != core.TransportDoT {
		t.Errorf("transports after seeding = %v, want the signal's [DoT Do53]", got)
	}
}

func TestSetTransportsIfNone(t *testing.T) {
	s := NewAuthServer("ns.example.")
	s.SetTransportsIfNone([]core.Transport{core.TransportDoT})
	if got := s.GetTransports(); len(got) != 1 || got[0] != core.TransportDo53 {
		t.Errorf("a server with transports: got %v, want its own [Do53] kept", got)
	}
	s.SetTransports(nil)
	s.SetTransportsIfNone([]core.Transport{core.TransportDoT})
	if got := s.GetTransports(); len(got) != 1 || got[0] != core.TransportDoT {
		t.Errorf("a server with none: got %v, want [DoT]", got)
	}
}
