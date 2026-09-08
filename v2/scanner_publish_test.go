/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"
)

// TestAPublishedScannerIsAlwaysFullyInitialised.
//
// ScannerEngine runs on its own goroutine; API handlers, the UPDATE responder
// and the DSYNC API all read the same pointer from theirs. The engine used to
// store the Scanner and THEN assign scanner.conf, so a request arriving in that
// window got a Scanner whose conf was still nil -- and scanner.imr() reads conf
// to resolve the IMR, so the delegation-coherence check would quietly find no
// resolver and refuse as unverifiable.
//
// Run under -race: the unsynchronised write to a published object is the half
// that no assertion can catch on its own.
func TestAPublishedScannerIsAlwaysFullyInitialised(t *testing.T) {
	conf := &Config{}
	conf.Internal.ScannerQ = make(chan ScanRequest, 1)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 1)
	conf.Internal.ImrReady = NewImrReadiness()

	if s := conf.Internal.GetScanner(); s != nil {
		t.Fatalf("a fresh Config already has a scanner: %p", s)
	}

	ctx, cancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- ScannerEngine(ctx, conf) }()

	observed := make(chan *Scanner, 1)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if s := conf.Internal.GetScanner(); s != nil {
				// Read through the pointer the same way a handler would.
				_ = s.imr()
				if s.conf == nil {
					observed <- s
				}
				return
			}
		}
	}()

	<-watchDone
	cancel()
	<-engineDone

	select {
	case s := <-observed:
		t.Errorf("observed a published Scanner (%p) whose conf was still nil; a request"+
			" arriving in that window resolves no IMR", s)
	default:
	}

	s := conf.Internal.GetScanner()
	if s == nil {
		t.Fatal("ScannerEngine never published a scanner")
	}
	if s.conf == nil {
		t.Error("the published scanner has no conf; scanner.imr() can only return nil")
	}
}

// Nothing may assume the scanner is up: the engines start concurrently, so an
// early UPDATE genuinely can arrive first. The coherence check's asker is built
// from it, and a nil scanner has to yield a nil asker rather than a panic.
func TestTheCoherenceAskerToleratesAnUnpublishedScanner(t *testing.T) {
	conf := &Config{}
	if conf.Internal.GetScanner() != nil {
		t.Fatal("a fresh Config reports a scanner")
	}
	if conf.Internal.GetScanner().childNameserverAsker(nil) != nil {
		t.Error("an unpublished scanner produced an asker; the coherence check must" +
			" refuse as unverifiable rather than guess")
	}
}
