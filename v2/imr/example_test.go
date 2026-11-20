/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/johanix/tdns/v2/imr"
	"github.com/miekg/dns"
)

// An application runs the resolver in its own process. It has no Output
// comment, so go test compiles it and does not run it: it needs the network.
func Example() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The resolver logs through the logger it is given. Per-query lines are
	// at Debug, so at Info it logs only what happens once or rarely.
	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// imr.New sends nothing, and fails only on the configuration. The zero
	// Config resolves from the root, validating with the IANA root anchor.
	r, err := imr.New(ctx, imr.Config{}, imr.Options{Logger: lg})
	if err != nil {
		fmt.Println("imr.New:", err)
		return
	}

	// Start primes the root in the background, retrying until that works,
	// and keeps the resolver going until ctx ends.
	r.Start(ctx)

	// WaitReady waits for the priming, and says at once if the resolver
	// stopped first. Ready is a channel for a select, closed once it is ready.
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := r.WaitReady(wctx); err != nil {
		fmt.Println("not ready:", err)
		return
	}

	resp, err := r.Query(ctx, "www.iana.org.", dns.TypeA, dns.ClassINET)
	if err != nil {
		fmt.Println("Query:", err)
		return
	}
	if resp.RRset != nil {
		for _, rr := range resp.RRset.RRs {
			fmt.Println(rr)
		}
	}
	fmt.Println("validated:", resp.Validated)
}
