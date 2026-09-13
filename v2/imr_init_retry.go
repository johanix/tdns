/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Priming needs an answer from a root server, and a daemon starts at the moment
// it is least likely to get one: every resolver on the network priming at once,
// or the root server on the same host not up yet. A failed InitImrEngine used to
// end the ImrEngine goroutine for good. The process stayed up with no resolver,
// the DelegationSyncher waited for it forever, and every DS change a parent had
// to check was refused as unverifiable -- one root timeout at boot cost a
// restart.

const (
	imrInitFirstRetry = 5 * time.Second
	imrInitMaxRetry   = 2 * time.Minute
)

// imrInitRetryDelay is the wait before init attempt attempt+2: 5s, doubling,
// capped at two minutes.
func imrInitRetryDelay(attempt int) time.Duration {
	d := imrInitFirstRetry
	for i := 0; i < attempt && d < imrInitMaxRetry; i++ {
		d *= 2
	}
	if d > imrInitMaxRetry {
		d = imrInitMaxRetry
	}
	return d
}

// initImrEngineRetrying runs init until it succeeds or ctx is done. While it
// keeps failing, `config status` shows DEGRADED with the latest reason; the
// entry is cleared once the resolver is up. Returns nil on success, and the last
// init error if ctx ends first.
func (conf *Config) initImrEngineRetrying(ctx context.Context, init func() error, delay func(attempt int) time.Duration) error {
	for attempt := 0; ; attempt++ {
		err := init()
		if err == nil {
			if attempt > 0 {
				conf.Internal.ServerErrors.ClearImrPrimingError()
				lgImr.Info("IMR started after failed attempts", "attempts", attempt+1)
			}
			return nil
		}
		wait := delay(attempt)
		conf.Internal.ServerErrors.SetImrPrimingError(
			fmt.Sprintf("IMR did not start (no DNS listeners), retrying in %s: %v", wait, err))
		lgImr.Warn("InitImrEngine failed; will retry", "attempt", attempt+1, "retry-in", wait, "err", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
}

// The IMR debug log and the two hooks that write to it are process-wide, and
// set up once. InitImrEngine runs again after a failed priming, and each run
// used to open the file again and append another pair of hooks, so every query
// would have been logged once for each failed start.
var (
	imrDebugLogOnce sync.Once
	imrDebugLog     *log.Logger
)

// imrDebugLogger returns the IMR debug logger, opening logfile and registering
// the hooks on first use. Nil if the file cannot be opened.
func imrDebugLogger(logfile string) *log.Logger {
	imrDebugLogOnce.Do(func() {
		if logfile == "" {
			logfile = "/var/log/tdns/imr-debug.log"
		}
		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			lgImr.Error("failed to open IMR debug log file, debug logging disabled", "file", logfile, "err", err)
			return
		}
		dl := log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
		lgImr.Info("IMR debug logging enabled", "file", logfile)
		RegisterImrOutboundQueryHook(func(ctx context.Context, qname string, qtype uint16, serverName, serverAddr string, transport core.Transport) error {
			dl.Printf("OUTBOUND qname=%s qtype=%s server=%s addr=%s transport=%s",
				qname, dns.TypeToString[qtype], serverName, serverAddr, core.TransportToString[transport])
			return nil
		})
		RegisterImrResponseHook(func(ctx context.Context, qname string, qtype uint16, serverName, serverAddr string, transport core.Transport, response *dns.Msg, rcode int) {
			var ans []string
			if response != nil {
				for _, rr := range response.Answer {
					ans = append(ans, rr.String())
				}
			}
			dl.Printf("RESPONSE qname=%s qtype=%s server=%s addr=%s transport=%s rcode=%s answer=%v",
				qname, dns.TypeToString[qtype], serverName, serverAddr,
				core.TransportToString[transport], dns.RcodeToString[rcode], ans)
		})
		imrDebugLog = dl
	})
	return imrDebugLog
}
