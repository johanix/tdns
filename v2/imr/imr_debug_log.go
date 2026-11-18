/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"log"
	"log/slog"
	"os"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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
func imrDebugLogger(lg *slog.Logger, logfile string) *log.Logger {
	imrDebugLogOnce.Do(func() {
		if logfile == "" {
			logfile = "/var/log/tdns/imr-debug.log"
		}
		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			lg.Error("failed to open IMR debug log file, debug logging disabled", "file", logfile, "err", err)
			return
		}
		dl := log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
		lg.Info("IMR debug logging enabled", "file", logfile)
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
