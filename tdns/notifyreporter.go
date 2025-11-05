/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"net"

	"context"

	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// This is a minimal DNS server that only handles NOTIFYs. It is (only?) used in the tdns-reporter.

func NotifyReporter(conf *Config, tsigSecrets map[string]string) (stop func(context.Context) error, err error) {
	addr := viper.GetString("reporter.dns.listen")
	if addr == "" {
		addr = ":53"
	}

	// Set up a dedicated ServeMux to avoid global handlers
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if r == nil || r.Opcode != dns.OpcodeNotify {
			// Optionally reply REFUSED, or silently drop. Here we refuse.
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(resp)
			return
		}

		// At this point we have a NOTIFY. Minimal ACK:
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.MsgHdr.Authoritative = true

		var tsig *dns.TSIG

		if tsig = r.IsTsig(); tsig == nil {
			resp.SetRcode(r, dns.RcodeRefused)
			edns0.AttachEDEToResponse(resp, edns0.EDETsigRequired)
			_ = w.WriteMsg(resp)
			return
		}

		if err = w.TsigStatus(); err != nil {
			// TSIG validation failure
			resp.SetRcode(r, dns.RcodeNotAuth)
			edns0.AttachEDEToResponse(resp, edns0.EDETsigValidationFailure)
			_ = w.WriteMsg(resp)
			return
		}

		if edns0.HasReportOption(r.IsEdns0()) {
			ro, found := edns0.ExtractReportOption(r.IsEdns0())
			if found {
				edetxt, ok := edns0.EDEToString(ro.EDECode)
				if !ok {
					edetxt = fmt.Sprintf("Unknown EDE code: %d", ro.EDECode)
				}
				if ro.Details == "" {
					ro.Details = "No details provided"
				}
				fmt.Printf("NotifyReport: Zone: %s Sender: %s Error: %s (%d) Details: %s\n",
					ro.ZoneName, ro.Sender, edetxt, ro.EDECode, ro.Details)
			} else {
				fmt.Printf("NotifyReporter: Received a NOTIFY for %s (has EDNS(0) OPT RR, but no Report option found)\n", r.Question[0].Name)
				edns0.AttachEDEToResponse(resp, edns0.EDEReportOptionNotFound)
			}
		} else {
			fmt.Printf("NotifyReporter: Received a NOTIFY for %s (no EDNS(0) options at all)\n", r.Question[0].Name)
			edns0.AttachEDEToResponse(resp, edns0.EDEReportOptionNotFound)
		}
		_ = w.WriteMsg(resp)
	})

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP notify listener on %s: %w", addr, err)
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("failed to bind TCP notify listener on %s: %w", addr, err)
	}

	udpSrv := &dns.Server{PacketConn: udpConn, Net: "udp", Handler: mux, Addr: addr, TsigSecret: tsigSecrets}
	tcpSrv := &dns.Server{Listener: tcpListener, Net: "tcp", Handler: mux, Addr: addr, TsigSecret: tsigSecrets}

	go func() {
		if serveErr := udpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("notify-only UDP server stopped: %v", serveErr)
		}
	}()
	go func() {
		if serveErr := tcpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("notify-only TCP server stopped: %v", serveErr)
		}
	}()

	// Return a unified stopper
	return func(ctx context.Context) error {
		_ = udpSrv.ShutdownContext(ctx)
		_ = tcpSrv.ShutdownContext(ctx)
		return nil
	}, nil
}
