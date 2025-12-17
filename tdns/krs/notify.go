/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * NOTIFY receiver for tdns-krs
 */

package krs

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
)

// StartNotifyReceiver starts a minimal DNS server that only handles NOTIFYs
// Similar to tdns.NotifyReporter but adapted for KRS
func StartNotifyReceiver(ctx context.Context, krsDB *KrsDB, conf *KrsConf) error {
	addr := conf.DnsEngine.Addresses[0]
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

		if err := w.TsigStatus(); err != nil {
			// TSIG validation failure
			resp.SetRcode(r, dns.RcodeNotAuth)
			edns0.AttachEDEToResponse(resp, edns0.EDETsigValidationFailure)
			_ = w.WriteMsg(resp)
			return
		}

		// Handle NOTIFY for control zone
		qname := r.Question[0].Name
		log.Printf("KRS: Received NOTIFY for %s", qname)

		// TODO: Check if this is a NOTIFY for the control zone
		// If so, trigger a KMCTRL query to check for new keys
		// For now, just log it
		log.Printf("KRS: NOTIFY received for zone %s (control zone: %s)", qname, conf.ControlZone)

		_ = w.WriteMsg(resp)
	})

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP notify listener on %s: %w", addr, err)
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("failed to bind TCP notify listener on %s: %w", addr, err)
	}

	udpSrv := &dns.Server{PacketConn: udpConn, Net: "udp", Handler: mux, Addr: addr}
	tcpSrv := &dns.Server{Listener: tcpListener, Net: "tcp", Handler: mux, Addr: addr}

	go func() {
		if serveErr := udpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("KRS notify-only UDP server stopped: %v", serveErr)
		}
	}()
	go func() {
		if serveErr := tcpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("KRS notify-only TCP server stopped: %v", serveErr)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown servers
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = udpSrv.ShutdownContext(shutdownCtx)
	_ = tcpSrv.ShutdownContext(shutdownCtx)

	return nil
}

