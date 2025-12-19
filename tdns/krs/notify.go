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
	"strings"
	"time"

	"github.com/miekg/dns"
)

// StartNotifyReceiver starts a minimal DNS server that only handles NOTIFYs
// Similar to tdns.NotifyReporter but adapted for KRS
func StartNotifyReceiver(ctx context.Context, krsDB *KrsDB, conf *KrsConf) error {
	addr := conf.DnsEngine.Addresses[0]
	if addr == "" {
		addr = ":53"
	}
	log.Printf("KRS: Starting NOTIFY receiver on %s", addr)
	log.Printf("KRS: DNS engine addresses: %v", conf.DnsEngine.Addresses)
	log.Printf("KRS: DNS engine transports: %v", conf.DnsEngine.Transports)

	// Set up a dedicated ServeMux to avoid global handlers
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		log.Printf("KRS: Received DNS message from %s", w.RemoteAddr())
		if r == nil {
			log.Printf("KRS: ERROR: Received nil message")
			return
		}
		log.Printf("KRS: Message ID: %d, Opcode: %s (%d), Question count: %d", 
			r.MsgHdr.Id, dns.OpcodeToString[r.Opcode], r.Opcode, len(r.Question))
		if r.Opcode != dns.OpcodeNotify {
			log.Printf("KRS: Rejecting non-NOTIFY message (opcode=%s)", dns.OpcodeToString[r.Opcode])
			// Optionally reply REFUSED, or silently drop. Here we refuse.
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeRefused)
			if err := w.WriteMsg(resp); err != nil {
				log.Printf("KRS: Error writing REFUSED response: %v", err)
			}
			return
		}

		// At this point we have a NOTIFY. Extract zone name from question section
		var notifyZone string
		if len(r.Question) > 0 {
			notifyZone = r.Question[0].Name
			log.Printf("KRS: Received NOTIFY for zone: %s (Qtype: %s)", notifyZone, dns.TypeToString[r.Question[0].Qtype])
		} else {
			log.Printf("KRS: Received NOTIFY with no question section")
			notifyZone = "<unknown>"
		}

		// TODO: Later we will verify SIG(0) signatures, but for now we accept unsigned NOTIFYs
		// Check for SIG(0) signature (for future use)
		if sig0 := r.IsEdns0(); sig0 != nil {
			log.Printf("KRS: NOTIFY has EDNS(0) options")
		}
		// Check for SIG RR in additional section (SIG(0))
		sigCount := 0
		for _, rr := range r.Extra {
			if rr.Header().Rrtype == dns.TypeSIG {
				sigCount++
			}
		}
		if sigCount > 0 {
			log.Printf("KRS: NOTIFY contains %d SIG(0) signature(s) (not yet validated)", sigCount)
		} else {
			log.Printf("KRS: NOTIFY has no SIG(0) signature (accepting unsigned NOTIFY for now)")
		}

		// At this point we have a NOTIFY. Minimal ACK:
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.MsgHdr.Authoritative = true

		// Check if this is a NOTIFY for the control zone or a distribution event
		// Format: <distributionID>.<controlzone> or just <controlzone>
		controlZoneFQDN := conf.ControlZone
		if !strings.HasSuffix(controlZoneFQDN, ".") {
			controlZoneFQDN += "."
		}

		if notifyZone == controlZoneFQDN {
			// NOTIFY for control zone - query KMCTRL (legacy flow)
			log.Printf("KRS: NOTIFY received for control zone %s, triggering KMCTRL query", notifyZone)
			
			// Query KMCTRL records asynchronously (don't block the NOTIFY response)
			go func() {
				kmctrlRecords, err := QueryKMCTRL(krsDB, conf)
				if err != nil {
					log.Printf("KRS: Error querying KMCTRL: %v", err)
					return
				}
				
				// Process KMCTRL records and trigger KMREQ queries for new keys
				if err := ProcessKMCTRL(krsDB, conf, kmctrlRecords); err != nil {
					log.Printf("KRS: Error processing KMCTRL records: %v", err)
				}
			}()
		} else if strings.HasSuffix(notifyZone, controlZoneFQDN) {
			// NOTIFY for distribution event: <distributionID>.<controlzone>
			// Extract distributionID
			suffixLen := len(controlZoneFQDN)
			prefix := notifyZone[:len(notifyZone)-suffixLen]
			if strings.HasSuffix(prefix, ".") {
				prefix = prefix[:len(prefix)-1]
			}
			
			// Get the last label (distributionID)
			labels := strings.Split(prefix, ".")
			distributionID := labels[len(labels)-1]
			
			log.Printf("KRS: NOTIFY received for distribution event %s (zone: %s)", distributionID, notifyZone)
			
			// Process distribution asynchronously
			go func() {
				if err := ProcessDistribution(krsDB, conf, distributionID, nil); err != nil {
					log.Printf("KRS: Error processing distribution %s: %v", distributionID, err)
				}
			}()
		} else {
			log.Printf("KRS: NOTIFY received for zone %s (not control zone %s), ignoring", notifyZone, controlZoneFQDN)
		}

		if err := w.WriteMsg(resp); err != nil {
			log.Printf("KRS: Error writing NOTIFY response: %v", err)
		} else {
			log.Printf("KRS: NOTIFY response sent successfully")
		}
	})

	log.Printf("KRS: Attempting to bind UDP listener on %s", addr)
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("KRS: ERROR: Failed to bind UDP listener: %v", err)
		return fmt.Errorf("failed to bind UDP notify listener on %s: %w", addr, err)
	}
	log.Printf("KRS: Successfully bound UDP listener on %s", addr)

	log.Printf("KRS: Attempting to bind TCP listener on %s", addr)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("KRS: ERROR: Failed to bind TCP listener: %v", err)
		_ = udpConn.Close()
		return fmt.Errorf("failed to bind TCP notify listener on %s: %w", addr, err)
	}
	log.Printf("KRS: Successfully bound TCP listener on %s", addr)

	udpSrv := &dns.Server{PacketConn: udpConn, Net: "udp", Handler: mux, Addr: addr}
	tcpSrv := &dns.Server{Listener: tcpListener, Net: "tcp", Handler: mux, Addr: addr}

	log.Printf("KRS: Starting UDP server goroutine")
	go func() {
		log.Printf("KRS: UDP server starting to serve on %s", addr)
		if serveErr := udpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("KRS notify-only UDP server stopped: %v", serveErr)
		}
	}()
	log.Printf("KRS: Starting TCP server goroutine")
	go func() {
		log.Printf("KRS: TCP server starting to serve on %s", addr)
		if serveErr := tcpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("KRS notify-only TCP server stopped: %v", serveErr)
		}
	}()
	log.Printf("KRS: NOTIFY receiver started successfully on %s", addr)

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown servers
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = udpSrv.ShutdownContext(shutdownCtx)
	_ = tcpSrv.ShutdownContext(shutdownCtx)

	return nil
}

