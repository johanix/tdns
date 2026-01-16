/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/spf13/viper"
)

func DnsDoQEngine(ctx context.Context, conf *Config, doqaddrs []string, cert *tls.Certificate,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"doq"},
	}
	tlsConfig.Certificates = []tls.Certificate{*cert}

	ports := viper.GetStringSlice("dnsengine.ports.doq")
	if len(ports) == 0 {
		ports = []string{"8853"}
	}
	var listeners []*quic.Listener
	for _, addr := range doqaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port) // At the moment, we only support port 8853
			log.Printf("DnsEngine: serving on %s (DoQ)\n", hostport)
			listener, err := quic.ListenAddr(hostport, tlsConfig, &quic.Config{
				MaxIdleTimeout:  time.Duration(30) * time.Second,
				KeepAlivePeriod: time.Duration(15) * time.Second,
			})
			if err != nil {
				log.Printf("Failed to setup the DoQ listener on %s: %s", hostport, err.Error())
				continue
			}
			listeners = append(listeners, listener)

			go func(l *quic.Listener, hp string) {
				for {
					conn, err := l.Accept(ctx)
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						log.Printf("Failed to accept QUIC connection on %s: %s", hp, err.Error())
						continue
					}
					go handleDoQConnection(ctx, conn, ourDNSHandler)
				}
			}(listener, hostport)
		}
	}
	go func() {
		<-ctx.Done()
		log.Printf("DnsDoQEngine: shutting down DoQ listeners...")
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	return nil
}

func handleDoQConnection(ctx context.Context, conn *quic.Conn, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	defer conn.CloseWithError(0, "") // ensure clean connection closure

	for {
		if Globals.Debug {
			log.Printf("DoQ: waiting for stream on connection from %v", conn.RemoteAddr())
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Log all errors, but with different levels of detail
			if err.Error() == "Application error 0x0 (remote)" {
				if Globals.Debug {
					log.Printf("DoQ: client %v closed connection: %v", conn.RemoteAddr(), err)
				}
			} else {
				log.Printf("DoQ: failed to accept stream: %v", err)
			}
			return
		}

		if Globals.Debug {
			log.Printf("DoQ: accepted stream %v from %v", stream.StreamID(), conn.RemoteAddr())
		}
		go handleDoQStream(ctx, stream, conn, dnsHandler)
	}
}

func handleDoQStream(ctx context.Context, stream *quic.Stream, conn *quic.Conn, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	if Globals.Debug {
		log.Printf("DoQ: handling stream %v from %v", stream.StreamID(), conn.RemoteAddr())
	}

	// Read the DNS message length (2 bytes)
	lenBuf := make([]byte, 2)
	if err := readExactWithContext(ctx, stream, lenBuf); err != nil {
		if ctx.Err() != nil {
			// graceful cancellation
			_ = stream.Close()
			return
		}
		log.Printf("Failed to read message length: %s", err.Error())
		stream.Close()
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)

	// Read the DNS message
	msgBuf := make([]byte, msgLen)
	if err := readExactWithContext(ctx, stream, msgBuf); err != nil {
		if ctx.Err() != nil {
			_ = stream.Close()
			return
		}
		log.Printf("Failed to read DNS message: %s", err.Error())
		stream.Close()
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		log.Printf("Failed to unpack DNS message: %s", err.Error())
		stream.Close()
		return
	}

	// Create a response writer for DoQ with both stream and connection
	rw := &doqResponseWriter{stream: stream, conn: conn}

	if Globals.Debug {
		log.Printf("*** DoQ received message opcode: %s qname: %s rrtype: %s", dns.OpcodeToString[msg.Opcode], msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
	}

	// Handle the DNS message
	dnsHandler(rw, msg)

	if Globals.Debug {
		log.Printf("DoQ: finished handling stream %v from %v", stream.StreamID(), conn.RemoteAddr())
	}
}

// readExactWithContext reads exactly len(buf) bytes from the stream,
// periodically setting a short read deadline to allow checking ctx.Done().
func readExactWithContext(ctx context.Context, s *quic.Stream, buf []byte) error {
	const sliceReadDeadline = 200 * time.Millisecond
	defer func() {
		// clear any deadline
		_ = s.SetReadDeadline(time.Time{})
	}()
	total := 0
	for total < len(buf) {
		// set a short read deadline to avoid blocking indefinitely
		_ = s.SetReadDeadline(time.Now().Add(sliceReadDeadline))
		n, err := s.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			// handle deadline expiry to check ctx.Done()
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					// continue reading
					continue
				}
			}
			return err
		}
		// If no bytes and no error (shouldn't happen with SetReadDeadline), loop again
	}
	return nil
}

// DoQ Response Writer implementation
type doqResponseWriter struct {
	stream *quic.Stream
	conn   *quic.Conn
	wrote  bool // Add this field to track if we've written
}

func (w *doqResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.wrote {
		return fmt.Errorf("response already written")
	}
	w.wrote = true

	if Globals.Debug {
		log.Printf("DoQ: writing response on stream %v", w.stream.StreamID())
	}

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	// Write length prefix
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := w.stream.Write(lenBuf); err != nil {
		return err
	}

	// Write DNS message
	if _, err = w.stream.Write(packed); err != nil {
		return err
	}

	// Just signal that we're done writing
	w.stream.Close()

	if Globals.Debug {
		log.Printf("DoQ: finished writing response on stream %v", w.stream.StreamID())
	}
	return nil
}

func (w *doqResponseWriter) Close() error              { return w.stream.Close() }
func (w *doqResponseWriter) TsigStatus() error         { return nil }
func (w *doqResponseWriter) TsigTimersOnly(bool)       {}
func (w *doqResponseWriter) Hijack()                   {}
func (w *doqResponseWriter) LocalAddr() net.Addr       { return w.conn.LocalAddr() }
func (w *doqResponseWriter) RemoteAddr() net.Addr      { return w.conn.RemoteAddr() }
func (w *doqResponseWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("not implemented") }
func (w *doqResponseWriter) WriteMsgWithTsig(*dns.Msg, string, bool) error {
	return fmt.Errorf("not implemented")
}
