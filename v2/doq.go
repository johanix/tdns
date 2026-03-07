/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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
		ports = []string{"853"}
	}
	var listeners []*quic.Listener
	for _, addr := range doqaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port) // At the moment, we only support port 853
			lgDns.Info("DnsEngine: serving on DoQ", "hostport", hostport)
			listener, err := quic.ListenAddr(hostport, tlsConfig, &quic.Config{
				MaxIdleTimeout:  time.Duration(30) * time.Second,
				KeepAlivePeriod: time.Duration(15) * time.Second,
			})
			if err != nil {
				lgDns.Error("failed to setup DoQ listener", "hostport", hostport, "err", err)
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
						lgDns.Error("failed to accept QUIC connection", "hostport", hp, "err", err)
						continue
					}
					go handleDoQConnection(ctx, conn, ourDNSHandler)
				}
			}(listener, hostport)
		}
	}
	go func() {
		<-ctx.Done()
		lgDns.Info("DnsDoQEngine: shutting down DoQ listeners")
		for _, l := range listeners {
			if err := l.Close(); err != nil {
				lgDns.Warn("DnsDoQEngine: error closing DoQ listener", "err", err)
			}
		}
	}()
	return nil
}

func handleDoQConnection(ctx context.Context, conn *quic.Conn, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	defer conn.CloseWithError(0, "") // ensure clean connection closure

	for {
		lgDns.Debug("DoQ: waiting for stream on connection", "remote", conn.RemoteAddr())
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Log all errors, but with different levels of detail
			if err.Error() == "Application error 0x0 (remote)" {
				lgDns.Debug("DoQ: client closed connection", "remote", conn.RemoteAddr(), "err", err)
			} else {
				lgDns.Error("DoQ: failed to accept stream", "err", err)
			}
			return
		}

		lgDns.Debug("DoQ: accepted stream", "stream", stream.StreamID(), "remote", conn.RemoteAddr())
		go handleDoQStream(ctx, stream, conn, dnsHandler)
	}
}

func handleDoQStream(ctx context.Context, stream *quic.Stream, conn *quic.Conn, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	lgDns.Debug("DoQ: handling stream", "stream", stream.StreamID(), "remote", conn.RemoteAddr())

	// Read the DNS message length (2 bytes)
	lenBuf := make([]byte, 2)
	if err := readExactWithContext(ctx, stream, lenBuf); err != nil {
		if ctx.Err() != nil {
			// graceful cancellation
			_ = stream.Close()
			return
		}
		lgDns.Error("DoQ: failed to read message length", "err", err)
		if err := stream.Close(); err != nil {
			lgDns.Warn("DoQ: error closing stream", "err", err)
		}
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	if msgLen == 0 {
		lgDns.Warn("DoQ: received zero-length DNS message", "remote", conn.RemoteAddr())
		if err := stream.Close(); err != nil {
			lgDns.Warn("DoQ: error closing stream", "err", err)
		}
		return
	}

	// Read the DNS message
	msgBuf := make([]byte, msgLen)
	if err := readExactWithContext(ctx, stream, msgBuf); err != nil {
		if ctx.Err() != nil {
			_ = stream.Close()
			return
		}
		lgDns.Error("DoQ: failed to read DNS message", "err", err)
		if err := stream.Close(); err != nil {
			lgDns.Warn("DoQ: error closing stream", "err", err)
		}
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		lgDns.Error("DoQ: failed to unpack DNS message", "err", err)
		if err := stream.Close(); err != nil {
			lgDns.Warn("DoQ: error closing stream", "err", err)
		}
		return
	}

	if len(msg.Question) == 0 {
		lgDns.Warn("DoQ: received message with no question section", "remote", conn.RemoteAddr())
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeFormatError)
		rw := &doqResponseWriter{stream: stream, conn: conn}
		rw.WriteMsg(resp)
		return
	}

	// Create a response writer for DoQ with both stream and connection
	rw := &doqResponseWriter{stream: stream, conn: conn}

	lgDns.Debug("DoQ: received message", "opcode", dns.OpcodeToString[msg.Opcode], "qname", msg.Question[0].Name, "rrtype", dns.TypeToString[msg.Question[0].Qtype])

	// Handle the DNS message
	dnsHandler(rw, msg)

	lgDns.Debug("DoQ: finished handling stream", "stream", stream.StreamID(), "remote", conn.RemoteAddr())
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

	lgDns.Debug("DoQ: writing response on stream", "stream", w.stream.StreamID())

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
	if err := w.stream.Close(); err != nil {
		lgDns.Warn("DoQ: error closing stream after write", "err", err)
	}

	lgDns.Debug("DoQ: finished writing response on stream", "stream", w.stream.StreamID())
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
