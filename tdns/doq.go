/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/spf13/viper"
)

func DnsDoQEngine(conf *Config, doqaddrs []string,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {
	certFile := viper.GetString("dnsengine.doq.certfile")
	keyFile := viper.GetString("dnsengine.doq.keyfile")

	if certFile == "" || keyFile == "" {
		log.Println("DnsDoQEngine: no certificate file or key file provided. Not starting.")
		return fmt.Errorf("no certificate file or key file provided")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("DnsDoQEngine: certificate file %q does not exist. Not starting.", certFile)
		return fmt.Errorf("certificate file %q does not exist", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("DnsDoQEngine: key file %q does not exist. Not starting.", keyFile)
		return fmt.Errorf("key file %q does not exist", keyFile)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"doq"},
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	for _, addr := range doqaddrs {
		go func(addr string) {
			log.Printf("DnsEngine: serving on %s (DoQ)\n", addr)
			listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
				MaxIdleTimeout:  time.Duration(30) * time.Second,
				KeepAlivePeriod: time.Duration(15) * time.Second,
			})
			if err != nil {
				log.Printf("Failed to setup the DoQ listener: %s", err.Error())
				return
			}

			for {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					log.Printf("Failed to accept QUIC connection: %s", err.Error())
					continue
				}

				go handleDoQConnection(conn, ourDNSHandler)
			}
		}(addr)
	}
	return nil
}

func handleDoQConnection(conn quic.Connection, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Failed to accept QUIC stream: %s", err.Error())
			return
		}

		go handleDoQStream(stream, conn, dnsHandler)
	}
}

func handleDoQStream(stream quic.Stream, conn quic.Connection, dnsHandler func(w dns.ResponseWriter, r *dns.Msg)) {
	defer stream.Close()

	// Read the DNS message length (2 bytes)
	lenBuf := make([]byte, 2)
	_, err := io.ReadFull(stream, lenBuf)
	if err != nil {
		log.Printf("Failed to read message length: %s", err.Error())
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)

	// Read the DNS message
	msgBuf := make([]byte, msgLen)
	_, err = io.ReadFull(stream, msgBuf)
	if err != nil {
		log.Printf("Failed to read DNS message: %s", err.Error())
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		log.Printf("Failed to unpack DNS message: %s", err.Error())
		return
	}

	// Create a response writer for DoQ with both stream and connection
	rw := &doqResponseWriter{
		stream: stream,
		conn:   conn,
	}

	// Handle the DNS message
	dnsHandler(rw, msg)
}

// DoQ Response Writer implementation
type doqResponseWriter struct {
	stream quic.Stream
	conn   quic.Connection
}

func (w *doqResponseWriter) WriteMsg(m *dns.Msg) error {
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
	_, err = w.stream.Write(packed)
	return err
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
