/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Per-zone transfer authentication — the downstream-auth mechanism ladder
 * (docs/2026-07-21-peers-xfr-auth-design.md §5/§6). Policy lives on the
 * zone (zd.DownstreamAuth: which proof classes are acceptable), credentials
 * live on the matched downstreams entries (prefix/key inline; tls-identity
 * via peers references). Enforcement happens at TRANSFER time, never at the
 * TLS handshake: the DoT listener merely REQUESTS a client certificate
 * (tls.RequestClientCert) and verifies nothing, so cert-less DoT query
 * clients and every non-TLS transport are unaffected.
 */
package imr

import (
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// caPoolCache memoizes parsed trust-anchor pools per ca-file, invalidated by
// the file's modification time — so a busy primary does not re-read and
// re-parse the same ca-file on every transfer-time PKIX verification.
var (
	caPoolMu    sync.Mutex
	caPoolCache = map[string]caPoolEntry{}
)

type caPoolEntry struct {
	modTime time.Time
	pool    *x509.CertPool
}

// LoadCAPool returns the trust-anchor pool for caFile, reusing a cached parse
// when the file is unchanged (by mtime) and re-parsing when it has been
// modified. Errors mirror the previous inline behavior.
func LoadCAPool(caFile string) (*x509.CertPool, error) {
	fi, err := os.Stat(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading ca-file: %v", err)
	}
	mt := fi.ModTime()

	caPoolMu.Lock()
	defer caPoolMu.Unlock()
	if e, ok := caPoolCache[caFile]; ok && e.modTime.Equal(mt) {
		return e.pool, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading ca-file: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no usable certificates in ca-file %s", caFile)
	}
	caPoolCache[caFile] = caPoolEntry{modTime: mt, pool: pool}
	return pool, nil
}
