/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

// mintTestCA returns a pathlen-0 CA and the PEM path the pkix verifier reads.
func mintTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dsync-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := writeCertPEM(path, ca.Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return ca, key, path
}

func mintTestClientLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string, cn string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	if cn == "" {
		cn = "dsync-client"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, parsed
}

func registerDsyncApiParent(t *testing.T, zone string) {
	t.Helper()
	zd := &ZoneData{
		ZoneName: zone,
		Options: map[ZoneOption]bool{
			OptChildSync:         true,
			OptAllowChildUpdates: true,
		},
	}
	Zones.Set(zone, zd)
	t.Cleanup(func() { Zones.Remove(zone) })
}

func setDsyncApiClientAuth(t *testing.T, ca *DsyncApiClientAuthConf) {
	t.Helper()
	prev := DelegationSyncConfig()
	next := *prev
	next.ChildSync.Api.ClientAuth = ca
	SetDelegationSyncConfig(next)
	t.Cleanup(func() { SetDelegationSyncConfig(*prev) })
}

func dsyncApiCertAuthServer(t *testing.T, kdb *KeyDB, requestCert bool) *httptest.Server {
	t.Helper()
	rtr := mux.NewRouter().StrictSlash(true)
	sr := rtr.PathPrefix(DsyncApiPathPrefix).Subrouter()
	sr.Use(dsyncApiAuthMiddleware(kdb))
	sr.HandleFunc("/delegation/{child}", func(w http.ResponseWriter, r *http.Request) {
		cred := dsyncApiCredentialFrom(r)
		fmt.Fprintf(w, "%s %s", cred.AuthMethod, cred.Principal)
	}).Methods("GET")

	srv := httptest.NewUnstartedServer(rtr)
	if srv.TLS == nil {
		srv.TLS = &tls.Config{}
	}
	if requestCert {
		srv.TLS.ClientAuth = tls.RequestClientCert
		srv.TLS.MinVersion = tls.VersionTLS12
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func dsyncApiAuthClient(t *testing.T, srv *httptest.Server, clientCert *tls.Certificate) *http.Client {
	t.Helper()
	c := srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	if clientCert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*clientCert}
	}
	c.Transport = tr
	return c
}

func dsyncApiGet(t *testing.T, client *http.Client, srv *httptest.Server, child string, mutate func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+DsyncApiPathPrefix+"/delegation/"+child, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func readAuthBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func TestDsyncApiCertAuth_Additivity(t *testing.T) {
	registerDsyncApiParent(t, "example.")
	kdb := newTestKeyDB(t)
	key, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{})
	if err != nil {
		t.Fatalf("add bearer: %v", err)
	}

	ca, caKey, caFile := mintTestCA(t)
	clientCert, leaf := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "other-cn")
	if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPin, SPKISHA256(leaf), "child1.example.", "", time.Time{}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	t.Run("1 bearer with client-auth unset", func(t *testing.T) {
		setDsyncApiClientAuth(t, nil)
		srv := dsyncApiCertAuthServer(t, kdb, false)
		client := dsyncApiAuthClient(t, srv, nil)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.SetBasicAuth("child1.example.", key)
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if !strings.Contains(body, DsyncApiAuthBasic) {
			t.Errorf("body = %q, want basic", body)
		}
	})

	t.Run("2 bearer with client-auth set and no cert", func(t *testing.T) {
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin, DsyncApiAuthTLSPkix},
			CAFile:     caFile,
		})
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, nil)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.SetBasicAuth("child1.example.", key)
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("4 unrelated cert plus valid Basic", func(t *testing.T) {
		rogue, _ := mintTestClientLeaf(t, ca, caKey, []string{"rogue.example"}, "")
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
			CAFile:     caFile,
		})
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &rogue)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.SetBasicAuth("child1.example.", key)
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if !strings.Contains(body, DsyncApiAuthBasic) {
			t.Errorf("body = %q, want basic (certificate ignored)", body)
		}
	})

	t.Run("5 wrong password plus valid cert is 401", func(t *testing.T) {
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
			CAFile:     caFile,
		})
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.SetBasicAuth("child1.example.", key+"x")
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d body %q, want 401", resp.StatusCode, body)
		}
		if body != "" {
			t.Errorf("401 body %q, want empty", body)
		}
	})

	t.Run("6 Bearer header plus valid cert is 401", func(t *testing.T) {
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
			CAFile:     caFile,
		})
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer not-basic")
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d body %q, want 401", resp.StatusCode, body)
		}
		if body != "" {
			t.Errorf("401 body %q, want empty", body)
		}
	})

	t.Run("empty Authorization header plus valid cert is 401", func(t *testing.T) {
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
			CAFile:     caFile,
		})
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", func(r *http.Request) {
			r.Header.Set("Authorization", "")
		})
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d body %q, want 401", resp.StatusCode, body)
		}
		if body != "" {
			t.Errorf("401 body %q, want empty", body)
		}
	})
}

func TestDsyncApiCertAuth_PinAndPkix(t *testing.T) {
	registerDsyncApiParent(t, "example.")
	kdb := newTestKeyDB(t)
	ca, caKey, caFile := mintTestCA(t)
	clientCert, leaf := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "cn-ignored")
	setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
		Mechanisms: []string{DsyncApiAuthTLSPin, DsyncApiAuthTLSPkix},
		CAFile:     caFile,
	})

	t.Run("tls-pin", func(t *testing.T) {
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPin, SPKISHA256(leaf), "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if body != DsyncApiAuthTLSPin+" child1.example." {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("tls-pkix", func(t *testing.T) {
		kdb2 := newTestKeyDB(t)
		if err := kdb2.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb2, true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if body != DsyncApiAuthTLSPkix+" child1.example." {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("unknown identity is empty 401", func(t *testing.T) {
		srv := dsyncApiCertAuthServer(t, newTestKeyDB(t), true)
		client := dsyncApiAuthClient(t, srv, &clientCert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || body != "" {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
	})
}

func TestDsyncApiCertAuth_IdentityResolution(t *testing.T) {
	registerDsyncApiParent(t, "example.")
	ca, caKey, caFile := mintTestCA(t)
	setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
		Mechanisms: []string{DsyncApiAuthTLSPkix},
		CAFile:     caFile,
	})

	t.Run("two SANs both provisioned: first in DNSNames wins", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		cert, _ := mintTestClientLeaf(t, ca, caKey, []string{"first.example", "second.example"}, "cn")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "first.example.", "first.example.", "", time.Time{}); err != nil {
			t.Fatalf("add first: %v", err)
		}
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "second.example.", "second.example.", "", time.Time{}); err != nil {
			t.Fatalf("add second: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if body != DsyncApiAuthTLSPkix+" first.example." {
			t.Errorf("body = %q, want first SAN", body)
		}
	})

	t.Run("two SANs, row for the second only", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		cert, _ := mintTestClientLeaf(t, ca, caKey, []string{"first.example", "second.example"}, "cn")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "second.example.", "second.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if body != DsyncApiAuthTLSPkix+" second.example." {
			t.Errorf("body = %q, want second SAN", body)
		}
	})

	t.Run("CN names a provisioned identity, SANs do not: 401", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		cert, _ := mintTestClientLeaf(t, ca, caKey, []string{"other.example"}, "child1.example.")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || body != "" {
			t.Fatalf("CN lookup must not authenticate: status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("SAN matches a row but chain fails: continue, then 401", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		otherCA, otherKey, _ := mintTestCA(t)
		cert, _ := mintTestClientLeaf(t, otherCA, otherKey, []string{"child1.example"}, "cn")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || body != "" {
			t.Fatalf("failed chain authenticated: status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("disabled tls-pin does not block a live tls-pkix row", func(t *testing.T) {
		setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin, DsyncApiAuthTLSPkix},
			CAFile:     caFile,
		})
		kdb := newTestKeyDB(t)
		cert, leaf := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "cn")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPin, SPKISHA256(leaf), "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add pin: %v", err)
		}
		if _, err := kdb.SetDsyncApiCertCredentialDisabled("example.", DsyncApiAuthTLSPin, SPKISHA256(leaf), true); err != nil {
			t.Fatalf("disable pin: %v", err)
		}
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add pkix: %v", err)
		}
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("disabled pin blocked pkix: status %d body %q", resp.StatusCode, body)
		}
		if body != DsyncApiAuthTLSPkix+" child1.example." {
			t.Errorf("body = %q, want tls-pkix", body)
		}
	})
}

func TestDsyncApiCertAuth_DisabledExpiredIndistinguishable(t *testing.T) {
	registerDsyncApiParent(t, "example.")
	ca, caKey, caFile := mintTestCA(t)
	setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
		Mechanisms: []string{DsyncApiAuthTLSPkix},
		CAFile:     caFile,
	})
	cert, _ := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "cn")

	assertEmpty401 := func(t *testing.T, kdb *KeyDB) {
		t.Helper()
		srv := dsyncApiCertAuthServer(t, kdb, true)
		client := dsyncApiAuthClient(t, srv, &cert)
		resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
		body := readAuthBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || body != "" {
			t.Fatalf("status %d body %q, want empty 401", resp.StatusCode, body)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("certificate-path 401 must still send WWW-Authenticate: Basic")
		}
	}

	t.Run("disabled", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, err := kdb.SetDsyncApiCertCredentialDisabled("example.", DsyncApiAuthTLSPkix, "child1.example.", true); err != nil {
			t.Fatalf("disable: %v", err)
		}
		assertEmpty401(t, kdb)
	})

	t.Run("expired", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix, "child1.example.", "", "", time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("add: %v", err)
		}
		assertEmpty401(t, kdb)
	})
}

func TestDsyncApiCertAuth_PolicySameAsBearer(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	policy := policyDetail("selfsub", dns.TypeNS, dns.TypeDS)
	actions := []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "child1.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.child1.example."},
	}
	ok, _ := zd.ApproveActionsForPrincipal(policy, "child1.example.", actions, "dsync-api update")
	if !ok {
		t.Fatal("selfsub must allow the child's own NS")
	}
	if ok, _ := zd.ApproveActionsForPrincipal(policy, "child2.example.", actions, "dsync-api update"); ok {
		t.Fatal("a different principal must not change child1")
	}
}

func TestDsyncApiListenerClientAuthHandshake(t *testing.T) {
	rootsFromConf := func(t *testing.T, conf *Config) *x509.CertPool {
		t.Helper()
		pemBytes, err := os.ReadFile(conf.DelegationSync.ChildSync.Api.CertFile)
		if err != nil {
			t.Fatalf("read server cert: %v", err)
		}
		block, _ := pem.Decode(pemBytes)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse server cert: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return pool
	}

	handshake := func(t *testing.T, addr string, roots *x509.CertPool) (requested bool, err error) {
		t.Helper()
		var last error
		for i := 0; i < 50; i++ {
			var saw bool
			var conn *tls.Conn
			conn, last = tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", addr, &tls.Config{
				RootCAs:    roots,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					saw = true
					return new(tls.Certificate), nil
				},
			})
			if last == nil {
				conn.Close()
				return saw, nil
			}
			if !strings.Contains(last.Error(), "connection refused") {
				return saw, last
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false, last
	}

	// startListener runs StartDsyncApiListener and waits for it to return after
	// the subtest, matching TestDsyncApiListenerBlocksUntilShutdown. Cancel is
	// enough; the stop channel is only there because the signature requires it.
	startListener := func(t *testing.T, conf *Config, router *mux.Router) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		stop := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- conf.StartDsyncApiListener(ctx, router, stop) }()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("listener: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("StartDsyncApiListener did not return")
			}
		})
	}

	t.Run("7 client-auth unset sends no CertificateRequest", func(t *testing.T) {
		conf, router, ok := dsyncApiTestListener(t)
		if !ok {
			t.Skip("no test certificate available")
		}
		startListener(t, conf, router)

		addr := conf.DelegationSync.ChildSync.Api.Listen[0]
		requested, err := handshake(t, addr, rootsFromConf(t, conf))
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if requested {
			t.Fatal("unconfigured listener sent a CertificateRequest")
		}
	})

	t.Run("3 certless client completes handshake when certificates are requested", func(t *testing.T) {
		conf, router, ok := dsyncApiTestListener(t)
		if !ok {
			t.Skip("no test certificate available")
		}
		conf.DelegationSync.ChildSync.Api.ClientAuth = &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
		}
		SetDelegationSyncConfig(conf.DelegationSync)

		startListener(t, conf, router)

		addr := conf.DelegationSync.ChildSync.Api.Listen[0]
		requested, err := handshake(t, addr, rootsFromConf(t, conf))
		if err != nil {
			t.Fatalf("certless handshake failed: %v", err)
		}
		if !requested {
			t.Fatal("configured listener did not send a CertificateRequest")
		}
	})
}

func TestDsyncApiClientAuthReloadWarnsWhenHandshakeDisagrees(t *testing.T) {
	prevUp := dsyncApiListenerUp.Load()
	prevReq := dsyncApiListenerHandshakeRequestsCert.Load()
	t.Cleanup(func() {
		dsyncApiListenerUp.Store(prevUp)
		dsyncApiListenerHandshakeRequestsCert.Store(prevReq)
	})

	dsyncApiListenerUp.Store(false)
	dsyncApiListenerHandshakeRequestsCert.Store(false)
	if dsyncApiClientAuthReloadMismatch(true) {
		t.Fatal("no running listener is not a mismatch")
	}

	dsyncApiListenerUp.Store(true)
	if !dsyncApiClientAuthReloadMismatch(true) {
		t.Fatal("enabling client-auth against a certless listener must be a mismatch")
	}
	if dsyncApiClientAuthReloadMismatch(false) {
		t.Fatal("config matching the certless listener is not a mismatch")
	}

	dsyncApiListenerHandshakeRequestsCert.Store(true)
	if !dsyncApiClientAuthReloadMismatch(false) {
		t.Fatal("disabling client-auth against a requesting listener must be a mismatch")
	}
	if dsyncApiClientAuthReloadMismatch(true) {
		t.Fatal("config matching the requesting listener is not a mismatch")
	}
}

// --- What the failure says (issue #533) ----------------------------------
//
// The 401 stays empty; the failure the middleware logs is where the answer
// lives. These assert on the failure the authenticator returns rather than on
// captured log output, so they pin the content and not the formatting.

// certAuthRequest fakes the TLS state the middleware sees, so a failure can be
// inspected without going through a listener.
func certAuthRequest(leaf *x509.Certificate) *http.Request {
	return &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
}

func TestDsyncApiCertAuthFailureReasons(t *testing.T) {
	ca, caKey, caFile := mintTestCA(t)
	pkixOnly := &DsyncApiClientAuthConf{Mechanisms: []string{DsyncApiAuthTLSPkix}, CAFile: caFile}

	t.Run("no client certificate", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		_, fail := authenticateDsyncApiClientCert(kdb, "example.", &http.Request{}, pkixOnly)
		if fail == nil || fail.Reason != dsyncApiCertNoCertificate {
			t.Fatalf("fail = %+v, want %s", fail, dsyncApiCertNoCertificate)
		}
	})

	t.Run("unknown identity names every SAN looked up", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		_, leaf := mintTestClientLeaf(t, ca, caKey, []string{"a.child.example", "b.child.example"}, "cn")
		_, fail := authenticateDsyncApiClientCert(kdb, "example.", certAuthRequest(leaf), pkixOnly)
		if fail == nil || fail.Reason != dsyncApiCertUnknownIdentity {
			t.Fatalf("fail = %+v, want %s", fail, dsyncApiCertUnknownIdentity)
		}
		// The whole point of the issue: the operator must be able to see which
		// identity the server actually considered, without inspecting the
		// client's certificate by hand.
		considered := joinDsyncApiCertNotes(fail.Notes, false)
		for _, want := range []string{"a.child.example.", "b.child.example."} {
			if !strings.Contains(considered, want) {
				t.Errorf("considered %q does not name %s", considered, want)
			}
		}
		if fail.Subject == "" || fail.Issuer == "" || fail.Serial == "" || fail.NotAfter == "" {
			t.Errorf("the presented certificate is not described: %+v", fail)
		}
	})

	// A self-signed client certificate is the case the issue calls out as
	// looking identical to an unregistered identity. It must not.
	t.Run("registered identity, chain does not verify", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		otherCA, otherKey, _ := mintTestCA(t)
		_, leaf := mintTestClientLeaf(t, otherCA, otherKey, []string{"child1.example"}, "cn")
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix,
			"child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		_, fail := authenticateDsyncApiClientCert(kdb, "example.", certAuthRequest(leaf), pkixOnly)
		if fail == nil || fail.Reason != dsyncApiCertUntrustedChain {
			t.Fatalf("fail = %+v, want %s", fail, dsyncApiCertUntrustedChain)
		}
		if fail.Err == nil {
			t.Error("the verifier's own reason must be carried, not discarded")
		}
	})

	t.Run("disabled and expired are told apart", func(t *testing.T) {
		_, leaf := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "cn")

		kdb := newTestKeyDB(t)
		if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix,
			"child1.example.", "child1.example.", "", time.Time{}); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, err := kdb.SetDsyncApiCertCredentialDisabled("example.", DsyncApiAuthTLSPkix,
			"child1.example.", true); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if _, fail := authenticateDsyncApiClientCert(kdb, "example.", certAuthRequest(leaf), pkixOnly); fail == nil ||
			fail.Reason != dsyncApiCertDisabled {
			t.Fatalf("disabled: fail = %+v", fail)
		}

		kdb2 := newTestKeyDB(t)
		if err := kdb2.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix,
			"child1.example.", "child1.example.", "", time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, fail := authenticateDsyncApiClientCert(kdb2, "example.", certAuthRequest(leaf), pkixOnly); fail == nil ||
			fail.Reason != dsyncApiCertExpired {
			t.Fatalf("expired: fail = %+v", fail)
		}
	})

	// The walk is over dNSName SANs; the CN is not consulted. A certificate
	// with no SAN therefore has nothing to look up, which is a different
	// problem from having one that is not registered.
	t.Run("no dNSName SAN", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		_, leaf := mintTestClientLeaf(t, ca, caKey, nil, "child1.example.")
		_, fail := authenticateDsyncApiClientCert(kdb, "example.", certAuthRequest(leaf), pkixOnly)
		if fail == nil || fail.Reason != dsyncApiCertNoIdentity {
			t.Fatalf("fail = %+v, want %s", fail, dsyncApiCertNoIdentity)
		}
	})

	// The pin is the identity under tls-pin, and it is what the operator
	// compares against `tdns-cli` output.
	t.Run("tls-pin reports the pin it looked up", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		_, leaf := mintTestClientLeaf(t, ca, caKey, nil, "cn")
		_, fail := authenticateDsyncApiClientCert(kdb, "example.",
			certAuthRequest(leaf), &DsyncApiClientAuthConf{Mechanisms: []string{DsyncApiAuthTLSPin}})
		if fail == nil || fail.Reason != dsyncApiCertUnknownIdentity {
			t.Fatalf("fail = %+v", fail)
		}
		if !strings.Contains(joinDsyncApiCertNotes(fail.Notes, false), SPKISHA256(leaf)) {
			t.Errorf("the pin looked up is not reported: %q", joinDsyncApiCertNotes(fail.Notes, false))
		}
	})
}

// One request can produce several outcomes. The one reported is the most
// specific, not whichever SAN the certificate happened to list first.
func TestDsyncApiCertAuthFailureReasonIsTheMostSpecific(t *testing.T) {
	_, _, caFile := mintTestCA(t)
	otherCA, otherKey, _ := mintTestCA(t)
	kdb := newTestKeyDB(t)

	// Two SANs: the first is not registered at all, the second is registered
	// but the certificate does not chain to the ca-file. "unknown identity"
	// would send the operator looking for a missing registration that is not
	// the problem.
	_, leaf := mintTestClientLeaf(t, otherCA, otherKey,
		[]string{"stranger.example", "child1.example"}, "cn")
	if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix,
		"child1.example.", "child1.example.", "", time.Time{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	_, fail := authenticateDsyncApiClientCert(kdb, "example.", certAuthRequest(leaf),
		&DsyncApiClientAuthConf{Mechanisms: []string{DsyncApiAuthTLSPkix}, CAFile: caFile})
	if fail == nil || fail.Reason != dsyncApiCertUntrustedChain {
		t.Fatalf("fail = %+v, want %s", fail, dsyncApiCertUntrustedChain)
	}
	// Both are still on the line: the summary is one reason, the detail is all
	// of them.
	considered := joinDsyncApiCertNotes(fail.Notes, false)
	if !strings.Contains(considered, "stranger.example.") || !strings.Contains(considered, "child1.example.") {
		t.Errorf("considered %q, want both SANs", considered)
	}
}

// A refusal that a later mechanism recovers from is not a failure, but it is
// not nothing either: an operator who disabled a pin and saw the request keep
// working needs to know the pkix row is what let it in.
func TestDsyncApiCertAuthRefusalsAreDistinguishedFromMisses(t *testing.T) {
	ca, caKey, _ := mintTestCA(t)
	_, leaf := mintTestClientLeaf(t, ca, caKey, []string{"child1.example"}, "cn")

	notes := []dsyncApiCertAuthNote{
		{Mech: DsyncApiAuthTLSPin, Identity: SPKISHA256(leaf), Reason: dsyncApiCertUnknownIdentity},
		{Mech: DsyncApiAuthTLSPkix, Identity: "child1.example.", Reason: dsyncApiCertDisabled},
	}
	all := joinDsyncApiCertNotes(notes, false)
	refused := joinDsyncApiCertNotes(notes, true)
	if !strings.Contains(all, dsyncApiCertUnknownIdentity) || !strings.Contains(all, dsyncApiCertDisabled) {
		t.Errorf("all = %q, want both", all)
	}
	// A miss is routine with several mechanisms configured and must not warn.
	if strings.Contains(refused, dsyncApiCertUnknownIdentity) {
		t.Errorf("refusals = %q; a missing row is not a refusal", refused)
	}
	if !strings.Contains(refused, dsyncApiCertDisabled) {
		t.Errorf("refusals = %q, want the disabled row", refused)
	}
}

// The 401 must not become informative just because the log did.
func TestDsyncApiCertAuthFailureDoesNotReachTheClient(t *testing.T) {
	registerDsyncApiParent(t, "example.")
	_, _, caFile := mintTestCA(t)
	setDsyncApiClientAuth(t, &DsyncApiClientAuthConf{
		Mechanisms: []string{DsyncApiAuthTLSPkix},
		CAFile:     caFile,
	})
	otherCA, otherKey, _ := mintTestCA(t)
	cert, _ := mintTestClientLeaf(t, otherCA, otherKey, []string{"child1.example"}, "cn")

	kdb := newTestKeyDB(t)
	if err := kdb.AddDsyncApiCertCredential("example.", DsyncApiAuthTLSPkix,
		"child1.example.", "child1.example.", "", time.Time{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	srv := dsyncApiCertAuthServer(t, kdb, true)
	client := dsyncApiAuthClient(t, srv, &cert)
	resp := dsyncApiGet(t, client, srv, "child1.example.", nil)
	body := readAuthBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || body != "" {
		t.Fatalf("status %d body %q, want an empty 401", resp.StatusCode, body)
	}
}
