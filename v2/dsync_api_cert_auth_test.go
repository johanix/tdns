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
			OptDelSyncParent:     true,
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
	next.Parent.Api.ClientAuth = ca
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
		pemBytes, err := os.ReadFile(conf.DelegationSync.Parent.Api.CertFile)
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

	t.Run("7 client-auth unset sends no CertificateRequest", func(t *testing.T) {
		conf, router, ok := dsyncApiTestListener(t)
		if !ok {
			t.Skip("no test certificate available")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stop := make(chan struct{})
		defer close(stop)
		go func() { _ = conf.StartDsyncApiListener(ctx, router, stop) }()

		addr := conf.DelegationSync.Parent.Api.Listen[0]
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
		conf.DelegationSync.Parent.Api.ClientAuth = &DsyncApiClientAuthConf{
			Mechanisms: []string{DsyncApiAuthTLSPin},
		}
		SetDelegationSyncConfig(conf.DelegationSync)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stop := make(chan struct{})
		defer close(stop)
		go func() { _ = conf.StartDsyncApiListener(ctx, router, stop) }()

		addr := conf.DelegationSync.Parent.Api.Listen[0]
		requested, err := handshake(t, addr, rootsFromConf(t, conf))
		if err != nil {
			t.Fatalf("certless handshake failed: %v", err)
		}
		if !requested {
			t.Fatal("configured listener did not send a CertificateRequest")
		}
	})
}
