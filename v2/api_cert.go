/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The management API's TLS certificate when the config names none: a path
 * per config file, and a self-signed pair the daemon writes at its first
 * start. Clients verify the daemon by the pin of its key (tdns-ncli config
 * add writes the pin, as the daemon serves it), so no CA is involved.
 */
package tdns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// apiCertValidity is long: clients verify the daemon by the pin of its key,
// not by the certificate's dates. A new key is a deliberate act (remove the
// pair, restart, re-pin), not an expiry.
const apiCertValidity = 10 * 365 * 24 * time.Hour

// ApiCertPaths is the default API certificate and key of the daemon whose
// config file is cfgfile: {confdir}/certs/{config name}-api.crt and .key, so
// /etc/tdns/tdns-auth.yaml has /etc/tdns/certs/tdns-auth-api.crt. One pair per
// config file: daemons whose configs share a directory get keys of their own
// (a client pinning one daemon's key must not accept another daemon), and
// the directory tells configs elsewhere apart. "" when cfgfile is "".
func ApiCertPaths(cfgfile string) (cert, key string) {
	if cfgfile == "" {
		return "", ""
	}
	abs, err := filepath.Abs(cfgfile)
	if err != nil {
		return "", ""
	}
	base := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	dir := filepath.Join(filepath.Dir(abs), "certs")
	return filepath.Join(dir, base+"-api.crt"), filepath.Join(dir, base+"-api.key")
}

// applyCertDefaults gives an apiserver block that names neither certfile nor
// keyfile the default pair of cfgfile (ApiCertPaths). A block that names
// either is left as it is: an operator's paths are used, never written.
//
// With neither default file there yet, write (the daemon at its first start:
// ParseConfig, not a reload) writes a self-signed pair and uses it. Without
// write (config check, a reload), or when writing fails, the paths stay empty
// and CertPending says why: the validator lets that pass (the daemon writes
// the pair when it starts), and APIdispatcher starts no TCP listener without
// a certificate. One default file without the other is left for the
// validator to refuse: something removed half a pair, and writing over the
// other half would replace a key someone may have pinned.
func (a *ApiServerConf) applyCertDefaults(cfgfile string, write bool) {
	a.CertPending = false
	if a.CertFile != "" || a.KeyFile != "" {
		return
	}
	cert, key := ApiCertPaths(cfgfile)
	if cert == "" {
		return
	}
	_, cerr := os.Stat(cert)
	_, kerr := os.Stat(key)
	switch {
	case cerr == nil || kerr == nil:
		a.CertFile, a.KeyFile = cert, key
		return
	case !write || len(a.Addresses) == 0:
		// Nothing to write yet: no TCP listener needs it, or this is not
		// the daemon starting.
		a.CertPending = len(a.Addresses) > 0
		return
	}
	pin, created, err := EnsureDefaultApiCert(cfgfile, a.Addresses)
	if err != nil {
		lgApi.Error("management API: could not write the default API certificate; the TCP API will not start",
			"cert", cert, "key", key, "err", err)
		a.CertPending = true
		return
	}
	if created {
		lgApi.Info("management API: wrote a self-signed API certificate (clients verify it by its certificate pin, which tdns-ncli config add writes)",
			"cert", cert, "key", key, "pin", pin)
	}
	a.CertFile, a.KeyFile = cert, key
}

// EnsureDefaultApiCert writes the default API certificate and key of the
// daemon whose config file is cfgfile (ApiCertPaths) when neither is there,
// as the daemon does at its first start (applyCertDefaults), and returns
// the key's pin when it wrote them. addresses are the API's listen
// addresses, which the certificate names (apiCertSANs). The daemon is the
// only writer of its pair: tdns-ncli never makes it.
//
// A pair that is there is left as it is (created false). One file without
// the other is an error, as the validator refuses it: something removed half
// a pair, and writing over the other half would replace a key someone may
// have pinned.
func EnsureDefaultApiCert(cfgfile string, addresses []string) (pin string, created bool, err error) {
	cert, key := ApiCertPaths(cfgfile)
	if cert == "" {
		return "", false, errors.New("no config file to name the default API certificate after")
	}
	_, cerr := os.Stat(cert)
	_, kerr := os.Stat(key)
	switch {
	case cerr == nil && kerr == nil:
		return "", false, nil
	case cerr == nil || kerr == nil:
		return "", false, HalfApiCertPairError(cert, key, cerr == nil)
	case !errors.Is(cerr, os.ErrNotExist):
		return "", false, cerr
	case !errors.Is(kerr, os.ErrNotExist):
		return "", false, kerr
	}
	leaf, err := apiCertLeaf(cert, addresses)
	if err != nil {
		return "", false, err
	}
	// The key (mode 0600) and then the certificate, each only if it is not
	// there: one made meanwhile is an error, and nothing of this pair is
	// left.
	if err := os.MkdirAll(filepath.Dir(cert), 0o755); err != nil {
		return "", false, err
	}
	if err := writeNewFile(key, leaf.KeyPEM, 0o600); err != nil {
		return "", false, err
	}
	if err := writeNewFile(cert, leaf.CertPEM, 0o644); err != nil {
		os.Remove(key)
		return "", false, err
	}
	return SPKISHA256(leaf.Cert), true, nil
}

// HalfApiCertPairError is the refusal of one file of the default API pair
// cert and key without the other: the certificate without its key when
// certThere, else the key without its certificate. EnsureDefaultApiCert
// returns it.
func HalfApiCertPairError(cert, key string, certThere bool) error {
	if certThere {
		return fmt.Errorf("%s is there without its key %s: one file of the default API pair, which the daemon refuses", cert, key)
	}
	return fmt.Errorf("%s is there without its certificate %s: one file of the default API pair, which the daemon refuses", key, cert)
}

// LookupCertDefaults is applyCertDefaults without writing anything: for a
// config check, which reports what the daemon would use (and write).
func (a *ApiServerConf) LookupCertDefaults(cfgfile string) {
	a.applyCertDefaults(cfgfile, false)
}

// apiCertLeaf is a self-signed API certificate for cert's name, naming this
// host, localhost, loopback and the API's listen addresses (apiCertSANs).
func apiCertLeaf(cert string, addresses []string) (*PKICert, error) {
	hostname, _ := os.Hostname()
	dnsNames, ips := apiCertSANs(hostname, addresses)
	return CreateSelfSignedLeaf(LeafOptions{
		Name:     strings.TrimSuffix(filepath.Base(cert), ".crt"),
		DNSNames: dnsNames,
		IPs:      ips,
		Server:   true,
		Validity: apiCertValidity,
		Alg:      CertAlgECDSAP256, // what every TLS client takes
	})
}

// writeNewFile writes data to path, which must not exist.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// apiCertSANs are the names a default API certificate carries: localhost,
// this host, loopback, and every API listen address that is not a wildcard.
func apiCertSANs(hostname string, addresses []string) ([]string, []net.IP) {
	dnsNames := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, a := range addresses {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		switch {
		case ip == nil && host != "" && host != "localhost":
			dnsNames = append(dnsNames, host)
		case ip == nil, ip.IsUnspecified(), slices.ContainsFunc(ips, ip.Equal):
			// A loopback address other than 127.0.0.1 and ::1 (127.0.0.2) is
			// one the API listens on, and the certificate must cover it.
		default:
			ips = append(ips, ip)
		}
	}
	return dnsNames, ips
}
