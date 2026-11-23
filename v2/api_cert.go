/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The management API's TLS certificate when the config names none: a path
 * per config file, and a self-signed pair the daemon writes at its first
 * start. Clients verify the daemon by the pin of its key (tdns-ncli config
 * add writes the pin), so no CA is involved.
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
		lgApi.Info("management API: wrote a self-signed API certificate (clients pin its key; tdns-ncli config add writes the pin)",
			"cert", cert, "key", key, "pin", pin)
	}
	a.CertFile, a.KeyFile = cert, key
}

// EnsureDefaultApiCert writes the default API certificate and key of the
// daemon whose config file is cfgfile (ApiCertPaths) when neither is there,
// as the daemon does at its first start, and returns the key's pin when it
// wrote them. addresses are the API's listen addresses, which the
// certificate names (apiCertSANs). The one way the pair is made: the daemon
// (applyCertDefaults) and tdns-ncli config add, which pins a daemon that has
// not started yet, both call it.
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
	case cerr == nil:
		return "", false, fmt.Errorf("%s is there without its key %s: one file of the default API pair, which the daemon refuses", cert, key)
	case kerr == nil:
		return "", false, fmt.Errorf("%s is there without its certificate %s: one file of the default API pair, which the daemon refuses", key, cert)
	case !errors.Is(cerr, os.ErrNotExist):
		return "", false, cerr
	case !errors.Is(kerr, os.ErrNotExist):
		return "", false, kerr
	}
	pin, err = writeApiCert(cert, key, addresses)
	if err != nil {
		return "", false, err
	}
	return pin, true, nil
}

// LookupCertDefaults is applyCertDefaults without writing anything: for a
// config check, which reports what the daemon would use (and write).
func (a *ApiServerConf) LookupCertDefaults(cfgfile string) {
	a.applyCertDefaults(cfgfile, false)
}

// writeApiCert writes a self-signed API certificate and its key to cert and
// key, which must not exist, and returns the key's pin. The certificate names
// this host, localhost, loopback and the API's listen addresses. The key is
// mode 0600; neither file is ever overwritten, and a key written without its
// certificate is removed again.
func writeApiCert(cert, key string, addresses []string) (string, error) {
	hostname, _ := os.Hostname()
	name := strings.TrimSuffix(filepath.Base(cert), ".crt")
	dnsNames, ips := apiCertSANs(hostname, addresses)
	leaf, err := CreateSelfSignedLeaf(LeafOptions{
		Name:     name,
		DNSNames: dnsNames,
		IPs:      ips,
		Server:   true,
		Validity: apiCertValidity,
		Alg:      CertAlgECDSAP256, // what every TLS client takes
	})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(cert), 0o755); err != nil {
		return "", err
	}
	if err := writeNewFile(key, leaf.KeyPEM, 0o600); err != nil {
		return "", err
	}
	if err := writeNewFile(cert, leaf.CertPEM, 0o644); err != nil {
		os.Remove(key)
		return "", err
	}
	return SPKISHA256(leaf.Cert), nil
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
