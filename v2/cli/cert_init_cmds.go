/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * `tdns-cli cert init` — the one-shot local provisioning path: create the
 * CA if absent, mint a server certificate for the local tdns-auth with SANs
 * derived from its own config, and write cert/key to the exact paths the
 * config already names. After this + a daemon restart, the primary serves
 * verified XoT; the command prints everything a secondary needs (ca-file,
 * pin, TLSA) for each of the three auth modes.
 */
package cli

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	certInitServerConfig string
	certInitCADir        string
	certInitCAName       string
)

var certInitCmd = &cobra.Command{
	Use:   "init",
	Short: "One-shot local provisioning: CA (if absent) + server cert for the local tdns-auth",
	Long: `Reads the local tdns-auth config, creates a private CA if one does not
exist yet, and issues a server certificate written to the exact
dnsengine.certfile/keyfile paths the config already names — no config
editing needed, just restart the daemon. SANs are derived from the
config's listen addresses plus this host's name (and loopback). The leaf
carries both serverAuth and clientAuth EKU so the same daemon can also
present it as a client certificate under mutual XoT.

Re-running is safe: an existing CA is reused; existing cert/key files are
only replaced with --force.`,
	Run: func(cmd *cobra.Command, args []string) {
		runCertInit()
	},
}

func runCertInit() {
	cfgPath := certInitServerConfig
	if cfgPath == "" {
		cfgPath = tdns.DefaultAuthCfgFile
	}
	v := viper.New()
	v.SetConfigFile(cfgPath)
	if err := v.ReadInConfig(); err != nil {
		cliFatalf("cert init: reading server config %s: %v", cfgPath, err)
	}
	// Single-level include: merge, same as the daemon loader.
	for _, inc := range v.GetStringSlice("include") {
		if !filepath.IsAbs(inc) {
			inc = filepath.Join(filepath.Dir(cfgPath), inc)
		}
		if _, err := os.Stat(inc); err == nil {
			v.SetConfigFile(inc)
			if err := v.MergeInConfig(); err != nil {
				cliFatalf("cert init: merging include %s: %v", inc, err)
			}
		}
	}

	certFile := v.GetString("dnsengine.certfile")
	keyFile := v.GetString("dnsengine.keyfile")
	if certFile == "" || keyFile == "" {
		cliFatalf("cert init: %s does not set dnsengine.certfile/keyfile — set both (they are where the new cert/key will be written), then re-run", cfgPath)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		cliFatalf("cert init: cannot determine hostname: %v", err)
	}
	leafName := certName
	if leafName == "" {
		leafName = hostname
	}
	dnsSANs, ipSANs := initSANs(leafName, hostname, v.GetStringSlice("dnsengine.addresses"))

	// CA: reuse when present, mint when absent, refuse a half-present pair.
	caDir := certInitCADir
	if caDir == "" {
		if os.Geteuid() == 0 {
			caDir = DefaultCADir
		} else {
			caDir = "."
		}
	}
	caBase := filepath.Join(caDir, safeFileName(certInitCAName))
	caCertPath, caKeyPath := caBase+".crt", caBase+".key"
	_, certErr := os.Stat(caCertPath)
	_, keyErr := os.Stat(caKeyPath)
	var created bool
	switch {
	case certErr == nil && keyErr == nil:
		// reuse
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		ca, err := tdns.CreateCA(tdns.CAOptions{Name: certInitCAName, Alg: tdns.CertAlgorithm(certAlgorithm)})
		if err != nil {
			cliFatalf("cert init: creating CA: %v", err)
		}
		writeCertAndKey(caBase, ca, 0o700)
		appendIssuedLog(caDir, "ca-created", ca.Cert)
		created = true
	default:
		cliFatalf("cert init: inconsistent CA state in %s (found one of %s / %s but not both) — repair or remove before re-running", caDir, caCertPath, caKeyPath)
	}
	certCAFile, certCAKeyFile = caCertPath, caKeyPath
	caCert, caKey := loadCA()
	if created {
		fmt.Printf("created CA:      %s (+ .key, mode 0600 — guard it)\n", caCertPath)
	} else {
		fmt.Printf("reusing CA:      %s\n", caCertPath)
	}

	leaf, err := tdns.IssueLeaf(caCert, caKey, tdns.LeafOptions{
		Name:     leafName,
		DNSNames: dnsSANs,
		IPs:      ipSANs,
		Server:   true,
		Client:   true, // mutual-XoT ready: the daemon can present it as a client cert too
		Validity: time.Duration(certValidity) * 24 * time.Hour,
		Alg:      tdns.CertAlgorithm(certAlgorithm),
	})
	if err != nil {
		cliFatalf("cert init: issuing server cert: %v", err)
	}
	writeFileSafe(certFile, leaf.CertPEM, 0o644)
	writeFileSafe(keyFile, leaf.KeyPEM, 0o600)
	appendIssuedLog(caDir, "init-server-leaf", leaf.Cert)
	fmt.Printf("server cert:     %s\nserver key:      %s\n", certFile, keyFile)

	// Drop a copy of the CA cert next to the server cert for use as
	// ca-file / downstream-ca on this host. Idempotent: identical content
	// is left alone; a different file needs --force.
	caCopy := filepath.Join(filepath.Dir(certFile), safeFileName(certInitCAName)+".crt")
	if existing, err := os.ReadFile(caCopy); err != nil || !bytes.Equal(existing, mustReadFile(caCertPath)) {
		writeFileSafe(caCopy, mustReadFile(caCertPath), 0o644)
	}
	fmt.Printf("CA cert copy:    %s\n\n", caCopy)

	dotPort := initDotPort(v)
	fmt.Printf("Restart tdns-auth to serve the new certificate. Secondaries can then use any of:\n\n")
	fmt.Printf("  # pkix — copy %s to the secondary:\n", filepath.Base(caCopy))
	fmt.Printf("  primaries:\n     - addr: %s:%s\n       key: NOKEY\n       transport: dot\n       tls-auth: pkix\n       ca-file: /etc/tdns/certs/%s\n\n", leafName, dotPort, filepath.Base(caCopy))
	fmt.Printf("  # pin — no file distribution needed:\n")
	fmt.Printf("  #    tls-auth: pin\n  #    pins: [ %q ]\n\n", tdns.SPKISHA256(leaf.Cert))
	tlsa, terr := tdns.NewTlsaRR(dns.Fqdn(leafName), initPortNum(dotPort), leaf.Cert)
	if terr == nil {
		fmt.Printf("  # dane — publish this record (zone must be DNSSEC-signed):\n  #    %s\n", tlsa.String())
	}
}

// initSANs derives the certificate SANs: the leaf name, the hostname,
// localhost, loopback, and every listen address from the config (skipping
// wildcard binds).
func initSANs(leafName, hostname string, addresses []string) ([]string, []net.IP) {
	dnsSet := map[string]bool{leafName: true, hostname: true, "localhost": true}
	ipSet := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}
	for _, addr := range addresses {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsUnspecified() {
				ipSet[ip.String()] = ip
			}
		} else if host != "" {
			dnsSet[host] = true
		}
	}
	var dnsSANs []string
	for name := range dnsSet {
		if ip := net.ParseIP(name); ip == nil {
			dnsSANs = append(dnsSANs, name)
		}
	}
	sort.Strings(dnsSANs)
	var ipKeys []string
	for k := range ipSet {
		ipKeys = append(ipKeys, k)
	}
	sort.Strings(ipKeys)
	ips := make([]net.IP, 0, len(ipKeys))
	for _, k := range ipKeys {
		ips = append(ips, ipSet[k])
	}
	return dnsSANs, ips
}

// initDotPort returns the DoT port the config implies: dnsengine.ports.dot
// when set, else 853.
func initDotPort(v *viper.Viper) string {
	if ports := v.GetStringSlice("dnsengine.ports.dot"); len(ports) > 0 {
		return ports[0]
	}
	if ports := v.GetIntSlice("dnsengine.ports.dot"); len(ports) > 0 {
		return strconv.Itoa(ports[0])
	}
	return "853"
}

func initPortNum(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 853
	}
	return uint16(n)
}

func mustReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		cliFatalf("cert init: reading %s: %v", path, err)
	}
	return data
}

func init() {
	certInitCmd.Flags().StringVar(&certInitServerConfig, "serverconfig", "", "path to the tdns-auth config (default: "+tdns.DefaultAuthCfgFile+")")
	certInitCmd.Flags().StringVar(&certInitCADir, "ca-dir", "", "CA directory (default: "+DefaultCADir+" as root, else cwd)")
	certInitCmd.Flags().StringVar(&certInitCAName, "ca-name", "tdns-ca", "CA name (CN and file base name)")
	certInitCmd.Flags().StringVar(&certName, "name", "", "server cert CN and primary SAN (default: hostname)")
	certInitCmd.Flags().IntVar(&certValidity, "validity", 397, "server cert validity in days")
	certInitCmd.Flags().StringVar(&certAlgorithm, "algorithm", "ed25519", "key algorithm: ed25519 | ecdsa-p256 | rsa2048")
	certInitCmd.Flags().BoolVar(&certForce, "force", false, "overwrite existing cert/key files")
}
