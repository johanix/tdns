/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * `tdns-cli cert …` — a deliberately minimal internal PKI for provisioning
 * XoT/TLS certificates in a *private* trust domain (docs/2026-07-21-pkix-
 * cert-tooling-design.md). Not public-PKI tooling: no CRL, no OCSP, no
 * renewal automation, no cert database. The only persistent artifacts are
 * the PEM files themselves plus an append-only, human-readable issued.log
 * next to the CA. The crypto lives in v2/pki.go; this file is flag
 * handling, file I/O, and output.
 */
package cli

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// DefaultCADir is where `cert ca` (and `cert init`) put CA material when
// running as root; non-root runs default to the current directory so the
// tool never surprises a user with writes into /etc.
const DefaultCADir = "/etc/tdns/ca"

var CertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Minimal internal PKI for XoT/TLS provisioning (private trust domains only)",
	Long: `Minimal internal PKI for provisioning XoT/TLS certificates.

Scope: a provisioning convenience for a PRIVATE trust domain (your own
primaries and secondaries) — not general CA tooling. No CRL, no OCSP, no
renewal automation, no certificate database. State is plain PEM files plus
an append-only issued.log next to the CA key.

Typical flows:
  cert init  — one command: CA (if absent) + a server cert for the local
               tdns-auth, written to the paths its config already names.
  cert ca / cert leaf — mint the CA and individual certs by hand.
  cert csr / cert sign — split provisioning: the remote side generates the
               key+CSR locally (key never travels), the CA side signs.`,
}

var (
	certName       string
	certOutDir     string
	certValidity   int
	certCAValidity int // separate backing var: certValidity is shared/rebound by addCommonLeafFlags
	certAlgorithm  string
	certForce      bool
	certCAFile     string
	certCAKeyFile  string
	certDNSNames   []string
	certIPs        []string
	certServer     bool
	certClient     bool
	certCSRFile    string
	certEmitPin    bool
	certEmitTlsa   string
	certTlsaPort   uint16
)

var certCaCmd = &cobra.Command{
	Use:   "ca",
	Short: "Create a self-signed CA (pathlen 0: signs leaves only)",
	Run: func(cmd *cobra.Command, args []string) {
		outDir := certOutDirDefault()
		ca, err := tdns.CreateCA(tdns.CAOptions{
			Name:     certName,
			Validity: time.Duration(certCAValidity) * 24 * time.Hour,
			Alg:      tdns.CertAlgorithm(certAlgorithm),
		})
		if err != nil {
			cliFatalf("cert ca: %v", err)
		}
		base := filepath.Join(outDir, safeFileName(certName))
		writeCertAndKey(base, ca, 0o700)
		appendIssuedLog(outDir, "ca-created", ca.Cert)
		fmt.Printf("CA certificate: %s.crt\nCA signing key: %s.key (mode 0600 — guard it; nothing in tdns ever auto-loads it)\n", base, base)
	},
}

var certLeafCmd = &cobra.Command{
	Use:   "leaf",
	Short: "Generate a key and a CA-signed end-entity certificate",
	Run: func(cmd *cobra.Command, args []string) {
		caCert, caKey := loadCA()
		leaf, err := tdns.IssueLeaf(caCert, caKey, tdns.LeafOptions{
			Name:     certName,
			DNSNames: certDNSNames,
			IPs:      parseIPFlags(),
			Server:   certServer,
			Client:   certClient,
			Validity: time.Duration(certValidity) * 24 * time.Hour,
			Alg:      tdns.CertAlgorithm(certAlgorithm),
		})
		if err != nil {
			cliFatalf("cert leaf: %v", err)
		}
		base := filepath.Join(certOutDirDefaultCwd(), safeFileName(certName))
		writeCertAndKey(base, leaf, 0o755)
		appendIssuedLog(filepath.Dir(certCAFile), "leaf", leaf.Cert)
		fmt.Printf("certificate: %s.crt\nprivate key: %s.key\n", base, base)
		emitPinAndTlsa(leaf.Cert)
	},
}

var (
	certKeyFile  string
	certFromCert string
)

var certCsrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate a certificate signing request (key never leaves this host)",
	Long: `Generate a certificate signing request. By default a fresh key is
generated next to the CSR. With --key an EXISTING private key (PKCS#8, or
legacy openssl EC/RSA PEM) signs the CSR instead — the upgrade-in-place
path for turning a self-signed cert into a CA-signed one: the key (and so
the SPKI) is unchanged, which keeps configured pins and published TLSA
records valid. --from-cert copies CN and SANs from an existing
certificate so the replacement matches what it replaces.`,
	Run: func(cmd *cobra.Command, args []string) {
		opts := tdns.CSROptions{
			Name:     certName,
			DNSNames: certDNSNames,
			IPs:      parseIPFlags(),
			Alg:      tdns.CertAlgorithm(certAlgorithm),
		}
		if certFromCert != "" {
			old := readCertArg(certFromCert)
			if opts.Name == "" {
				opts.Name = old.Subject.CommonName
			}
			opts.DNSNames = append(append([]string(nil), old.DNSNames...), opts.DNSNames...)
			for _, ip := range old.IPAddresses {
				opts.IPs = append(opts.IPs, ip)
			}
		}
		if opts.Name == "" {
			cliFatalf("cert csr: need --name (or --from-cert with a CN)")
		}
		if certKeyFile != "" {
			keyData, err := os.ReadFile(certKeyFile)
			if err != nil {
				cliFatalf("cert csr: reading --key: %v", err)
			}
			key, err := tdns.ParsePrivateKeyPEM(keyData)
			if err != nil {
				cliFatalf("cert csr: %v", err)
			}
			opts.Key = key
		}
		csrPEM, keyPEM, err := tdns.CreateCSR(opts)
		if err != nil {
			cliFatalf("cert csr: %v", err)
		}
		base := filepath.Join(certOutDirDefaultCwd(), safeFileName(opts.Name))
		writeFileSafe(base+".csr", csrPEM, 0o644)
		if keyPEM != nil {
			writeFileSafe(base+".key", keyPEM, 0o600)
			fmt.Printf("CSR:         %s.csr  (send this to the CA operator)\nprivate key: %s.key  (stays here)\n", base, base)
		} else {
			fmt.Printf("CSR:         %s.csr  (send this to the CA operator)\nreusing key: %s  (unchanged — existing pins and TLSA records stay valid)\n", base, certKeyFile)
		}
	},
}

var certSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a CSR with the CA (SANs are taken from the CSR)",
	Run: func(cmd *cobra.Command, args []string) {
		caCert, caKey := loadCA()
		csrPEM, err := os.ReadFile(certCSRFile)
		if err != nil {
			cliFatalf("cert sign: reading CSR: %v", err)
		}
		signed, err := tdns.SignCSR(caCert, caKey, csrPEM, tdns.SignOptions{
			Server:   certServer,
			Client:   certClient,
			Validity: time.Duration(certValidity) * 24 * time.Hour,
		})
		if err != nil {
			cliFatalf("cert sign: %v", err)
		}
		name := signed.Cert.Subject.CommonName
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(certCSRFile), ".csr")
		}
		out := filepath.Join(certOutDirDefaultCwd(), safeFileName(name)+".crt")
		writeFileSafe(out, signed.CertPEM, 0o644)
		appendIssuedLog(filepath.Dir(certCAFile), "csr-signed", signed.Cert)
		fmt.Printf("certificate: %s  (return this to the requester)\n", out)
		emitPinAndTlsa(signed.Cert)
	},
}

var certPinCmd = &cobra.Command{
	Use:   "pin <cert.pem>",
	Short: "Print the base64 SPKI SHA-256 pin of a certificate",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(tdns.SPKISHA256(readCertArg(args[0])))
	},
}

var certShowCmd = &cobra.Command{
	Use:   "show <cert.pem>",
	Short: "Human-readable certificate summary (subject, SANs, EKU, validity, pin)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cert := readCertArg(args[0])
		fmt.Printf("subject:  %s\nissuer:   %s\nserial:   %x\nvalidity: %s — %s\nis-ca:    %v\n",
			cert.Subject, cert.Issuer, cert.SerialNumber,
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cert.IsCA)
		if sans := sanStrings(cert); len(sans) > 0 {
			fmt.Printf("sans:     %s\n", strings.Join(sans, ", "))
		}
		if ekus := ekuStrings(cert); len(ekus) > 0 {
			fmt.Printf("eku:      %s\n", strings.Join(ekus, ", "))
		}
		fmt.Printf("spki pin: %s\n", tdns.SPKISHA256(cert))
	},
}

// --- shared helpers ---------------------------------------------------------

// certOutDirDefault: CA material goes to /etc/tdns/ca when running as root,
// else the cwd (never surprise-write into /etc without privileges).
func certOutDirDefault() string {
	if certOutDir != "" {
		return certOutDir
	}
	if os.Geteuid() == 0 {
		return DefaultCADir
	}
	return "."
}

func certOutDirDefaultCwd() string {
	if certOutDir != "" {
		return certOutDir
	}
	return "."
}

func loadCA() (*x509.Certificate, crypto.Signer) {
	certData, err := os.ReadFile(certCAFile)
	if err != nil {
		cliFatalf("cert: reading CA cert: %v", err)
	}
	caCert, err := tdns.ParseCertPEM(certData)
	if err != nil {
		cliFatalf("cert: parsing CA cert %s: %v", certCAFile, err)
	}
	keyData, err := os.ReadFile(certCAKeyFile)
	if err != nil {
		cliFatalf("cert: reading CA key: %v", err)
	}
	caKey, err := tdns.ParsePrivateKeyPEM(keyData)
	if err != nil {
		cliFatalf("cert: parsing CA key %s: %v", certCAKeyFile, err)
	}
	return caCert, caKey
}

func safeFileName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, name)
}

// writeFileSafe writes data, creating parent dirs, refusing to overwrite an
// existing file unless --force was given.
func writeFileSafe(path string, data []byte, mode os.FileMode) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		cliFatalf("cert: mkdir %s: %v", filepath.Dir(path), err)
	}
	if _, err := os.Stat(path); err == nil && !certForce {
		cliFatalf("cert: %s already exists (use --force to overwrite)", path)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		cliFatalf("cert: write %s: %v", path, err)
	}
	// os.WriteFile does not chmod an existing file; enforce the mode.
	if err := os.Chmod(path, mode); err != nil {
		cliFatalf("cert: chmod %s: %v", path, err)
	}
}

// writeCertAndKey writes <base>.crt (0644) and <base>.key (0600), ensuring
// the containing directory exists with dirMode (0700 for the CA home).
func writeCertAndKey(base string, pc *tdns.PKICert, dirMode os.FileMode) {
	dir := filepath.Dir(base)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		cliFatalf("cert: mkdir %s: %v", dir, err)
	}
	writeFileSafe(base+".crt", pc.CertPEM, 0o644)
	writeFileSafe(base+".key", pc.KeyPEM, 0o600)
}

// appendIssuedLog appends one human-readable line per issuance next to the
// CA. Nothing ever reads this programmatically — it is an operator audit
// trail, not a certificate database. Failure to write it is a warning, not
// an abort (the cert already exists on disk).
func appendIssuedLog(caDir, kind string, cert *x509.Certificate) {
	line := fmt.Sprintf("%s  kind=%s  serial=%x  cn=%q  sans=%s  eku=%s\n",
		time.Now().UTC().Format(time.RFC3339), kind, cert.SerialNumber,
		cert.Subject.CommonName,
		strings.Join(sanStrings(cert), ","), strings.Join(ekuStrings(cert), ","))
	path := filepath.Join(caDir, "issued.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not append to %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not append to %s: %v\n", path, err)
	}
}

func sanStrings(cert *x509.Certificate) []string {
	out := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func ekuStrings(cert *x509.Certificate) []string {
	var out []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "server")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "client")
		default:
			out = append(out, fmt.Sprintf("eku-%d", eku))
		}
	}
	return out
}

func parseIPFlags() []net.IP {
	var ips []net.IP
	for _, s := range certIPs {
		ip := net.ParseIP(s)
		if ip == nil {
			cliFatalf("cert: --ip %q is not a valid IP address", s)
		}
		ips = append(ips, ip)
	}
	return ips
}

func readCertArg(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		cliFatalf("cert: reading %s: %v", path, err)
	}
	cert, err := tdns.ParseCertPEM(data)
	if err != nil {
		cliFatalf("cert: parsing %s: %v", path, err)
	}
	return cert
}

// emitPinAndTlsa prints the SPKI pin and/or the TLSA 3-1-1 record for a
// freshly issued certificate, so one provisioning step feeds all three XoT
// auth modes (pkix via the CA file, pin via the digest, dane via the RR).
func emitPinAndTlsa(cert *x509.Certificate) {
	if certEmitPin {
		fmt.Printf("spki pin (for pins: / +pin=): %s\n", tdns.SPKISHA256(cert))
	}
	if certEmitTlsa != "" {
		tlsa, err := tdns.NewTlsaRR(dns.Fqdn(certEmitTlsa), certTlsaPort, cert)
		if err != nil {
			cliFatalf("cert: building TLSA record: %v", err)
		}
		fmt.Printf("TLSA (publish for dane):     %s\n", tlsa.String())
	}
}

func addCommonLeafFlags(c *cobra.Command) {
	c.Flags().StringVar(&certCAFile, "ca", "", "path to the CA certificate (PEM)")
	c.Flags().StringVar(&certCAKeyFile, "ca-key", "", "path to the CA signing key (PEM)")
	c.Flags().BoolVar(&certServer, "server", true, "include serverAuth EKU (default true; use --server=false for a client-only cert)")
	c.Flags().BoolVar(&certClient, "client", false, "include clientAuth EKU (a mutual-XoT downstream wants both)")
	c.Flags().IntVar(&certValidity, "validity", 397, "validity in days")
	c.Flags().BoolVar(&certEmitPin, "emit-pin", false, "print the SPKI pin after issuing")
	c.Flags().StringVar(&certEmitTlsa, "emit-tlsa", "", "print a TLSA 3-1-1 RR for this owner name after issuing")
	c.Flags().Uint16Var(&certTlsaPort, "tlsa-port", 853, "port for the --emit-tlsa owner name")
	_ = c.MarkFlagRequired("ca")
	_ = c.MarkFlagRequired("ca-key")
}

func init() {
	CertCmd.AddCommand(certCaCmd, certLeafCmd, certCsrCmd, certSignCmd, certPinCmd, certShowCmd, certInitCmd)

	for _, c := range []*cobra.Command{certCaCmd, certLeafCmd, certCsrCmd, certSignCmd} {
		c.Flags().StringVar(&certOutDir, "out-dir", "", "output directory (default: cwd; cert ca as root: "+DefaultCADir+")")
		c.Flags().StringVar(&certAlgorithm, "algorithm", "ed25519", "key algorithm: ed25519 | ecdsa-p256 | rsa2048")
		c.Flags().BoolVar(&certForce, "force", false, "overwrite existing files")
	}
	for _, c := range []*cobra.Command{certCaCmd, certLeafCmd, certCsrCmd} {
		c.Flags().StringVar(&certName, "name", "", "subject CN (and default file base name)")
	}
	// csr may take its name from --from-cert instead (validated in Run).
	_ = certCaCmd.MarkFlagRequired("name")
	_ = certLeafCmd.MarkFlagRequired("name")
	for _, c := range []*cobra.Command{certLeafCmd, certCsrCmd} {
		c.Flags().StringSliceVar(&certDNSNames, "dns", nil, "DNS SANs (comma-separated or repeated)")
		c.Flags().StringSliceVar(&certIPs, "ip", nil, "IP SANs (comma-separated or repeated)")
	}
	certCsrCmd.Flags().StringVar(&certKeyFile, "key", "", "reuse this EXISTING private key (PKCS#8 or legacy openssl EC/RSA PEM) instead of generating one — keeps the SPKI, so pins/TLSA stay valid")
	certCsrCmd.Flags().StringVar(&certFromCert, "from-cert", "", "copy CN and SANs from this existing certificate (PEM)")
	// Own backing variable: certValidity is shared with (and rebound to 397 by)
	// addCommonLeafFlags below, which would otherwise leave `cert ca` minting a
	// 397-day root instead of 3650.
	certCaCmd.Flags().IntVar(&certCAValidity, "validity", 3650, "validity in days")

	addCommonLeafFlags(certLeafCmd)
	addCommonLeafFlags(certSignCmd)
	certSignCmd.Flags().StringVar(&certCSRFile, "csr", "", "path to the CSR (PEM) to sign")
	_ = certSignCmd.MarkFlagRequired("csr")
}
