/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * `tdns-cli auth config mwe` — generate a Minimal Working Example config for
 * tdns-auth: a single self-contained YAML, a self-signed cert/key pair, and
 * two example primary zones (one signed, one unsigned) with generated zone
 * files, plus a commented-out secondary. Everything is generated so the
 * resulting tree passes `tdns-cli auth config check` and the daemon starts.
 */
package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newConfigMweCmd builds the `config mwe` subcommand for the given role.
// Only tdns-auth is supported today.
func newConfigMweCmd(role string) *cobra.Command {
	var dir string
	c := &cobra.Command{
		Use:   "mwe",
		Short: "Generate a minimal working example config (+ certs, zones) for tdns-" + role,
		Long: `Generate a Minimal Working Example configuration for tdns-` + role + `.

Writes a single self-contained YAML to <dir>/tdns-` + role + `.yaml (or, if that
file already exists, to <dir>/tdns-` + role + `.yaml.mwe so nothing is
clobbered). Also generates, unless already present:

  - a self-signed cert/key pair under <dir>/certs (for the API server and the
    encrypted DNS transports)
  - two example primary zones — one unsigned, one signed — using two different
    zone templates, with generated zone files under <dir>/zones
  - a commented-out secondary zone using a third template

The DNS engine listens on IPv4 and IPv6 localhost; extra listen addresses are
shown commented out. The generated tree is designed to pass
` + "`tdns-cli " + role + " config check`" + `.`,
		Run: func(cmd *cobra.Command, args []string) {
			if role != "auth" {
				cliFatalf("config mwe is currently only implemented for auth")
			}
			runConfigMwe(role, dir)
		},
	}
	c.Flags().StringVar(&dir, "dir", "/etc/tdns", "base directory for the generated config, certs and zones")
	return c
}

// mweZone describes one example zone the MWE generates.
type mweZone struct {
	name     string
	template string
	signed   bool
}

func runConfigMwe(role, dir string) {
	dir = filepath.Clean(dir)
	cfgPath := filepath.Join(dir, "tdns-"+role+".yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		cfgPath += ".mwe"
		fmt.Printf("Config %s already exists; writing MWE to %s instead.\n",
			filepath.Join(dir, "tdns-"+role+".yaml"), cfgPath)
	}

	zonesDir := filepath.Join(dir, "zones")
	certsDir := filepath.Join(dir, "certs")
	for _, d := range []string{dir, zonesDir, certsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			cliFatalf("could not create directory %s: %v", d, err)
		}
	}

	// Certificate/key pair (shared by apiserver and the encrypted DNS
	// transports). Reused if already present.
	certFile := filepath.Join(certsDir, "localhost.crt")
	keyFile := filepath.Join(certsDir, "localhost.key")
	certCreated, err := ensureSelfSignedCert(certFile, keyFile)
	if err != nil {
		cliFatalf("could not generate certificate: %v", err)
	}

	// Random API key.
	apiKey, err := randomAPIKey()
	if err != nil {
		cliFatalf("could not generate api key: %v", err)
	}

	// Example zones: two primaries (different templates), one secondary
	// (third template, emitted commented-out below).
	zones := []mweZone{
		{name: "signed.example.", template: "signed-primary", signed: true},
		{name: "unsigned.example.", template: "unsigned-primary", signed: false},
	}
	var zoneFilesCreated, zoneFilesKept []string
	for _, z := range zones {
		zf := filepath.Join(zonesDir, strings.TrimSuffix(z.name, ".")+".zone")
		if _, err := os.Stat(zf); err == nil {
			zoneFilesKept = append(zoneFilesKept, zf)
			continue
		}
		if err := os.WriteFile(zf, []byte(mweZoneFileContent(z.name)), 0o644); err != nil {
			cliFatalf("could not write zone file %s: %v", zf, err)
		}
		zoneFilesCreated = append(zoneFilesCreated, zf)
	}

	apiPort := "8989"
	dnsPort := "5354"
	content := renderMweConfig(role, dir, zonesDir, certFile, keyFile, apiKey, apiPort, dnsPort)
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		cliFatalf("could not write config %s: %v", cfgPath, err)
	}

	// Summary.
	fmt.Printf("\nWrote MWE config:  %s\n", cfgPath)
	if certCreated {
		fmt.Printf("Generated cert:    %s\n", certFile)
		fmt.Printf("Generated key:     %s\n", keyFile)
	} else {
		fmt.Printf("Reused cert/key:   %s , %s\n", certFile, keyFile)
	}
	for _, zf := range zoneFilesCreated {
		fmt.Printf("Generated zone:    %s\n", zf)
	}
	for _, zf := range zoneFilesKept {
		fmt.Printf("Kept zone file:    %s\n", zf)
	}

	fmt.Printf("\nTo let `tdns-cli %s ...` reach this server, add to your tdns-cli.yaml:\n\n", role)
	fmt.Printf("  apiservers:\n")
	fmt.Printf("     - name:       tdns-%s\n", role)
	fmt.Printf("       baseurl:    https://127.0.0.1:%s/api/v1\n", apiPort)
	fmt.Printf("       apikey:     %s\n", apiKey)
	fmt.Printf("       authmethod: X-API-Key\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  tdns-%s --config %s        # start the server\n", role, cfgPath)
	fmt.Printf("  tdns-cli %s config check --serverconfig %s   # validate\n", role, cfgPath)
}

// ---------------------------------------------------------------------------
// Config rendering
// ---------------------------------------------------------------------------

func renderMweConfig(role, dir, zonesDir, certFile, keyFile, apiKey, apiPort, dnsPort string) string {
	r := strings.NewReplacer(
		"{{ROLE}}", role,
		"{{DIR}}", dir,
		"{{ZONESDIR}}", zonesDir,
		"{{CERT}}", certFile,
		"{{KEY}}", keyFile,
		"{{APIKEY}}", apiKey,
		"{{APIPORT}}", apiPort,
		"{{DNSPORT}}", dnsPort,
	)
	return r.Replace(mweConfigTemplate)
}

// mweConfigTemplate is the single-file MWE. Placeholders in {{...}} form are
// substituted by renderMweConfig (avoids fmt verb collisions with the %s zone
// pattern shown in a comment below).
const mweConfigTemplate = `# Minimal Working Example — tdns-{{ROLE}}
#
# Generated by ` + "`tdns-cli {{ROLE}} config mwe`" + `. Self-contained: one file, a
# self-signed cert, and two example primary zones with generated zone files.
# Validate it any time with:  tdns-cli {{ROLE}} config check --serverconfig <this file>

service:
   name:  TDNS-AUTH

dnsengine:
   # Listen on IPv4 and IPv6 localhost. Port {{DNSPORT}} is used so the server
   # runs unprivileged; use 53 for a real deployment (needs root/capabilities).
   addresses:   [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}' ]
   # Add more listen addresses by uncommenting/extending, e.g.:
   #   addresses: [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}', 192.0.2.53:53, '[2001:db8::53]:53' ]
   transports:  [ do53 ]
   # For encrypted transports, add them here and the cert/key are already set:
   #   transports: [ do53, dot, doh, doq ]
   certfile:  {{CERT}}
   keyfile:   {{KEY}}

apiserver:
   addresses:  [ 127.0.0.1:{{APIPORT}} ]
   apikey:     {{APIKEY}}
   certfile:   {{CERT}}
   keyfile:    {{KEY}}
   usetls:     true

db:
   file:  {{DIR}}/tdns-{{ROLE}}.db

log:
   file:   {{DIR}}/tdns-{{ROLE}}.log
   level:  info

# One DNSSEC policy, referenced by the signed zone below. ED25519 for both
# roles (same algorithm needs no split_algorithms entry), static keys.
dnssec:
   policies:
      default:
         algorithm:  ED25519
         ksk: { lifetime: forever }
         zsk: { lifetime: forever }
         csk: { lifetime: none }
         sigvalidity:
            default:  14d
            dnskey:   30d
            ds:       14d

# Zone templates. The two primaries below use two DIFFERENT templates; the
# commented-out secondary uses a third.
templates:
   - name:   unsigned-primary
     type:   primary
     store:  map

   - name:          signed-primary
     type:          primary
     store:         map
     options:       [ online-signing ]
     dnssecpolicy:  default

   - name:   basic-secondary
     type:   secondary
     store:  map

zones:
   # Unsigned primary (template: unsigned-primary).
   - name:      unsigned.example.
     zonefile:  {{ZONESDIR}}/unsigned.example.zone
     template:  unsigned-primary
     downstreams:
        - { prefix: "127.0.0.0/8", key: NOKEY }
        - { prefix: "::1",         key: NOKEY }

   # Signed primary (template: signed-primary -> online-signing + dnssecpolicy).
   - name:      signed.example.
     zonefile:  {{ZONESDIR}}/signed.example.zone
     template:  signed-primary
     downstreams:
        - { prefix: "127.0.0.0/8", key: NOKEY }
        - { prefix: "::1",         key: NOKEY }

   # Example SECONDARY zone (template: basic-secondary). Uncomment and point
   # primaries: at your real primary to enable. A template may instead carry a
   # zonefile pattern like  zonefile: {{ZONESDIR}}/%szone  to derive the path.
   # - name:      secondary.example.
   #   template:  basic-secondary
   #   primaries:
   #      - { addr: "192.0.2.1:53", key: NOKEY }
   #   allow-notify:
   #      - { prefix: "192.0.2.1", key: NOKEY }
`

// mweZoneFileContent returns a minimal, valid zone file (SOA + NS + address
// records) for the named zone. The name includes its trailing dot.
func mweZoneFileContent(zone string) string {
	return "" +
		"$ORIGIN " + zone + "\n" +
		"$TTL 3600\n" +
		"@     IN SOA  ns1." + zone + " hostmaster." + zone + " ( 1 3600 1800 1209600 3600 )\n" +
		"@     IN NS   ns1." + zone + "\n" +
		"ns1   IN A    127.0.0.1\n" +
		"ns1   IN AAAA ::1\n" +
		"www   IN A    127.0.0.1\n" +
		"www   IN AAAA ::1\n"
}

// ---------------------------------------------------------------------------
// Cert + key generation
// ---------------------------------------------------------------------------

// ensureSelfSignedCert writes a self-signed ECDSA P-256 cert/key pair for
// localhost to certFile/keyFile unless BOTH already exist. Returns whether a
// new pair was created.
func ensureSelfSignedCert(certFile, keyFile string) (bool, error) {
	_, cerr := os.Stat(certFile)
	_, kerr := os.Stat(keyFile)
	if cerr == nil && kerr == nil {
		return false, nil // reuse existing pair
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return false, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return false, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return false, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// randomAPIKey returns a URL-safe base64 random string (32 bytes of entropy).
func randomAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
