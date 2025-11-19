package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	GenerateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate DNS records or encodings",
	}

	tlsaPort  uint16
	tlsaProto string
	tlsaTTL   uint32
)

var generateTLSACmd = &cobra.Command{
	Use:   "tlsa <domain> <cert.pem>",
	Short: "Generate a TLSA record (usage 3 1 1) from a PEM certificate",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		domain := dns.Fqdn(args[0])
		certFile := args[1]

		pemData, err := os.ReadFile(certFile)
		if err != nil {
			log.Fatalf("failed to read %s: %v", certFile, err)
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Fatalf("failed to decode PEM data in %s", certFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse certificate: %v", err)
		}
		digest := sha256.Sum256(cert.Raw)
		digestHex := strings.ToUpper(hex.EncodeToString(digest[:]))

		owner := fmt.Sprintf("_%d._%s.%s", tlsaPort, strings.ToLower(tlsaProto), domain)
		fmt.Printf("%s %d IN TLSA 3 1 1 %s\n", owner, tlsaTTL, digestHex)
	},
}

func init() {
	GenerateCmd.AddCommand(ToRFC3597Cmd)
	GenerateCmd.AddCommand(generateTLSACmd)

	generateTLSACmd.Flags().Uint16VarP(&tlsaPort, "port", "p", 443, "Service port for the TLSA owner name")
	generateTLSACmd.Flags().Uint32VarP(&tlsaTTL, "ttl", "t", 3600, "TTL for the resulting TLSA RR")
	generateTLSACmd.Flags().StringVar(&tlsaProto, "proto", "tcp", "Protocol for the TLSA owner name (e.g. tcp)")
}
