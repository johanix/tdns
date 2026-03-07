/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Root-level "keys generate": JOSE keypair generation for agent/combiner.
 * No config required; use when setting up agent.jose.private / combiner.jose.private.
 * Migrated from tdns-nm/cmd/kdc-cli "keys generate --jose".
 */

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/johanix/tdns/v2/crypto"
	_ "github.com/johanix/tdns/v2/crypto/jose"
	"github.com/spf13/cobra"
)

// RootKeysCmd is the root-level "keys" command (e.g. tdns-cli keys generate).
// It does not require tdns-cli config or API; use for generating JOSE keypairs on disk.
var RootKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate long-term keypairs for agent/combiner (JOSE)",
	Long: `Generate JOSE keypairs used by tdns-agentv2 and tdns-combinerv2 for
authenticated NOTIFY(CHUNK) and API traffic. Use one keypair per party:
  - Agent:  agent.jose.private (+ optional agent.jose.pub for combiner config)
  - Combiner: combiner.jose.private (+ optional combiner.jose.pub for agent config)
`,
}

var rootKeysGenerateCmd = &cobra.Command{
	Use:   "generate [--jose] [--jose-outfile <path>] [--jose-pubfile <path>]",
	Short: "Generate JOSE keypair (P-256)",
	Long: `Generate a JOSE keypair (P-256) for agent or combiner.

Must specify --jose and --jose-outfile (private key path).

  --jose              Generate new JOSE keypair
  --jose-outfile      Path for JOSE private key file (required if --jose)
  --jose-pubfile      Optional: path to write public key (JWK) for the peer
                      e.g. agent.jose.pub on combiner, combiner.jose.pub on agent

Examples:
  tdns-cli keys generate --jose --jose-outfile /etc/tdns/agent.jose.private --jose-pubfile /etc/tdns/agent.jose.pub
  tdns-cli keys generate --jose --jose-outfile /etc/tdns/combiner.jose.private --jose-pubfile /etc/tdns/combiner.jose.pub

Then configure:
  - Agent:  long_term_jose_priv_key: /etc/tdns/agent.jose.private
           combiner.long_term_jose_pub_key: /etc/tdns/combiner.jose.pub
  - Combiner: long_term_jose_priv_key: /etc/tdns/combiner.jose.private
              agent_peer.long_term_jose_pub_key: /etc/tdns/agent.jose.pub
`,
	Run: runRootKeysGenerate,
}

func runRootKeysGenerate(cmd *cobra.Command, args []string) {
	genJose, _ := cmd.Flags().GetBool("jose")
	joseOutfile, _ := cmd.Flags().GetString("jose-outfile")
	josePubfile, _ := cmd.Flags().GetString("jose-pubfile")

	if !genJose {
		log.Fatalf("Error: Must specify --jose")
	}
	if joseOutfile == "" {
		joseOutfile = "./agent.jose.private"
	}

	if _, err := os.Stat(joseOutfile); err == nil {
		log.Fatalf("Error: JOSE key file already exists: %s\nUse a different path or remove the existing file first.", joseOutfile)
	}

	backend, err := crypto.GetBackend("jose")
	if err != nil {
		log.Fatalf("Error getting JOSE backend: %v", err)
	}

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		log.Fatalf("Error generating JOSE keypair: %v", err)
	}

	privKeyBytes, err := backend.SerializePrivateKey(privKey)
	if err != nil {
		log.Fatalf("Error serializing JOSE private key: %v", err)
	}
	pubKeyBytes, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		log.Fatalf("Error serializing JOSE public key: %v", err)
	}

	var prettyJSON interface{}
	if err := json.Unmarshal(privKeyBytes, &prettyJSON); err != nil {
		log.Fatalf("Error parsing JOSE private key JSON: %v", err)
	}
	prettyJSONBytes, err := json.MarshalIndent(prettyJSON, "", "  ")
	if err != nil {
		log.Fatalf("Error formatting JOSE private key JSON: %v", err)
	}

	keyID := keyIDFromPub("jose", pubKeyBytes)
	generatedAt := time.Now().Format(time.RFC3339)

	// Write file with comment header (KDC/KRS style); parsers use StripKeyFileComments before JSON parse.
	keyContent := fmt.Sprintf(`# JOSE Private Key (P-256) - agent/combiner long-term
# Generated: %s
# KeyID: %s
# Algorithm: P-256 (ECDH-ES + ECDSA)
# Used by tdns-agentv2 / tdns-combinerv2 for NOTIFY(CHUNK) and API auth.
#
# WARNING: This is a PRIVATE KEY. Keep it secret. Do not share.
#
# Config: long_term_jose_priv_key: %s
#
%s
`, generatedAt, keyID, joseOutfile, string(prettyJSONBytes))

	// Use O_EXCL to atomically prevent overwriting existing files (TOCTOU safe)
	keyContentBytes := []byte(keyContent)
	f, err := os.OpenFile(joseOutfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Error creating JOSE key file (may already exist): %v", err)
	}
	if _, err := f.Write(keyContentBytes); err != nil {
		f.Close()
		log.Fatalf("Error writing JOSE key file: %v", err)
	}
	f.Close()

	// Zero sensitive key material in memory after write (M66)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0
	}
	for i := range prettyJSONBytes {
		prettyJSONBytes[i] = 0
	}
	for i := range keyContentBytes {
		keyContentBytes[i] = 0
	}

	absPriv, _ := filepath.Abs(joseOutfile)
	fmt.Printf("JOSE keypair generated\n")
	fmt.Printf("  KeyID:  %s\n", keyID)
	fmt.Printf("  Priv:   %s\n", absPriv)

	if josePubfile != "" {
		var pubPretty interface{}
		if err := json.Unmarshal(pubKeyBytes, &pubPretty); err != nil {
			log.Fatalf("Error parsing JOSE public key JSON: %v", err)
		}
		pubPrettyBytes, err := json.MarshalIndent(pubPretty, "", "  ")
		if err != nil {
			log.Fatalf("Error formatting JOSE public key JSON: %v", err)
		}
		pubWithNewline := append(pubPrettyBytes, '\n')
		if err := os.WriteFile(josePubfile, pubWithNewline, 0644); err != nil {
			log.Fatalf("Error writing JOSE public key file: %v", err)
		}
		absPub, _ := filepath.Abs(josePubfile)
		fmt.Printf("  Pub:    %s\n", absPub)
	}
}

func keyIDFromPub(alg string, pubKeyBytes []byte) string {
	h := sha256.Sum256(pubKeyBytes)
	return alg + "_" + hex.EncodeToString(h[:])[:8]
}

func init() {
	RootKeysCmd.AddCommand(rootKeysGenerateCmd)
	rootKeysGenerateCmd.Flags().Bool("jose", false, "Generate new JOSE keypair")
	rootKeysGenerateCmd.Flags().String("jose-outfile", "", "Output path for JOSE private key (default: ./agent.jose.private)")
	rootKeysGenerateCmd.Flags().String("jose-pubfile", "", "Optional: output path for JOSE public key (for peer config)")
}
