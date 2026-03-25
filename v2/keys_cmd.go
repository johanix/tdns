/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * JOSE keypair CLI (generate, show) for agent and combiner secure CHUNK comms.
 * Invoked from tdns-agent and tdns-combiner when first argument is "keys".
 */

package tdns

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/johanix/tdns-transport/v2/crypto/jose"
	"gopkg.in/yaml.v3"
)

// LoadConfigForKeys reads the given YAML config file and decodes it into Config.
// Used by tdns-cli agent/combiner keys to get long_term_jose_priv_key path.
// Does not process includes or run full ParseConfig.
func LoadConfigForKeys(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &conf, nil
}

// RunKeysCmd runs the "keys" subcommand (generate | show).
// Used by tdns-cli agent keys / tdns-cli combiner keys. conf must be loaded from the server's config file.
func RunKeysCmd(conf *Config, appType AppType, args []string) error {
	if len(args) < 1 {
		printKeysUsage(appType)
		return fmt.Errorf("missing subcommand (generate or show)")
	}

	backend := jose.NewBackend()

	switch args[0] {
	case "generate":
		return runKeysGenerate(conf, appType, backend, args[1:])
	case "show":
		return runKeysShow(conf, appType, backend, args[1:])
	default:
		printKeysUsage(appType)
		return fmt.Errorf("unknown keys command: %q", args[0])
	}
}

func runKeysGenerate(conf *Config, appType AppType, backend crypto.Backend, args []string) error {
	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	output := fs.String("output", "", "path for generated private key (default from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	privPath := strings.TrimSpace(getKeysPrivKeyPath(conf, appType))
	if *output != "" {
		privPath = strings.TrimSpace(*output)
	}
	if privPath == "" {
		return fmt.Errorf("no key path: set long_term_jose_priv_key in server config or use -output")
	}

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	privJSON, err := backend.SerializePrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("serialize private key: %w", err)
	}
	pubJSON, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize public key: %w", err)
	}

	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(privPath, privJSON, 0600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	pubPath := privPath + ".pub"
	if err := os.WriteFile(pubPath, pubJSON, 0644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	fmt.Printf("Generated JOSE keypair:\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return nil
}

func runKeysShow(conf *Config, appType AppType, backend crypto.Backend, args []string) error {
	privPath := strings.TrimSpace(getKeysPrivKeyPath(conf, appType))
	if privPath == "" {
		return fmt.Errorf("no key path: set long_term_jose_priv_key in server config")
	}

	data, err := os.ReadFile(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("private key file not found: %q: %w", privPath, err)
		}
		return fmt.Errorf("read %q: %w", privPath, err)
	}
	data = StripKeyFileComments(data)

	privKey, err := backend.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	// PublicFromPrivate is JOSE-specific; use type assertion
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return fmt.Errorf("derive public key: backend is not JOSE")
	}
	pubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	pubJSON, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize public key: %w", err)
	}
	fmt.Println(string(pubJSON))
	return nil
}

func getKeysPrivKeyPath(conf *Config, appType AppType) string {
	switch appType {
	case AppTypeAgent:
		if conf.MultiProvider != nil {
			return conf.MultiProvider.LongTermJosePrivKey
		}
		return ""
	case AppTypeCombiner:
		if conf.MultiProvider != nil {
			return conf.MultiProvider.LongTermJosePrivKey
		}
		return ""
	default:
		return ""
	}
}

func printKeysUsage(appType AppType) {
	name := "tdns-agent"
	if appType == AppTypeCombiner {
		name = "tdns-combiner"
	}
	fmt.Fprintf(os.Stderr, "Usage: %s keys generate [-output path]\n", name)
	fmt.Fprintf(os.Stderr, "       %s keys show\n", name)
	fmt.Fprintf(os.Stderr, "  generate  Write JOSE keypair; path from config long_term_jose_priv_key or -output.\n")
	fmt.Fprintf(os.Stderr, "  show      Print public key (JWK) from configured long_term_jose_priv_key.\n")
}
