package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// CustomValidator is a struct that embeds the validator.Validate type
type CustomValidator struct {
	*validator.Validate
}

// NewCustomValidator creates a new instance of CustomValidator
func NewCustomValidator() (*CustomValidator, error) {
	v := validator.New()
	if err := v.RegisterValidation("certkey", ValidateCertAndKeyFiles); err != nil {
		return nil, fmt.Errorf("NewCustomValidator: error registering certkey validation: %v", err)
	}
	return &CustomValidator{v}, nil
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			return fmt.Errorf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			return fmt.Errorf("ValidateConfig: Unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	switch Globals.App.Type {
	case AppTypeImr:
		configsections["imrengine"] = config.Imr
	case AppTypeReporter:
		configsections["apiserver"] = config.ApiServer
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		configsections["dnsengine"] = config.DnsEngine
		// Validate catalog configuration if present
		if config.Catalog.ConfigGroups != nil || config.Catalog.MetaGroups != nil || config.Catalog.Policy.Zones.Add != "" || config.Catalog.Policy.Zones.Remove != "" {
			configsections["catalog"] = config.Catalog
		}
	default:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		// Validate catalog configuration if present
		if config.Catalog.ConfigGroups != nil || config.Catalog.MetaGroups != nil || config.Catalog.Policy.Zones.Add != "" || config.Catalog.Policy.Zones.Remove != "" {
			configsections["catalog"] = config.Catalog
		}
	}

	if _, err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		return fmt.Errorf("Config \"%s\" is missing required attributes:\n%v", cfgfile, err)
	}

	// Validate crypto key files if configured
	if err := ValidateCryptoFiles(&config); err != nil {
		return fmt.Errorf("Config \"%s\" crypto validation failed: %v", cfgfile, err)
	}

	// Validate agent.nameservers if configured (FQDN, outside autozone)
	if err := ValidateAgentNameservers(&config); err != nil {
		return fmt.Errorf("Config \"%s\" agent.local.nameservers validation failed: %v", cfgfile, err)
	}

	// Validate agent.supported_mechanisms if agent is configured
	if err := ValidateAgentSupportedMechanisms(&config); err != nil {
		return fmt.Errorf("Config \"%s\" agent.supported_mechanisms validation failed: %v", cfgfile, err)
	}

	// Validate database file is set for apps that require it
	if err := ValidateDatabaseFile(&config); err != nil {
		return fmt.Errorf("Config \"%s\" database validation failed: %v", cfgfile, err)
	}

	return nil
}

func ValidateZones(c *Config, cfgfile string) error {
	config := c

	var zones = make(map[string]interface{}, 5)

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for _, val := range config.Zones {
		zones["zone:"+val.Name] = val
	}

	if _, err := ValidateBySection(config, zones, cfgfile); err != nil {
		return fmt.Errorf("Config \"%s\" is missing required attributes:\n%v", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) (string, error) {
	// validate := validator.New()
	validate, err := NewCustomValidator()
	if err != nil {
		return "", fmt.Errorf("ValidateBySection: error creating custom validator: %v", err)
	}

	for k, data := range configsections {
		lgConfig.Info("validating config section", "app", strings.ToUpper(Globals.App.Name), "section", k)
		if err := validate.Struct(data); err != nil {
			// log.Printf("ValidateBySection ERROR: %q section failed validation: %v\ndata:\n%+v", k, err, data)
			return fmt.Sprintf("%s: Config %s, section %q: missing required attributes:\n%v",
				strings.ToUpper(Globals.App.Name), cfgfile, k, err), err
		}
	}
	return "", nil
}

// validateCertAndKeyFiles is the custom validation function
func ValidateCertAndKeyFiles(fl validator.FieldLevel) bool {
	certFile := fl.Field().String()
	keyFile := fl.Parent().FieldByName("KeyFile").String()
	lgConfig.Debug("validating cert and key files", "certFile", certFile, "keyFile", keyFile)

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		lgConfig.Error("error reading cert file", "err", err)
		return false
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		lgConfig.Error("error reading key file", "err", err)
		return false
	}

	// Load the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		lgConfig.Error("error loading certificate", "err", err)
		return false
	}

	// Parse the certificate
	certParsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		lgConfig.Error("error parsing certificate", "err", err)
		return false
	}

	// If this cert is self-signed, we need to add it to the cert pool
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	// Check if the certificate is valid
	if _, err := certParsed.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		lgConfig.Warn("error verifying certificate against custom cert pool (self-signed)", "err", err)

		// If cert verification against the cert pool fails, try again with the system cert pool
		certPool, err := x509.SystemCertPool()
		if err != nil {
			lgConfig.Error("error loading system cert pool", "err", err)
			return false
		}
		if _, err := certParsed.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
			lgConfig.Error("error verifying certificate against system cert pool", "err", err)
			return false
		}
	}

	return true
}

// ValidateConfigWithCustomValidator validates the config using the custom validator
// XXX: Not used at the moment.
func ValidateConfigWithCustomValidator(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			return fmt.Errorf("unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			return fmt.Errorf("unmarshal error: %v", err)
		}
	}

	// Use the custom validator for other validations
	validate, err := NewCustomValidator()
	if err != nil {
		return fmt.Errorf("ValidateConfigWithCustomValidator: error creating custom validator: %v", err)
	}
	if err := validate.Struct(&config); err != nil {
		return fmt.Errorf("config validation error: %v", err)
	}

	return nil
}

// ValidateAgentNameservers ensures agent.local.nameservers are non-empty and outside the agent autozone (no glue).
// Each entry is normalized to FQDN (dns.Fqdn) in place so the config never carries non-FQDN names.
func ValidateAgentNameservers(config *Config) error {
	if config.Agent == nil || len(config.Agent.Local.Nameservers) == 0 {
		return nil
	}
	zoneFqdn := dns.Fqdn(config.Agent.Identity)
	for i, ns := range config.Agent.Local.Nameservers {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		nsFqdn := dns.Fqdn(ns)
		if nsFqdn == "." {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		if dns.IsSubDomain(zoneFqdn, nsFqdn) {
			return fmt.Errorf("agent.local.nameservers: %q is inside the agent autozone %q (glue not supported)", nsFqdn, config.Agent.Identity)
		}
		config.Agent.Local.Nameservers[i] = nsFqdn
	}
	return nil
}

// ValidateAgentSupportedMechanisms validates agent.supported_mechanisms configuration.
// Requirements:
// - Must be non-empty (agent needs at least one communication mechanism)
// - Can only contain "api" and/or "dns" (case-insensitive)
// - Default if omitted: ["api", "dns"]
func ValidateAgentSupportedMechanisms(config *Config) error {
	if config.Agent == nil {
		return nil
	}

	mechanisms := config.Agent.SupportedMechanisms

	// If empty, will default to both transports in NewTransportManager
	// But we enforce explicit configuration - empty list is an error
	if len(mechanisms) == 0 {
		return fmt.Errorf("agent.supported_mechanisms cannot be empty - agent requires at least one transport mechanism (valid: \"api\", \"dns\")")
	}

	// Validate each mechanism and normalize to lowercase
	validMechanisms := map[string]bool{"api": true, "dns": true}
	seen := make(map[string]bool)

	for i, m := range mechanisms {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" {
			return fmt.Errorf("agent.supported_mechanisms: empty entry at index %d", i)
		}
		if !validMechanisms[m] {
			return fmt.Errorf("agent.supported_mechanisms: invalid value %q at index %d (valid: \"api\", \"dns\")", mechanisms[i], i)
		}
		if seen[m] {
			return fmt.Errorf("agent.supported_mechanisms: duplicate value %q", m)
		}
		seen[m] = true
		// Normalize to lowercase in place
		config.Agent.SupportedMechanisms[i] = m
	}

	return nil
}

// ValidateCryptoFiles validates that configured crypto key files exist and are readable.
// This is called during config validation to provide early feedback about missing files.
func ValidateCryptoFiles(config *Config) error {
	// Validate agent crypto files if configured (paths are trimmed inside validateFileExists)
	if config.Agent != nil && strings.TrimSpace(config.Agent.LongTermJosePrivKey) != "" {
		if err := validateFileExists(config.Agent.LongTermJosePrivKey, "agent private key"); err != nil {
			return err
		}

		// Check combiner public key if configured
		if config.Agent.Combiner != nil && strings.TrimSpace(config.Agent.Combiner.LongTermJosePubKey) != "" {
			if err := validateFileExists(config.Agent.Combiner.LongTermJosePubKey, "combiner public key (agent.combiner)"); err != nil {
				return err
			}
		}

		// Check peer agent public keys if configured
		if config.Agent.Peers != nil {
			for peerID, peerConf := range config.Agent.Peers {
				if strings.TrimSpace(peerConf.LongTermJosePubKey) != "" {
					if err := validateFileExists(peerConf.LongTermJosePubKey, fmt.Sprintf("peer agent %s public key", peerID)); err != nil {
						return err
					}
				}
			}
		}
	}

	// Validate combiner crypto files if configured
	if config.Combiner != nil && strings.TrimSpace(config.Combiner.LongTermJosePrivKey) != "" {
		if err := validateFileExists(config.Combiner.LongTermJosePrivKey, "combiner private key"); err != nil {
			return err
		}

		// Check agent public keys for all configured agents
		for _, agent := range config.Combiner.Agents {
			if strings.TrimSpace(agent.LongTermJosePubKey) != "" {
				label := fmt.Sprintf("agent public key (combiner.agents[%s])", agent.Identity)
				if err := validateFileExists(agent.LongTermJosePubKey, label); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// ValidateDatabaseFile validates that the database file path is set for apps that require it.
// If db.file is unset or empty, this function returns an error (hard fail).
func ValidateDatabaseFile(config *Config) error {
	// Only validate for app types that require a database
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner:
		dbFile := strings.TrimSpace(config.Db.File)
		if dbFile == "" {
			return fmt.Errorf("db.file is required but not set (must be specified in config)")
		}
		// Also check if it's just "." (which filepath.Clean("") returns)
		if dbFile == "." {
			return fmt.Errorf("db.file is unset (got '.' from empty path); must specify a valid database file path")
		}
	}
	return nil
}

// validateFileExists checks if a file exists and is readable.
// Path is trimmed so that config values with accidental trailing whitespace or newlines are handled correctly.
func validateFileExists(path, description string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%s path is empty", description)
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s file does not exist: %q", description, path)
		}
		return fmt.Errorf("cannot access %s file %q: %w", description, path, err)
	}
	return nil
}
