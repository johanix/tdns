package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
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

// validateZonePeersAndAcls checks the per-zone peer lists and ACLs the daemon
// parses at zone load, so a shape error surfaces here instead of quarantining
// the zone after startup.
//
// This is the gap that let `notify:` and `downstreams:` be confused for one
// another. They take different shapes -- notify:/primaries: are {addr, key},
// downstreams:/allow-notify: are {prefix, key} -- and mapstructure silently
// ignores a key the target struct does not have. So writing
//
//	downstreams:
//	   - addr: "192.0.2.1:53"
//
// decodes to an AclEntry with an EMPTY prefix, validates clean, and then fails
// at zone load with `acl entry "": bad ip-spec ""`. The zone is quarantined and
// answers nothing, while `config check` reported no problems at all.
//
// ValidateACL is the daemon's own function, so the two cannot disagree about
// what a valid entry is. Key names are accepted unconditionally here: a key may
// legitimately live in the keystore database rather than in keys.tsig, and the
// checker reads a file.
func validateZonePeersAndAcls(config *Config) error {
	anyKey := func(string) bool { return true }

	check := func(kind, name string, zc *ZoneConf) error {
		for _, acl := range []struct {
			field string
			list  []AclEntry
		}{
			{"downstreams", zc.Downstreams},
			{"allow-notify", zc.AllowNotify},
		} {
			if err := ValidateACL(acl.list, anyKey); err != nil {
				return fmt.Errorf("%s %q: %s: %v (this list takes { prefix: <ip-spec>, key: ... };"+
					" { addr: ... } belongs in notify:/primaries:)", kind, name, acl.field, err)
			}
		}
		for _, peers := range []struct {
			field string
			list  []PeerConf
		}{
			{"notify", zc.Notify},
			{"primaries", zc.Primaries},
		} {
			for i, p := range peers.list {
				// A reference entry carries ids instead of an address, and a
				// legacy bare string is quarantined per-zone rather than here.
				if len(p.PeersRef) > 0 || p.Legacy != "" {
					continue
				}
				if strings.TrimSpace(p.Addr) == "" {
					return fmt.Errorf("%s %q: %s entry %d has no addr: (this list takes"+
						" { addr: <host:port>, key: ... }; { prefix: ... } belongs in"+
						" downstreams:/allow-notify:)", kind, name, peers.field, i+1)
				}
			}
		}
		return nil
	}

	for i := range config.Zones {
		if err := check("zone", config.Zones[i].Name, &config.Zones[i]); err != nil {
			return err
		}
	}
	for i := range config.Templates {
		if err := check("template", config.Templates[i].Name, &config.Templates[i]); err != nil {
			return err
		}
	}
	return nil
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	// Decode through the DAEMON's pipeline, not viper's.
	//
	// This function answers exactly one question -- "would the daemon start on
	// this file?" -- so it has to decode the file the way the daemon does.
	// viper.Unmarshal does not: it sets WeaklyTypedInput and adds
	// StringToSlice/StringToTimeDuration hooks that ParseConfig's decoder has
	// no equivalent of. A file writing `schemes: notify` where the struct wants
	// a slice, or `port: "5354"` where it wants a uint16, therefore passed
	// validation and then failed at startup -- the worst direction for a
	// checker to be wrong in, because it hands the operator a green light.
	//
	// Using the file path also picks up the daemon's include processing and
	// transfer-alias normalisation, which viper knows nothing about.
	if cfgfile != "" {
		if _, _, _, err := decodeConfigFile(cfgfile, &config); err != nil {
			return fmt.Errorf("ValidateConfig: %v", err)
		}
	} else if v != nil {
		// No file to re-read (an in-memory viper). Decode its settings through
		// the same strict decoder, so the strictness is identical even though
		// the include/alias front end cannot run.
		var md mapstructure.Metadata
		if err := decodeConfigMap(v.AllSettings(), &config, &md); err != nil {
			return fmt.Errorf("ValidateConfig: %v", err)
		}
	} else {
		return fmt.Errorf("ValidateConfig: neither a config file nor a viper instance to validate")
	}

	// Same dynamiczones: value validation the daemon loader applies
	// (ParseConfig), so `config check` and the daemon cannot disagree.
	if err := config.DynamicZones.Validate(); err != nil {
		return fmt.Errorf("ValidateConfig: %v", err)
	}

	// Global + every zone + every template, via the same function the daemon
	// loader uses, so this command cannot pass what startup would refuse.
	if err := ValidateAllTransferSrc(&config); err != nil {
		return fmt.Errorf("ValidateConfig: %v", err)
	}

	// Per-zone peer lists and ACLs, via the daemon's own ValidateACL.
	if err := validateZonePeersAndAcls(&config); err != nil {
		return fmt.Errorf("ValidateConfig: %v", err)
	}

	// Same loopback rule the daemon applies to the imr debug window.
	if err := validateImrDebugAddress(config.Listeners.ImrDebugAddress); err != nil {
		return fmt.Errorf("ValidateConfig: %v", err)
	}

	if err := config.DelegationSync.Validate(); err != nil {
		return fmt.Errorf("ValidateConfig: %v", err)
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	switch Globals.App.Type {
	case AppTypeImr:
		configsections["imrengine"] = config.Imr
		configsections["listeners"] = config.Listeners
	case AppTypeReporter:
		configsections["apiserver"] = config.ApiServer
	case AppTypeAuth, AppTypeAgent:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		configsections["listeners"] = config.Listeners
		configsections["authengine"] = config.AuthEngine
		// Validate catalog configuration if present
		if config.Catalog != nil && (config.Catalog.ConfigGroups != nil || config.Catalog.MetaGroups != nil || config.Catalog.Policy.Zones.Add != "" || config.Catalog.Policy.Zones.Remove != "") {
			configsections["catalog"] = config.Catalog
		}
	default:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		configsections["listeners"] = config.Listeners
		configsections["authengine"] = config.AuthEngine
		// Validate catalog configuration if present
		if config.Catalog != nil && (config.Catalog.ConfigGroups != nil || config.Catalog.MetaGroups != nil || config.Catalog.Policy.Zones.Add != "" || config.Catalog.Policy.Zones.Remove != "") {
			configsections["catalog"] = config.Catalog
		}
	}

	if _, err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		return fmt.Errorf("Config \"%s\" is missing required attributes:\n%v", cfgfile, err)
	}

	// Validate database file is set for tdns apps that require it
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeScanner:
		if err := ValidateDatabaseFile(&config); err != nil {
			return fmt.Errorf("Config \"%s\" database validation failed: %v", cfgfile, err)
		}
	}

	// Run external validators registered by MP apps (tdns-mp).
	if config.Internal.PostValidateConfigHook != nil {
		if err := config.Internal.PostValidateConfigHook(&config); err != nil {
			return fmt.Errorf("Config \"%s\" post-validation hook failed: %v", cfgfile, err)
		}
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

// ValidateDatabaseFile checks that db.file is set to a non-empty path.
func ValidateDatabaseFile(config *Config) error {
	dbFile := strings.TrimSpace(config.Db.File)
	if dbFile == "" {
		return fmt.Errorf("db.file is required but not set (must be specified in config)")
	}
	if dbFile == "." {
		return fmt.Errorf("db.file is unset (got '.' from empty path); must specify a valid database file path")
	}
	return nil
}
