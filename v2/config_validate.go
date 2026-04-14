package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
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
	case AppTypeAuth, AppTypeAgent:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		configsections["dnsengine"] = config.DnsEngine
		// Validate catalog configuration if present
		if config.Catalog != nil && (config.Catalog.ConfigGroups != nil || config.Catalog.MetaGroups != nil || config.Catalog.Policy.Zones.Add != "" || config.Catalog.Policy.Zones.Remove != "") {
			configsections["catalog"] = config.Catalog
		}
	default:
		configsections["service"] = config.Service
		configsections["db"] = config.Db
		configsections["apiserver"] = config.ApiServer
		configsections["dnsengine"] = config.DnsEngine
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
