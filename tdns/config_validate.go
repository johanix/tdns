package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
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
func NewCustomValidator() *CustomValidator {
	v := validator.New()
	v.RegisterValidation("certkey", ValidateCertAndKeyFiles)
	return &CustomValidator{v}
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	configsections["service"] = config.Service
	configsections["db"] = config.Db
	configsections["apiserver"] = config.ApiServer
	configsections["dnsengine"] = config.DnsEngine

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateZones(c *Config, cfgfile string) error {
	config := c

	var zones = make(map[string]interface{}, 5)

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for zname, val := range config.Zones {
		zones["zone:"+zname] = val
	}

	if err := ValidateBySection(config, zones, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	// validate := validator.New()
	validate := NewCustomValidator()

	for k, data := range configsections {
		log.Printf("%s: Validating config for %s section\n", strings.ToUpper(config.App.Name), k)
		if err := validate.Struct(data); err != nil {
			log.Fatalf("%s: Config %s, section %s: missing required attributes:\n%v\n",
				strings.ToUpper(config.App.Name), cfgfile, k, err)
		}
	}
	return nil
}

// validateCertAndKeyFiles is the custom validation function
func ValidateCertAndKeyFiles(fl validator.FieldLevel) bool {
	certFile := fl.Field().String()
	keyFile := fl.Parent().FieldByName("KeyFile").String()
	log.Printf("ValidateCertAndKeyFiles: certFile: %s, keyFile: %s", certFile, keyFile)

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		log.Printf("ValidateCertAndKeyFiles: error reading cert file: %v", err)
		return false
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		log.Printf("ValidateCertAndKeyFiles: error reading key file: %v", err)
		return false
	}

	// Load the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("ValidateCertAndKeyFiles: error loading certificate: %v", err)
		return false
	}

	// Parse the certificate
	certParsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Printf("ValidateCertAndKeyFiles: error parsing certificate: %v", err)
		return false
	}

	// If this cert is self-signed, we need to add it to the cert pool
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	// Check if the certificate is valid
	if _, err := certParsed.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		log.Printf("ValidateCertAndKeyFiles: error verifying certificate against custom cert pool (for self-signed cert): %v", err)

		// If cert verification against the cert pool fails, try again with the system cert pool
		certPool, err := x509.SystemCertPool()
		if err != nil {
			log.Printf("ValidateCertAndKeyFiles: error loading system cert pool: %v", err)
			return false
		}
		if _, err := certParsed.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
			log.Printf("ValidateCertAndKeyFiles: error verifying certificate against system cert pool: %v", err)
			return false
		}
	}

	return true
}

// ValidateConfigWithCustomValidator validates the config using the custom validator
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
	validate := NewCustomValidator()
	if err := validate.Struct(&config); err != nil {
		return fmt.Errorf("config validation error: %v", err)
	}

	return nil
}