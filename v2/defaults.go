/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import "fmt"

const (
	DogCfgFile = "/etc/axfr.net/dog.yaml"

	// Legacy constants for backward compatibility
	// New code should use GetDefaultConfigFile() instead
	DefaultCliCfgFile = "/etc/tdns/tdns-cli.yaml"
	// DefaultNcliCfgFile is tdns-ncli's own CLI config. It is deliberately not
	// tdns-cli's file: only tdns-ncli understands the role: key and the
	// instances it names. When tdns-ncli replaces tdns-cli, both the binary
	// name and this file name change.
	DefaultNcliCfgFile = "/etc/tdns/tdns-ncli.yaml"
	DefaultImrCfgFile  = "/etc/tdns/tdns-imr.yaml"

	DefaultAuthCfgFile = "/etc/tdns/tdns-auth.yaml"

	DefaultAgentCfgFile    = "/etc/tdns/tdns-agent.yaml"
	DefaultCombinerCfgFile = "/etc/tdns/tdns-combiner.yaml"
	DefaultReporterCfgFile = "/etc/tdns/tdns-reporter.yaml"
	DefaultScannerCfgFile  = "/etc/tdns/tdns-scanner.yaml"
	DefaultKdcCfgFile      = "/etc/tdns/tdns-kdc.yaml"
	DefaultKrsCfgFile      = "/etc/tdns/tdns-krs.yaml"
)

// GetDefaultConfigFile returns the default config file path based on Globals.App.Name.
// The path is constructed as /etc/tdns/{app-name}.yaml.
// If Globals.App.Name is empty, it returns an empty string.
func GetDefaultConfigFile() string {
	if Globals.App.Name == "" {
		return ""
	}
	return fmt.Sprintf("/etc/tdns/%s.yaml", Globals.App.Name)
}
