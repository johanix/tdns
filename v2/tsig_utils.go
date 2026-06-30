/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// ParseTsigKeys parses the TSIG keys from the configuration and returns the number
// of valid keys loaded and the secrets map for dns.Client/dns.Server. Uses the
// same validateTsigKeySpec rules as the server LoadTsigKeys path.
func ParseTsigKeys(keyconf *KeyConf) (int, map[string]string) {
	if keyconf == nil || len(keyconf.Tsig) == 0 {
		return 0, nil
	}
	valid, _ := collectValidConfigTsigKeys(keyconf.Tsig)
	if len(valid) == 0 {
		return 0, nil
	}
	Globals.TsigKeys = make(map[string]*TsigDetails, len(valid))
	tsigSecrets := make(map[string]string, len(valid))
	for _, val := range valid {
		d := val
		Globals.TsigKeys[val.Name] = &d
		tsigSecrets[val.Name] = val.Secret
	}
	return len(valid), tsigSecrets
}
