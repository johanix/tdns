/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// ParseTsigKeys parses the TSIG keys from the configuration and returns the number of keys and the secrets
// in the format expected by the dns.Server and the dns.Client. It also stores the keys with more details
// in the tdns.Globals struct.
func ParseTsigKeys(keyconf *KeyConf) (int, map[string]string) {
	numtsigs := len(keyconf.Tsig)
	var tsigSecrets map[string]string
	//fmt.Printf("numtsigs: %d\n", numtsigs)
	if numtsigs > 0 {
		Globals.TsigKeys = make(map[string]*TsigDetails, numtsigs)
		tsigSecrets = make(map[string]string, numtsigs)
		for _, val := range keyconf.Tsig {
			Globals.TsigKeys[val.Name] = &TsigDetails{
				Name:      val.Name,
				Algorithm: val.Algorithm,
				Secret:    val.Secret,
			}
			tsigSecrets[val.Name] = val.Secret
		}
		// fmt.Printf("tdns.Globals.TsigKeys: %+v\n", tdns.Globals.TsigKeys)
		return numtsigs, tsigSecrets
	}
	return numtsigs, nil
}
