/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
       "log"
       "strings"
       
       "github.com/miekg/dns"
)

var ValidTSIGAlgs = map[string]bool{
	dns.HmacSHA256: true,
//	dns.HmacSHA224: true,
//	dns.HmacSHA384: true,
	dns.HmacSHA512: true,
}

func ParseSignerAuth(astr, method string) AuthData {
     var keyname, secret string
     
	method = strings.ToLower(method)
	auth := AuthData{}

	switch method {
	case "rlddns":
	     fallthrough
	case "ddns":
		parts := strings.Split(astr, ":")
		if len(parts) == 2 { // alg not included
			auth.TSIGAlg = dns.HmacSHA256 // default
			keyname = parts[0]
			secret = parts[1]
		} else {
		        parts[0] = dns.Fqdn(parts[0])
			if _, ok := ValidTSIGAlgs[parts[0]]; ok {
				auth.TSIGAlg = parts[0]
				keyname = parts[1]
				secret = parts[2]
			} else {
				log.Fatalf("ParseSignerAuth: Unknown TSIG algorithm: '%s'. Terminating.",
							     parts[0])
			}
		}

		keyname := dns.Fqdn(keyname)
		if _, ok := dns.IsDomainName(keyname); !ok {
		   log.Fatalf("ParseSignerAuth: '%s' is not a legal TSIG key name. Terminating.",
			keyname)
		} else {
		  auth.TSIGName = keyname
		}

		err := validate.Var(secret, "required,base64")
		if err != nil {
		   log.Fatalf("ParseSignerAuth: TSIG secret is not a valid base64 encoded string. Terminating.")
		}
		auth.TSIGKey = secret
		
	case "rldesec":
	     fallthrough
	case "desec":
		// NYI
		
	default:
		log.Fatalf("Unknown signer method '%s'", method)
	}
	return auth
}
