/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"log"

	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type BindPrivateKey struct {
	Private_Key_Format string `yaml:"Private-key-format"`
	Algorithm          string `yaml:"Algorithm"`
	PrivateKey         string `yaml:"PrivateKey"`
}

func ReadPrivateKey(filename string) (*PrivateKeyCache, error) {

	if filename == "" {
		return nil, fmt.Errorf("Error: filename of SIG(0) or DNSSEC key not specified")
	}

	var basename, pubfile, privfile string

	if strings.HasSuffix(filename, ".key") {
		basename = strings.TrimSuffix(filename, ".key")
		pubfile = filename
		privfile = basename + ".private"
	} else if strings.HasSuffix(filename, ".private") {
		basename = strings.TrimSuffix(filename, ".private")
		privfile = filename
		pubfile = basename + ".key"
	} else {
		return nil, fmt.Errorf("Error: filename %s does not end in either .key or .private", filename)
	}

	_, err := os.Open(pubfile)
	if err != nil {
		return nil, fmt.Errorf("Error opening public key file '%s': %v", pubfile, err)
	}
	pubkeybytes, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key file '%s': %v", pubfile, err)
	}
	pubkey := string(pubkeybytes)
	_, err = dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key '%s': %v", pubkey, err)
	}

	_, err = os.Open(privfile)
	if err != nil {
		return nil, fmt.Errorf("Error opening private key file '%s': %v", privfile, err)
	}
	privkeybytes, err := os.ReadFile(privfile)
	if err != nil {
		return nil, fmt.Errorf("Error reading private key file '%s': %v", privfile, err)
	}
	privkey := string(privkeybytes)

	pkc, err := PrepareKeyCache(privkey, pubkey)
	if err != nil {
		return nil, fmt.Errorf("Error preparing key cache: %v", err)
	}
	return pkc, nil

	// var pkc PrivateKeyCache

	//	switch rr.(type) {
	//	case *dns.DNSKEY:
	//		rrk := rr.(*dns.DNSKEY)
	//		pkc.K, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
	//		if err != nil {
	//			return nil, fmt.Errorf("Error reading private key file '%s': %v", filename, err)
	//		}
	//		pkc.KeyType = dns.TypeDNSKEY
	//		pkc.Algorithm = rrk.Algorithm
	//		pkc.KeyId = rrk.KeyTag()
	//		pkc.DnskeyRR = *rrk
	//		pkc.PrivateKey = rrk.PrivateKeyString(pkc.K)

	//	case *dns.KEY:
	//		rrk := rr.(*dns.KEY)
	//		pkc.K, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
	//		if err != nil {
	//			return nil, fmt.Errorf("Error reading private key file '%s': %v", filename, err)
	//		}
	//		pkc.KeyType = dns.TypeKEY
	//		pkc.Algorithm = rrk.Algorithm
	//		pkc.KeyId = rrk.KeyTag()
	//		pkc.KeyRR = *rrk
	//		pkc.PrivateKey = rrk.PrivateKeyString(pkc.K)

	//	default:
	//		return nil, fmt.Errorf("Error: rr is of type %v", "foo")
	//	}

	//	var bpk BindPrivateKey
	//	err = yaml.Unmarshal([]byte(pkc.PrivateKey), &bpk)
	//	if err != nil {
	//		return nil, fmt.Errorf("Error from yaml.Unmarshal(): %v", err)
	//	}

	//	log.Printf("ReadPrivateKey: pkc.PrivateKey: %s", pkc.PrivateKey)
	//	log.Printf("ReadPrivateKey: bpk.PrivateKey: %s", bpk.PrivateKey)
	//	pkc.PrivateKey = bpk.PrivateKey

	//	switch pkc.Algorithm {
	//	case dns.RSASHA256, dns.RSASHA512:
	//		pkc.CS = pkc.K.(*rsa.PrivateKey)
	//	case dns.ED25519:
	//		pkc.CS = pkc.K.(ed25519.PrivateKey)
	//	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
	//		pkc.CS = pkc.K.(*ecdsa.PrivateKey)
	//	default:
	//		return nil, fmt.Errorf("Error: no support for algorithm %s yet", dns.AlgorithmToString[pkc.Algorithm])
	//	}

	// return &pkc, err
}

func ReadPubKey(filename string) (dns.RR, uint16, uint8, error) {

	if filename == "" {
		return nil, 0, 0, fmt.Errorf("Error: filename of key not specified")
	}

	var pubfile string

	if strings.HasSuffix(filename, ".key") {
		pubfile = filename
	} else {
		return nil, 0, 0, fmt.Errorf("Error: filename %s for a public key must end in '.key'", filename)
	}

	pubkeybytes, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("Error reading public key file %s: %v", pubfile, err)
	}
	pubkey := string(pubkeybytes)

	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("Error parsing public key '%s': %v", pubkey, err)
	}

	var ktype uint16
	var alg uint8

	switch rr.(type) {
	case *dns.DNSKEY:
		rrk := rr.(*dns.DNSKEY)
		ktype = dns.TypeDNSKEY
		alg = rrk.Algorithm
		// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	case *dns.KEY:
		rrk := rr.(*dns.KEY)
		ktype = dns.TypeKEY
		alg = rrk.Algorithm
		// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	default:
		return nil, 0, 0, fmt.Errorf("Error: rr is of type %v", "foo")
	}

	return rr, ktype, alg, err
}

func PrivKeyToBindFormat(privkey, algorithm string) (string, error) {
	alg, algexist := dns.StringToAlgorithm[strings.ToUpper(algorithm)]
	if !algexist {
		return "", fmt.Errorf("Error: algorithm %s is unknown", algorithm)
	}
	foo := fmt.Sprintf(
		`Private-key-format: v1.3
Algorithm: %d (%s)
PrivateKey: %s`,
		alg, algorithm, privkey)
	return foo, nil
}

// Note that the private key must be in the "BIND Private-key-format 1.3" format while
// the pubkey is in a string representation of either a DNS KEY RR or a DNSKEY RR.
// This function is extremely similar to the latter part of ReadPrivateKey() above, the
// difference being that here we read the private key from a string, whereas in the
// ReadPrivateKey() function we read it from a file. Yes, that should be unified.
func PrepareKeyCache(privkey, pubkey string) (*PrivateKeyCache, error) {
	log.Printf("PrepareKeyCache: privkey:\n%s\npubkey: %s", privkey, pubkey)
	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key '%s': %v", pubkey, err)
	}

	var pkc PrivateKeyCache

	switch rr.(type) {
	case *dns.DNSKEY:
		rrk := rr.(*dns.DNSKEY)
		pkc.K, err = rrk.NewPrivateKey(privkey)
		if err != nil {
			log.Printf("PrepareKeyCache: Error reading private key from string '%s': %v", privkey, err)
			return nil, fmt.Errorf("Error reading private key file '%s': %v", "foo", err)
		}
		pkc.KeyType = dns.TypeDNSKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.KeyId = rrk.KeyTag()
		pkc.DnskeyRR = *rrk

	case *dns.KEY:
		rrk := rr.(*dns.KEY)
		pkc.K, err = rrk.NewPrivateKey(privkey)
		if err != nil {
			return nil, fmt.Errorf("PrepareKeyCache: error parsing KEY private key: %v", err)
		}
		pkc.KeyType = dns.TypeKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.KeyId = rrk.KeyTag()
		pkc.KeyRR = *rrk

	default:
		return nil, fmt.Errorf("rr is of type %v", "foo")
	}

	var bpk BindPrivateKey
	// err = yaml.Unmarshal([]byte(pkc.PrivateKey), &bpk)
	err = yaml.Unmarshal([]byte(privkey), &bpk)
	if err != nil {
		return nil, fmt.Errorf("Error from yaml.Unmarshal(): %v", err)
	}

	pkc.PrivateKey = bpk.PrivateKey

	switch pkc.Algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		pkc.CS = pkc.K.(*rsa.PrivateKey)
	case dns.ED25519:
		pkc.CS = pkc.K.(ed25519.PrivateKey)
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pkc.CS = pkc.K.(*ecdsa.PrivateKey)
	default:
		return nil, fmt.Errorf("Error: no support for algorithm %s yet", dns.AlgorithmToString[pkc.Algorithm])
	}

	//	log.Printf("PrepareKeyCache: Zone: %s, algorithm: %s, keyid: %d,\nprivkey: %s,\npubkey: %s\npkc.K: %v",
	//		rr.Header().Name, dns.AlgorithmToString[pkc.Algorithm], pkc.KeyId, pkc.PrivateKey, pubkey, pkc.K)

	return &pkc, err
}

func ReadPubKeys(keydir string) (map[string]dns.KEY, error) {

	var keymap = make(map[string]dns.KEY, 5)

	if keydir == "" {
		return nil, fmt.Errorf("Error: key directory not specified in YAML config")
	}

	entries, err := os.ReadDir(keydir)
	if err != nil {
		return nil, fmt.Errorf("Error from os.ReadDir(%s): %v", keydir, err)
	}

	for _, f := range entries {
		fname := f.Name()
		fmt.Println(fname)

		if strings.HasSuffix(fname, ".key") {
			// basename = strings.TrimSuffix(filename, ".key")
			pubfile := keydir + "/" + fname
			_, err := os.Open(pubfile)
			if err != nil {
				return nil, fmt.Errorf("Error opening public key file '%s': %v",
					pubfile, err)
			}
			pubkeybytes, err := os.ReadFile(pubfile)
			if err != nil {
				return nil, fmt.Errorf("Error reading public key file '%s': %v",
					pubfile, err)
			}
			pubkey := string(pubkeybytes)
			rr, err := dns.NewRR(pubkey)
			if err != nil {
				return nil, fmt.Errorf("Error reading public key '%s': %v", pubkey, err)
			}

			switch rr.(type) {
			case *dns.KEY:
				rrk := rr.(*dns.KEY)
				keymap[rr.Header().Name] = *rrk
			default:
				return nil, fmt.Errorf("Error: rr is of type %v", "foo")
			}

		} else {
			fmt.Printf("File %s is not a public key file. Ignored.\n", fname)
		}
	}

	return keymap, nil
}
