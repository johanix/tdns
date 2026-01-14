/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
		return nil, fmt.Errorf("error: filename of SIG(0) or DNSSEC key not specified")
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
		return nil, fmt.Errorf("error: filename %s does not end in either .key or .private", filename)
	}

	_, err := os.Stat(pubfile)
	if err != nil {
		return nil, fmt.Errorf("error opening public key file '%s': %v", pubfile, err)
	}
	pubkeybytes, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file '%s': %v", pubfile, err)
	}
	pubkey := string(pubkeybytes)
	_, err = dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("error reading public key '%s': %v", pubkey, err)
	}

	_, err = os.Stat(privfile)
	if err != nil {
		return nil, fmt.Errorf("error opening private key file '%s': %v", privfile, err)
	}
	privkeybytes, err := os.ReadFile(privfile)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file '%s': %v", privfile, err)
	}
	privkey := string(privkeybytes)

	pkc, err := PrepareKeyCache(privkey, pubkey)
	if err != nil {
		return nil, fmt.Errorf("error preparing key cache: %v", err)
	}
	return pkc, nil

	// var pkc PrivateKeyCache

	//	switch rr.(type) {
	//	case *dns.DNSKEY:
	//		rrk := rr.(*dns.DNSKEY)
	//		pkc.K, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
	//		if err != nil {
	//			return nil, fmt.Errorf("error reading private key file '%s': %v", filename, err)
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
	//			return nil, fmt.Errorf("error reading private key file '%s': %v", filename, err)
	//		}
	//		pkc.KeyType = dns.TypeKEY
	//		pkc.Algorithm = rrk.Algorithm
	//		pkc.KeyId = rrk.KeyTag()
	//		pkc.KeyRR = *rrk
	//		pkc.PrivateKey = rrk.PrivateKeyString(pkc.K)

	//	default:
	//		return nil, fmt.Errorf("error: rr is of type %v", "foo")
	//	}

	//	var bpk BindPrivateKey
	//	err = yaml.Unmarshal([]byte(pkc.PrivateKey), &bpk)
	//	if err != nil {
	//		return nil, fmt.Errorf("error from yaml.Unmarshal(): %v", err)
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
	//		return nil, fmt.Errorf("error: no support for algorithm %s yet", dns.AlgorithmToString[pkc.Algorithm])
	//	}

	// return &pkc, err
}

func ReadPubKey(filename string) (dns.RR, uint16, uint8, error) {

	if filename == "" {
		return nil, 0, 0, fmt.Errorf("error: filename of key not specified")
	}

	var pubfile string

	if strings.HasSuffix(filename, ".key") {
		pubfile = filename
	} else {
		return nil, 0, 0, fmt.Errorf("error: filename %s for a public key must end in '.key'", filename)
	}

	pubkeybytes, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("error reading public key file %s: %v", pubfile, err)
	}
	pubkey := string(pubkeybytes)

	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("error parsing public key '%s': %v", pubkey, err)
	}

	var ktype uint16
	var alg uint8

	switch rr := rr.(type) {
	case *dns.DNSKEY:
		ktype = dns.TypeDNSKEY
		alg = rr.Algorithm
		// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	case *dns.KEY:
		ktype = dns.TypeKEY
		alg = rr.Algorithm
		// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	default:
		return nil, 0, 0, fmt.Errorf("error: rr is of type %v", "foo")
	}

	return rr, ktype, alg, err
}

func PrivKeyToBindFormat(privkey, algorithm string) (string, error) {
	alg, algexist := dns.StringToAlgorithm[strings.ToUpper(algorithm)]
	if !algexist {
		return "", fmt.Errorf("error: algorithm %s is unknown", algorithm)
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
// PrepareKeyCache creates a PrivateKeyCache from a private-key string and a public-key RR string.
// It parses the public-key RR to determine key type, algorithm, and key tag, parses the private-key
// material from the provided privkey string (accepts either PKCS#8 PEM format or BIND Private-key-format
// YAML with a `PrivateKey` field), and populates the returned cache with the parsed crypto.PrivateKey (K),
// a concrete key select (CS) of the appropriate type, the RD type (KEY/DNSKEY), Algorithm, KeyId,
// and the corresponding DNS RR (DnskeyRR or KeyRR).
//
// The function returns an error if the public-key RR cannot be parsed, if the private key cannot be
// created from the provided strings, if the privkey YAML cannot be unmarshaled, or if the algorithm
// PrepareKeyCache creates a PrivateKeyCache from a private-key string (BIND YAML format)
// and a public-key DNS RR string.
//
// PrepareKeyCache parses the public-key RR and the private-key (expected in BIND
// private-key-format YAML), validates supported RR types (DNSKEY or KEY) and
// supported DNSSEC algorithms, and populates the returned PrivateKeyCache with
// key metadata, the parsed private key, and a concrete crypto key value usable
// for signing. It returns an error if parsing fails or the RR type/algorithm is
// not supported.

func PrepareKeyCache(privkey, pubkey string) (*PrivateKeyCache, error) {
	// log.Printf("PrepareKeyCache: privkey:\n%s\npubkey: %s", privkey, pubkey)
	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("error reading public key '%s': %v", pubkey, err)
	}

	var pkc PrivateKeyCache
	var privKeyBase64 string // For storing the base64 private key material

	// Check if privkey is in PEM format
	if IsPEMFormat(privkey) {
		// PEM format: parse directly to crypto.PrivateKey
		pkc.K, err = PEMToPrivateKey(privkey)
		if err != nil {
			return nil, fmt.Errorf("error parsing PEM private key: %v", err)
		}

		// Convert to BIND format for the PrivateKey field (for backward compatibility)
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			bindFormat := rr.PrivateKeyString(pkc.K)
			// Extract the base64 part from BIND format
			var bpk BindPrivateKey
			err = yaml.Unmarshal([]byte(bindFormat), &bpk)
			if err != nil {
				return nil, fmt.Errorf("error converting PEM to BIND format: %v", err)
			}
			privKeyBase64 = bpk.PrivateKey
			pkc.KeyType = dns.TypeDNSKEY
			pkc.Algorithm = rr.Algorithm
			pkc.KeyId = rr.KeyTag()
			pkc.DnskeyRR = *rr

		case *dns.KEY:
			bindFormat := rr.PrivateKeyString(pkc.K)
			// Extract the base64 part from BIND format
			var bpk BindPrivateKey
			err = yaml.Unmarshal([]byte(bindFormat), &bpk)
			if err != nil {
				return nil, fmt.Errorf("error converting PEM to BIND format: %v", err)
			}
			privKeyBase64 = bpk.PrivateKey
			pkc.KeyType = dns.TypeKEY
			pkc.Algorithm = rr.Algorithm
			pkc.KeyId = rr.KeyTag()
			pkc.KeyRR = *rr

		default:
			return nil, fmt.Errorf("rr is of type %v", "foo")
		}
	} else {
		// BIND format: use existing logic
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			pkc.K, err = rr.NewPrivateKey(privkey)
			if err != nil {
				log.Printf("PrepareKeyCache: Error reading private key from string '%s': %v", privkey, err)
				return nil, fmt.Errorf("error reading private key %q: %v", "**REDACTED**", err)
			}
			pkc.KeyType = dns.TypeDNSKEY
			pkc.Algorithm = rr.Algorithm
			pkc.KeyId = rr.KeyTag()
			pkc.DnskeyRR = *rr

		case *dns.KEY:
			pkc.K, err = rr.NewPrivateKey(privkey)
			if err != nil {
				return nil, fmt.Errorf("PrepareKeyCache: error parsing KEY private key: %v", err)
			}
			pkc.KeyType = dns.TypeKEY
			pkc.Algorithm = rr.Algorithm
			pkc.KeyId = rr.KeyTag()
			pkc.KeyRR = *rr

		default:
			return nil, fmt.Errorf("rr is of type %v", "foo")
		}

		// Extract PrivateKey field from BIND format YAML
		var bpk BindPrivateKey
		err = yaml.Unmarshal([]byte(privkey), &bpk)
		if err != nil {
			// log.Printf("PrepareKeyCache: Error from yaml.Unmarshal(): %v", err)
			return nil, fmt.Errorf("error from yaml.Unmarshal(): %v", err)
		}
		privKeyBase64 = bpk.PrivateKey
	}

	pkc.PrivateKey = privKeyBase64

	switch pkc.Algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		pkc.CS = pkc.K.(*rsa.PrivateKey)
	case dns.ED25519:
		pkc.CS = pkc.K.(ed25519.PrivateKey)
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pkc.CS = pkc.K.(*ecdsa.PrivateKey)
	default:
		return nil, fmt.Errorf("error: no support for algorithm %s yet", dns.AlgorithmToString[pkc.Algorithm])
	}

	//	log.Printf("PrepareKeyCache: Zone: %s, algorithm: %s, keyid: %d,\nprivkey: %s,\npubkey: %s\npkc.K: %v",
	//		rr.Header().Name, dns.AlgorithmToString[pkc.Algorithm], pkc.KeyId, pkc.PrivateKey, pubkey, pkc.K)

	return &pkc, err
}

// PrivateKeyToPEM converts a crypto.PrivateKey to PKCS#8 PEM format.
// PrivateKeyToPEM converts a crypto.PrivateKey to a PKCS#8 PEM-encoded string.
// PrivateKeyToPEM converts a crypto.PrivateKey into a PKCS#8 PEM-encoded string.
//
// It returns the PEM-formatted private key. An error is returned if the provided
// private key is nil or if marshaling the key to PKCS#8 DER fails.
func PrivateKeyToPEM(privkey crypto.PrivateKey) (string, error) {
	if privkey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// Marshal the private key to PKCS#8 DER format
	derBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS#8: %v", err)
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

// PEMToPrivateKey parses pemData as a PKCS#8 PEM-encoded private key and returns it as a crypto.PrivateKey.
//
// The input must contain a PEM block of type "PRIVATE KEY" encoded in PKCS#8. Returns an error if the input
// PEMToPrivateKey parses a PKCS#8 PEM-encoded private key and returns the corresponding crypto.PrivateKey.
// It returns an error if pemData is empty, if no PEM block can be decoded, if the PEM block type is not "PRIVATE KEY", or if PKCS#8 parsing fails.
func PEMToPrivateKey(pemData string) (crypto.PrivateKey, error) {
	if pemData == "" {
		return nil, fmt.Errorf("PEM data is empty")
	}

	// Decode PEM block
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block type is %q, expected \"PRIVATE KEY\"", block.Type)
	}

	// Parse PKCS#8 private key
	privkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
	}

	return privkey, nil
}

// IsPEMFormat detects if a stored private key is in PKCS#8 PEM format (new format).
// It returns true if the data decodes to a PEM block of type "PRIVATE KEY"; otherwise false.
func IsPEMFormat(keyData string) bool {
	if keyData == "" {
		return false
	}
	block, _ := pem.Decode([]byte(keyData))
	return block != nil && block.Type == "PRIVATE KEY"
}

// ParsePrivateKeyFromDB parses a private key from the database, detecting whether
// it's in old BIND format or new PEM format, and returns a crypto.PrivateKey.
// ParsePrivateKeyFromDB parses a private key stored in the database, accepting either
// PKCS#8 PEM (new) or legacy BIND private-key formats.
//
// It returns the parsed crypto.PrivateKey, the DNSSEC algorithm numeric code, and a
// BIND-format private-key string suitable for backward compatibility. An error is
// ParsePrivateKeyFromDB parses a stored private key (either PKCS#8 PEM or legacy BIND format)
// and returns the crypto.PrivateKey, the DNSSEC algorithm numeric code, and a BIND-format
// private-key string suitable for use with PrepareKeyCache.
//
// If the input `privatekey` is detected as a PKCS#8 PEM, the function parses it and derives
// a BIND-format private-key string from `keyrrstr` (a DNSKEY/KEY RR string) for compatibility.
// If `privatekey` is not PEM, it is treated as the legacy BIND private-key material and is
// wrapped into a full BIND-format string. The `algorithm` parameter is validated and converted
// to the corresponding DNSSEC algorithm code.
//
// Returns an error if the algorithm is unknown, PEM decoding/parsing fails, the public key RR
// cannot be parsed, conversion to BIND format fails, or the legacy BIND parsing logic fails.
func ParsePrivateKeyFromDB(privatekey, algorithm, keyrrstr string) (crypto.PrivateKey, uint8, string, error) {
	var privkey crypto.PrivateKey
	var alg uint8
	var bindFormat string
	var err error

	// Parse algorithm string to uint8
	alg, ok := dns.StringToAlgorithm[strings.ToUpper(algorithm)]
	if !ok {
		return nil, 0, "", fmt.Errorf("unknown algorithm: %s", algorithm)
	}

	if IsPEMFormat(privatekey) {
		// New format: PKCS#8 PEM
		privkey, err = PEMToPrivateKey(privatekey)
		if err != nil {
			return nil, 0, "", fmt.Errorf("failed to parse PEM private key: %v", err)
		}

		// For backward compatibility, we need to create a BIND format string
		// so that PrepareKeyCache can work. We'll parse the public key RR to get the algorithm.
		rr, err := dns.NewRR(keyrrstr)
		if err != nil {
			return nil, 0, "", fmt.Errorf("failed to parse public key RR: %v", err)
		}

		var bindPrivKeyStr string
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			bindPrivKeyStr = rr.PrivateKeyString(privkey)
		case *dns.KEY:
			bindPrivKeyStr = rr.PrivateKeyString(privkey)
		default:
			return nil, 0, "", fmt.Errorf("unexpected RR type: %T", rr)
		}

		// PrivateKeyString() already returns the full BIND format string (with headers),
		// so we should use it directly instead of wrapping it again with PrivKeyToBindFormat
		bindFormat = bindPrivKeyStr
	} else {
		// Old format: BIND format
		// privatekey is just the base64 string, need to wrap it in BIND format
		bindFormat, err = PrivKeyToBindFormat(privatekey, algorithm)
		if err != nil {
			return nil, 0, "", fmt.Errorf("failed to convert to BIND format: %v", err)
		}

		// Parse using existing PrepareKeyCache logic
		pkc, err := PrepareKeyCache(bindFormat, keyrrstr)
		if err != nil {
			return nil, 0, "", fmt.Errorf("failed to prepare key cache: %v", err)
		}

		privkey = pkc.K
		// alg is already set from the algorithm parameter above
	}

	return privkey, alg, bindFormat, nil
}

// ReadPubKeys reads all ".key" public key files in the given directory and
// returns a mapping from each key's owner name to its dns.KEY record.
//
// If keydir is empty, the function returns an error. Only files with the
// ".key" suffix are processed; other files are ignored. Each processed file is
// parsed as a DNS RR and must be of type KEY; parse failures, unexpected RR
// ReadPubKeys reads all files with the ".key" suffix in the provided directory,
// parses each as a DNS KEY RR, and returns a map from the RR owner name to the
// dns.KEY value.
//
// The keydir parameter is the path to the directory containing public key files.
// Non-".key" files are ignored. If any filesystem operation fails or a file
// cannot be parsed as a DNS KEY RR, an error is returned.
func ReadPubKeys(keydir string) (map[string]dns.KEY, error) {

	var keymap = make(map[string]dns.KEY, 5)

	if keydir == "" {
		return nil, fmt.Errorf("error: key directory not specified in YAML config")
	}

	entries, err := os.ReadDir(keydir)
	if err != nil {
		return nil, fmt.Errorf("error from os.ReadDir(%s): %v", keydir, err)
	}

	for _, f := range entries {
		fname := f.Name()
		fmt.Println(fname)

		if strings.HasSuffix(fname, ".key") {
			// basename = strings.TrimSuffix(filename, ".key")
			pubfile := keydir + "/" + fname
			_, err = os.Stat(pubfile)
			if err != nil {
				return nil, fmt.Errorf("error opening public key file '%s': %v",
					pubfile, err)
			}
			pubkeybytes, err := os.ReadFile(pubfile)
			if err != nil {
				return nil, fmt.Errorf("error reading public key file '%s': %v",
					pubfile, err)
			}
			pubkey := string(pubkeybytes)
			rr, err := dns.NewRR(pubkey)
			if err != nil {
				return nil, fmt.Errorf("error reading public key '%s': %v", pubkey, err)
			}

			switch rr := rr.(type) {
			case *dns.KEY:
				keymap[rr.Header().Name] = *rr
			default:
				return nil, fmt.Errorf("error: rr is of type %v", "foo")
			}

		} else {
			fmt.Printf("File %s is not a public key file. Ignored.\n", fname)
		}
	}

	return keymap, nil
}
