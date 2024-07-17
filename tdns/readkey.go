/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func sigLifetime(t time.Time) (uint32, uint32) {
	sigJitter := time.Duration(60 * time.Second)
	sigValidityInterval := time.Duration(5 * time.Minute)
	incep := uint32(t.Add(-sigJitter).Unix())
	expir := uint32(t.Add(sigValidityInterval).Add(sigJitter).Unix())
	return incep, expir
}

func SignMsg(m dns.Msg, name string, sak *Sig0ActiveKeys) (*dns.Msg, error) {

	if sak == nil || len(sak.Keys) == 0 {
		return nil, fmt.Errorf("SignMsg: no active SIG(0) keys available")
	}

	for _, key := range sak.Keys {
		sigrr := new(dns.SIG)
		sigrr.Hdr = dns.RR_Header{
			Name:   key.KeyRR.Header().Name,
			Rrtype: dns.TypeSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		}
		sigrr.RRSIG.KeyTag = key.KeyRR.DNSKEY.KeyTag()
		sigrr.RRSIG.Algorithm = key.KeyRR.DNSKEY.Algorithm
		sigrr.RRSIG.Inception, sigrr.RRSIG.Expiration = sigLifetime(time.Now())
		sigrr.RRSIG.SignerName = name

		_, err := sigrr.Sign(key.CS, &m)
		if err != nil {
			log.Printf("Error from sig.Sign(%s): %v", name, err)
			return nil, err
		}
		m.Extra = append(m.Extra, sigrr)
	}
	log.Printf("Signed msg: %s\n", m.String())

	return &m, nil
}

func SignRRset(rrset *RRset, name string, dak *DnssecActiveKeys) error {

	if dak == nil || len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
		return fmt.Errorf("SignRRset: no active DNSSEC keys available")
	}

	if len(rrset.RRs) == 0 {
		return fmt.Errorf("SignRRsetNG: rrset has no RRs")
	}

	var signingkeys []*PrivateKeyCache

	if rrset.RRs[0].Header().Rrtype == dns.TypeDNSKEY {
		signingkeys = dak.KSKs
	} else {
		signingkeys = dak.ZSKs
	}

	for _, key := range signingkeys {
		rrsig := new(dns.RRSIG)
		rrsig.Hdr = dns.RR_Header{
			Name:   key.DnskeyRR.Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    604800, // one week in seconds
		}
		rrsig.KeyTag = key.DnskeyRR.KeyTag()
		rrsig.Algorithm = key.DnskeyRR.Algorithm
		rrsig.Inception, rrsig.Expiration = sigLifetime(time.Now())
		rrsig.SignerName = name

		err := rrsig.Sign(key.CS, rrset.RRs)
		if err != nil {
			log.Printf("Error from rrsig.Sign(%s): %v", name, err)
			return err
		}

		rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
	}

	return nil
}

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

	file, err := os.Open(pubfile)
	if err != nil {
		return nil, fmt.Errorf("Error opening public key file '%s': %v", pubfile, err)
	}
	pubkeybytes, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key file '%s': %v", pubfile, err)
	}
	pubkey := string(pubkeybytes)

	file, err = os.Open(privfile)
	if err != nil {
		return nil, fmt.Errorf("Error opening private key file '%s': %v", privfile, err)
	}

	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key '%s': %v", pubkey, err)
	}

	var pkc PrivateKeyCache

	switch rr.(type) {
	case *dns.DNSKEY:
		rrk := rr.(*dns.DNSKEY)
		pkc.K, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
		if err != nil {
			return nil, fmt.Errorf("Error reading private key file '%s': %v", filename, err)
		}
		pkc.KeyType = dns.TypeDNSKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.DnskeyRR = *rrk
		pkc.PrivateKey = rrk.PrivateKeyString(pkc.K)
		fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	case *dns.KEY:
		rrk := rr.(*dns.KEY)
		pkc.K, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
		if err != nil {
			return nil, fmt.Errorf("Error reading private key file '%s': %v", filename, err)
		}
		pkc.KeyType = dns.TypeKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.KeyRR = *rrk
		pkc.PrivateKey = rrk.DNSKEY.PrivateKeyString(pkc.K)
		fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])

	default:
		return nil, fmt.Errorf("Error: rr is of type %v", "foo")
	}

	var bpk BindPrivateKey
	err = yaml.Unmarshal([]byte(pkc.PrivateKey), &bpk)
	if err != nil {
		return nil, fmt.Errorf("Error from yaml.Unmarshal(): %v", err)
	}

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

	return &pkc, err
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

func PrepareKeyCache(privkey, pubkey, algorithm string) (*PrivateKeyCache, error) {
	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return nil, fmt.Errorf("Error reading public key '%s': %v", pubkey, err)
	}

	src := fmt.Sprintf(`Private-key-format: v1.3
Algorithm: %d (%s)
PrivateKey: %s`, dns.StringToAlgorithm[algorithm], algorithm, privkey)

	var pkc PrivateKeyCache

	switch rr.(type) {
	case *dns.DNSKEY:
		rrk := rr.(*dns.DNSKEY)
		pkc.K, err = rrk.NewPrivateKey(src)
		if err != nil {
			return nil, fmt.Errorf("Error reading private key file '%s': %v", "foo", err)
		}
		pkc.KeyType = dns.TypeDNSKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.DnskeyRR = *rrk

	case *dns.KEY:
		rrk := rr.(*dns.KEY)
		pkc.K, err = rrk.NewPrivateKey(src)
		if err != nil {
			return nil, fmt.Errorf("PrepareKey: error parsing KEY private key: %v", err)
		}
		pkc.KeyType = dns.TypeKEY
		pkc.Algorithm = rrk.Algorithm
		pkc.KeyRR = *rrk

	default:
		return nil, fmt.Errorf("rr is of type %v", "foo")
	}

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
