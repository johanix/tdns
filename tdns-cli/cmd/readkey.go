/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
//	"crypto"
//	"crypto/ecdsa"
//	"crypto/ed25519"
//	"crypto/rsa"

	"fmt"
	"log"
//	"os"
//	"strings"
//	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/johanix/tdns/tdns"
//	"gopkg.in/yaml.v3"
)

var filename string

var readkeyCmd = &cobra.Command{
	Use:   "readkey",
	Short: "read a DNS key, either a KEY or DNSKEY. arg is either the .key or the .private file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if filename == "" {
			log.Fatalf("Error: filename with key not specified")
		}

		k, cs, rr, ktype, privkey, alg, err := tdns.ReadKey(filename)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", filename, err)
		}

//		var bpk BindPrivateKey
//		err = yaml.Unmarshal([]byte(privkey), &bpk)
//		if err != nil {
//		   log.Fatal(err)
//		}
		fmt.Printf("PrivKey: %s\n", privkey)
		
		fmt.Printf("PubKey: %s\n", rr.String())
		fmt.Printf("PrivKey (%s): %v\n", ktype, k)
		fmt.Printf("crypto.Signer: %v\n", cs)
		fmt.Printf("cs.Public(): %v\n", cs.Public())
		fmt.Printf("alg: %s\n", dns.AlgorithmToString[alg])
		
	},
}

func init() {
	rootCmd.AddCommand(readkeyCmd)
	// rootCmd.AddCommand(signMsgCmd)
	readkeyCmd.Flags().StringVarP(&filename, "keyfile", "f", "", "Name of private key file")
}

// func sigLifetime(t time.Time) (uint32, uint32) {
// 	sigJitter := time.Duration(60 * time.Second)
// 	sigValidityInterval := time.Duration(5 * time.Minute)
// 	incep := uint32(t.Add(-sigJitter).Unix())
// 	expir := uint32(t.Add(sigValidityInterval).Add(sigJitter).Unix())
// 	return incep, expir
// }

// func SignMsgNG(m dns.Msg, name string, cs crypto.Signer, keyrr *dns.KEY) (dns.Msg, error) {
// 
// 	sigrr := new(dns.SIG)
// 	sigrr.Hdr = dns.RR_Header{
// 		Name:   keyrr.Header().Name,
// 		Rrtype: dns.TypeSIG,
// 		Class:  dns.ClassINET,
// 		Ttl:    300,
// 	}
// 	sigrr.RRSIG.KeyTag = keyrr.DNSKEY.KeyTag()
// 	sigrr.RRSIG.Algorithm = keyrr.DNSKEY.Algorithm
// 	sigrr.RRSIG.Inception, sigrr.RRSIG.Expiration = sigLifetime(time.Now())
// 	sigrr.RRSIG.SignerName = name
// 
// 	fmt.Printf("SIG pre-signing: %v\n", sigrr.String())
// 	fmt.Printf("Msg additional pre-signing: %d\n", len(m.Extra))
// 
// 	res, err := sigrr.Sign(cs, &m)
// 	if err != nil {
// 		log.Fatalf("Error from sig.Sign: %v", err)
// 	}
// 	// fmt.Printf("Res: %s\n", string(res))
// 	fmt.Printf("len(signed msg): %d\n", len(res))
// 	m.Extra = append(m.Extra, sigrr)
// 
// 	fmt.Printf("len(msg+sig): %d\n", m.Len())
// 
// 	fmt.Printf("Signed msg: %s\n", m.String())
// 	// fmt.Printf("Completed SIG RR: %s\n", sigrr.String())
// 
// 	return m, nil
// }

// func ReadKey(filename string) (crypto.PrivateKey, crypto.Signer, dns.RR, string, error) {
// 
// 	if filename == "" {
// 		log.Fatalf("Error: filename of key not specified")
// 	}
// 
// 	var basename, pubfile, privfile string
// 
// 	if strings.HasSuffix(filename, ".key") {
// 		basename = strings.TrimSuffix(filename, ".key")
// 		pubfile = filename
// 		privfile = basename + ".private"
// 	} else if strings.HasSuffix(filename, ".private") {
// 		basename = strings.TrimSuffix(filename, ".private")
// 		privfile = filename
// 		pubfile = basename + ".key"
// 	} else {
// 		log.Fatalf("Error: filename %s does not end in either .key or .private", filename)
// 	}
// 
// 	file, err := os.Open(pubfile)
// 	if err != nil {
// 		log.Fatalf("Error opening public key file '%s': %v",
// 			pubfile, err)
// 	}
// 	pubkeybytes, err := os.ReadFile(pubfile)
// 	if err != nil {
// 		log.Fatalf("Error reading public key file '%s': %v",
// 			pubfile, err)
// 	}
// 	pubkey := string(pubkeybytes)
// 
// 	file, err = os.Open(privfile)
// 	if err != nil {
// 		log.Fatalf("Error opening private key file '%s': %v",
// 			privfile, err)
// 	}
// 
// 	rr, err := dns.NewRR(pubkey)
// 	if err != nil {
// 		log.Fatalf("Error reading public key '%s': %v",
// 			pubkey, err)
// 	}
// 
// 	var k crypto.PrivateKey
// 	var cs crypto.Signer
// 	var ktype string
// 	var alg uint8
// 
// 	// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rr.Algorithm])
// 
// 	switch rr.(type) {
// 	case *dns.DNSKEY:
// 		rrk := rr.(*dns.DNSKEY)
// 		k, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
// 		if err != nil {
// 			log.Fatalf("Error reading private key file '%s': %v", filename, err)
// 		}
// 		ktype = "DNSKEY"
// 		alg = rrk.Algorithm
// 		fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])
// 	case *dns.KEY:
// 		rrk := rr.(*dns.KEY)
// 		k, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
// 		ktype = "KEY"
// 		alg = rrk.Algorithm
// 		fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])
// 	default:
// 		log.Fatalf("Error: rr is of type %v", "foo")
// 	}
// 
// 	switch alg {
// 	case dns.RSASHA256, dns.RSASHA512:
// 		cs = k.(*rsa.PrivateKey)
// 	case dns.ED25519:
// 		cs = k.(ed25519.PrivateKey)
// 	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
// 		cs = k.(*ecdsa.PrivateKey)
// 	default:
// 		log.Fatalf("Error: no support for algorithm %s yet", dns.AlgorithmToString[alg])
// 	}
// 
// 	return k, cs, rr, ktype, nil
// }

// func ReadPubKeys(keydir string) (map[string]dns.KEY, error) {
// 
// 	var keymap = make(map[string]dns.KEY, 5)
// 
// 	if keydir == "" {
// 		log.Fatalf("Error: key directory not specified in YAML config")
// 	}
// 
// 	entries, err := os.ReadDir(keydir)
// 	if err != nil {
// 		log.Fatalf("Error from os.ReadDir(%s): %v", keydir, err)
// 	}
// 
// 	for _, f := range entries {
// 		fname := f.Name()
// 		fmt.Println(fname)
// 
// 		if strings.HasSuffix(fname, ".key") {
// 			// basename = strings.TrimSuffix(filename, ".key")
// 			pubfile := keydir + "/" + fname
// 			_, err := os.Open(pubfile)
// 			if err != nil {
// 				log.Fatalf("Error opening public key file '%s': %v",
// 					pubfile, err)
// 			}
// 			pubkeybytes, err := os.ReadFile(pubfile)
// 			if err != nil {
// 				log.Fatalf("Error reading public key file '%s': %v",
// 					pubfile, err)
// 			}
// 			pubkey := string(pubkeybytes)
// 			rr, err := dns.NewRR(pubkey)
// 			if err != nil {
// 				log.Fatalf("Error reading public key '%s': %v",
// 					pubkey, err)
// 			}
// 
// 			switch rr.(type) {
// 			case *dns.KEY:
// 				rrk := rr.(*dns.KEY)
// 				keymap[rr.Header().Name] = *rrk
// 				//		k, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
// 				//		ktype = "KEY"
// 				//		alg = rrk.Algorithm
// 				//		fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])
// 			default:
// 				log.Fatalf("Error: rr is of type %v", "foo")
// 			}
// 
// 		} else {
// 			fmt.Printf("File %s is not a public key file. Ignored.\n", fname)
// 		}
// 	}
// 
// 	return keymap, nil
// }

// From Mieks DNS lib:
// const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.
// func WithinValidityPeriod(inc, exp uint32, t time.Time) bool {
// 	var utc int64
// 	if t.IsZero() {
// 		utc = time.Now().UTC().Unix()
// 	} else {
// 		utc = t.UTC().Unix()
// 	}
// 	modi := (int64(inc) - utc) / year68
// 	mode := (int64(exp) - utc) / year68
// 	ti := int64(inc) + modi*year68
// 	te := int64(exp) + mode*year68
// 	return ti <= utc && utc <= te
// }

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.
// func xxxSIGValidityPeriod(sig *dns.SIG, t time.Time) bool {
// 	var utc int64
// 	if t.IsZero() {
// 		utc = time.Now().UTC().Unix()
// 	} else {
// 		utc = t.UTC().Unix()
// 	}
// 	modi := (int64(sig.Inception) - utc) / year68
// 	mode := (int64(sig.Expiration) - utc) / year68
// 	ti := int64(sig.Inception) + modi*year68
// 	te := int64(sig.Expiration) + mode*year68
// 	return ti <= utc && utc <= te
// }

// func xxxRRSIGValidityPeriod(rrsig *dns.RRSIG, t time.Time) bool {
// 	var utc int64
// 	if t.IsZero() {
// 		utc = time.Now().UTC().Unix()
// 	} else {
// 		utc = t.UTC().Unix()
// 	}
// 	modi := (int64(rrsig.Inception) - utc) / year68
// 	mode := (int64(rrsig.Expiration) - utc) / year68
// 	ti := int64(rrsig.Inception) + modi*year68
// 	te := int64(rrsig.Expiration) + mode*year68
// 	return ti <= utc && utc <= te
// }
