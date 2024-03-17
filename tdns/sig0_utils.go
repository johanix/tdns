/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func SendSig0KeyUpdate(gennewkey bool) error {
	if Globals.Zonename == "" {
		return fmt.Errorf("Error: child zone name not specified.")
	}
	Globals.Zonename = dns.Fqdn(Globals.Zonename)

	if Globals.ParentZone == "" {
		return fmt.Errorf("Error: parent zone name not specified.")
	}
	Globals.ParentZone = dns.Fqdn(Globals.ParentZone)

	if childpri == "" {
		return fmt.Errorf("Error: child primary nameserver not specified.")
	}
	if parpri == "" {
		return fmt.Errorf("Error: parent primary nameserver not specified.")
	}

	keyrr, cs := LoadSigningKey(Globals.Sig0Keyfile)
	if keyrr != nil {
		fmt.Printf("keyid=%d\n", keyrr.KeyTag())
	} else {
		fmt.Printf("No signing key specified.\n")
	}

	var adds, removes []dns.RR

	if gennewkey {
		newkey, newcs, newpriv, err := GenerateSigningKey(Globals.Zonename,
			keyrr.Algorithm)
		if err != nil {
			return fmt.Errorf("Error from GenerateSigningKey: %v", err)
		}
		_ = newcs // XXX: should store the cs and new private key somewhere.
		_ = newpriv
		fmt.Printf("new key: %s\n", newkey.String())

		adds = []dns.RR{newkey}
		removes = []dns.RR{keyrr}
	} else {
		adds = []dns.RR{keyrr}
		removes = []dns.RR{}
	}

	const update_scheme = 2
	dsynctarget, err := LookupDSYNCTarget(Globals.ParentZone, parpri, dns.StringToType["ANY"],
		update_scheme)
	if err != nil {
		return fmt.Errorf("Error from LookupDDNSTarget(%s, %s): %v",
			Globals.ParentZone, parpri, err)
	}

	msg, err := CreateUpdate(Globals.ParentZone, Globals.Zonename, adds, removes)
	if err != nil {
		return fmt.Errorf("Error from CreateUpdate(%v): %v", dsynctarget, err)
	}

	if Globals.Sig0Keyfile != "" {
		fmt.Printf("Signing update.\n")
		msg, err = SignMsgNG(msg, Globals.Zonename, cs, keyrr)
		if err != nil {
			return fmt.Errorf("Error from SignMsgNG(%v): %v",
				dsynctarget, err)
		}
	} else {
		return fmt.Errorf("Error: Keyfile not specified, signing update not possible.\n")
	}

	err = SendUpdate(msg, Globals.ParentZone, dsynctarget)
	if err != nil {
		return fmt.Errorf("Error from SendUpdate(%v): %v", dsynctarget, err)
	}
	return nil
}

func GenerateSigningKey(owner string, alg uint8) (*dns.KEY, crypto.Signer, crypto.PrivateKey, error) {
	var keyrr *dns.KEY
	var cs crypto.Signer
	var privkey crypto.PrivateKey
	var err error

	mode := viper.GetString("roll.keygen.mode")

	var bits int
	switch alg {
	case dns.ECDSAP256SHA256, dns.ED25519:
		bits = 256
	case dns.ECDSAP384SHA384:
		bits = 384
	case dns.RSASHA256, dns.RSASHA512:
		bits = 2048
	}

	switch mode {
	case "internal":
		nkey := new(dns.KEY)
		nkey.Hdr.Name = owner
		nkey.Hdr.Rrtype = dns.TypeKEY
		nkey.Hdr.Class = dns.ClassINET
		// nkey.Algorithm  = dns.StringToAlgorithm["ED25519"]
		nkey.Algorithm = alg
		privkey, err = nkey.Generate(bits)
		if err != nil {
			log.Fatalf("Error from nkey.Generate: %v", err)
		}

		kbasename := fmt.Sprintf("K%s+%03d+%03d", owner, nkey.Algorithm, nkey.KeyTag())
		log.Printf("Key basename: %s", kbasename)

		log.Printf("Generated key: %s", nkey.String())
		log.Printf("Generated signer: %v", privkey)

		nkey.Hdr.Rrtype = dns.TypeKEY
		keyrr = nkey

	case "external":
		keygenprog := viper.GetString("roll.keygen.generator")
		if keygenprog == "" {
			log.Fatalf("Error: key generator program not specified.")
		}

		algstr := dns.AlgorithmToString[alg]

		cmdline := fmt.Sprintf("%s -a %s -T KEY -n ZONE %s", keygenprog, algstr, owner)
		fmt.Printf("cmd: %s\n", cmdline)
		cmdsl := strings.Fields(cmdline)
		command := exec.Command(cmdsl[0], cmdsl[1:]...)
		out, err := command.CombinedOutput()
		if err != nil {
			log.Printf("Error from exec: %v: %v\n", cmdsl, err)
		}

		var keyname string

		for _, l := range strings.Split(string(out), "\n") {
			if len(l) != 0 {
				elems := strings.Fields(l)
				if strings.HasPrefix(elems[0], "K"+owner) {
					keyname = elems[0]
					fmt.Printf("New key is in file %s\n", keyname)
				}
			}
		}

		keyrr, _ = LoadSigningKey(keyname + ".key")
		if err != nil {
			return keyrr, cs, privkey, err
		}

	default:
		log.Fatalf("Error: unknown keygen mode: \"%s\".", mode)
	}

	switch alg {
	case dns.RSASHA256:
		cs = privkey.(*rsa.PrivateKey)
	case dns.ED25519:
		cs = privkey.(*ed25519.PrivateKey)
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		cs = privkey.(*ecdsa.PrivateKey)
	default:
		log.Fatalf("Error: no support for algorithm %s yet", dns.AlgorithmToString[alg])
	}

	return keyrr, cs, privkey, nil
}

func LoadSigningKey(keyfile string) (*dns.KEY, crypto.Signer) {
	var keyrr *dns.KEY
	var cs crypto.Signer
	var rr dns.RR

	if keyfile != "" {
		var ktype string
		var err error
		_, cs, rr, ktype, err = ReadKey(keyfile)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", keyfile, err)
		}

		if ktype != "KEY" {
			log.Fatalf("Key must be a KEY RR")
		}

		keyrr = rr.(*dns.KEY)
	}
	return keyrr, cs
}

