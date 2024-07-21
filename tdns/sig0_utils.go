/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"path/filepath"

	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// XXX: FIXME: This is used from the CLI. It should change into code used by TDNSD and accessed via API.
//
//	The code should store the newly generated key in the keystore.
func SendSig0KeyUpdate(childpri, parpri string, gennewkey bool) error {
	pkc, err := LoadSig0SigningKey(Globals.Sig0Keyfile)
	if err != nil {
		return fmt.Errorf("Error from LoadSig0SigningKeyNG(%s): %v", Globals.Sig0Keyfile, err)
	}

	if pkc != nil {
		fmt.Printf("keyid=%d\n", pkc.KeyRR.KeyTag())
	} else {
		fmt.Printf("No signing key specified.\n")
	}

	sak := &Sig0ActiveKeys{
		Keys: []*PrivateKeyCache{pkc},
	}

	var adds, removes []dns.RR

	if gennewkey {
		newpkc, err := GenerateSigningKey(Globals.Zonename, pkc.Algorithm)
		if err != nil {
			return fmt.Errorf("Error from GenerateSigningKey: %v", err)
		}
		// _ = newcs // XXX: should store the cs and new private key in the KeyDB.
		// _ = newpriv
		fmt.Printf("new key: %s\n", newpkc.KeyRR.String())

		adds = []dns.RR{&newpkc.KeyRR}
		removes = []dns.RR{&pkc.KeyRR}
	} else {
		adds = []dns.RR{&pkc.KeyRR}
		removes = []dns.RR{}
	}

	const update_scheme = 2
	dsynctarget, err := LookupDSYNCTarget(Globals.ParentZone, parpri, dns.StringToType["ANY"], update_scheme)
	if err != nil {
		return fmt.Errorf("Error from LookupDSYNCTarget(%s, %s): %v",
			Globals.ParentZone, parpri, err)
	}

	msg, err := CreateChildUpdate(Globals.ParentZone, Globals.Zonename, adds, removes)
	if err != nil {
		return fmt.Errorf("Error from CreateChildUpdate(%v): %v", dsynctarget, err)
	}

	var smsg *dns.Msg

	if Globals.Sig0Keyfile != "" {
		fmt.Printf("Signing update.\n")
		smsg, err = SignMsg(*msg, Globals.Zonename, sak)
		if err != nil {
			return fmt.Errorf("Error from SignMsgNG(%v): %v", dsynctarget, err)
		}
	} else {
		return fmt.Errorf("Error: Keyfile not specified, signing update not possible.\n")
	}

	rcode, err := SendUpdate(smsg, Globals.ParentZone, dsynctarget.Addresses)
	if err != nil {
		return fmt.Errorf("Error from SendUpdate(%v): %v", dsynctarget, err)
	} else {
		log.Printf("SendUpdate(parent=%s, target=%s) returned rcode %s", Globals.ParentZone, dsynctarget.Addresses, dns.RcodeToString[rcode])
	}
	return nil
}

// XXX: This should die in favour of the kdb.GenerateSigningKey() below.
func GenerateSigningKey(owner string, alg uint8) (*PrivateKeyCache, error) {
	var privkey crypto.PrivateKey
	var err error

	var pkc *PrivateKeyCache

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
		nkey.Algorithm = alg
		privkey, err = nkey.Generate(bits)
		if err != nil {
			return nil, fmt.Errorf("Error from nkey.Generate: %v", err)
		}

		kbasename := fmt.Sprintf("K%s+%03d+%03d", owner, nkey.Algorithm, nkey.KeyTag())
		log.Printf("Key basename: %s", kbasename)

		log.Printf("Generated key: %s", nkey.String())
		log.Printf("Generated signer: %v", privkey)

		nkey.Hdr.Rrtype = dns.TypeKEY
		pkc.KeyRR = *nkey

	case "external":
		keygenprog := viper.GetString("roll.keygen.generator")
		if keygenprog == "" {
			return nil, fmt.Errorf("Error: key generator program not specified.")
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

		pkc, err = LoadSig0SigningKey(keyname + ".key")
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("Error: unknown keygen mode: \"%s\".", mode)
	}

	switch pkc.Algorithm {
	case dns.RSASHA256:
		pkc.CS = privkey.(*rsa.PrivateKey)
	case dns.ED25519:
		pkc.CS = privkey.(*ed25519.PrivateKey)
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pkc.CS = privkey.(*ecdsa.PrivateKey)
	default:
		return nil, fmt.Errorf("Error: no support for algorithm %s yet", dns.AlgorithmToString[alg])
	}

	return pkc, nil
}

func (kdb *KeyDB) GenerateSigningKey(owner string, alg uint8) (*PrivateKeyCache, error) {
	var privkey crypto.PrivateKey
	var err error

	var pkc *PrivateKeyCache

	// mode := viper.GetString("roll.keygen.mode")
	mode := viper.GetString("delegationsync.child.update.keygen.mode")

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
		nkey.Algorithm = alg
		nkey.Flags = 256 // XXX: FIXME: This is hardcoded.
		nkey.Protocol = 3
		nkey.Hdr.Ttl = 3600
		privkey, err = nkey.Generate(bits)
		if err != nil {
			return nil, fmt.Errorf("Error from nkey.Generate: %v", err)
		}

		kbasename := fmt.Sprintf("K%s+%03d+%03d", owner, nkey.Algorithm, nkey.KeyTag())
		log.Printf("Key basename: %s", kbasename)

		log.Printf("Generated key: %s", nkey.String())
		log.Printf("Generated signer: %v", privkey)

		nkey.Hdr.Rrtype = dns.TypeKEY
		dump.P(nkey)
		dump.P(privkey)

		// var privkeystr string

		// log.Printf("privkey (internal): %s", privkey.(string))

		switch privkey.(type) {
		case ed25519.PrivateKey:
			//privkeystr = base64.StdEncoding.EncodeToString(privkey.(ed25519.PrivateKey))
			//		case *rsa.PrivateKey:
			//			tmp, err := x509.MarshalECPrivateKey(privkey.(*rsa.PrivateKey))
			//			if err != nil {
			//				return nil, fmt.Errorf("Error from x509.MarshalECPrivateKey: %v", err)
			//			}
			//			privkeystr = base64.StdEncoding.EncodeToString(tmp)
		default:
			return nil, fmt.Errorf("Error: unknown private key type: %T", privkey)
		}

		// if pkbytes, ok := privkey.([]uint8); ok {
		//privkeystr = base64.StdEncoding.EncodeToString([]byte(pkbytes))
		// privkeystr, err := PrivateKeyToString(privkey)
		// if err != nil {
		// 	return nil, fmt.Errorf("Error from PrivateKeyToString: %v", err)
		// }

		// } else {
		// 	return nil, fmt.Errorf("Error: privkey is not []byte")
		// }

		//		pkc = &PrivateKeyCache{
		//			KeyType:   dns.TypeKEY,
		//			Algorithm: nkey.Algorithm,
		//			KeyRR:     *nkey,
		//		}

		// pkc, err = PrepareKeyCache(privkey.(string), nkey.String(), dns.AlgorithmToString[alg])
		// if err != nil {
		// 	return nil, fmt.Errorf("Error from PreparePrivateKeyCache: %v", err)
		// }

	case "external":
		// keygenprog := viper.GetString("roll.keygen.generator")
		keygenprog := viper.GetString("delegationsync.child.update.keygen.generator")
		if keygenprog == "" {
			return nil, fmt.Errorf("Error: key generator program not specified.")
		}

		algstr := dns.AlgorithmToString[alg]
		keydir := "/tmp"

		cmdline := fmt.Sprintf("%s -K %s -a %s -T KEY -n ZONE %s", keygenprog, keydir, algstr, owner)
		fmt.Printf("cmd: %s\n", cmdline)
		cmdsl := strings.Fields(cmdline)
		command := exec.Command(cmdsl[0], cmdsl[1:]...)
		out, err := command.CombinedOutput()
		if err != nil {
			log.Printf("Error from exec: %v: %v\n", cmdsl, err)
		}

		var keyname, keyfile string

		log.Printf("out: %s", out)
		for _, l := range strings.Split(string(out), "\n") {
			if len(l) != 0 {
				elems := strings.Fields(l)
				if strings.HasPrefix(elems[0], "K"+owner) {
					keyname = elems[0]
					keyfile = fmt.Sprintf("%s/%s.private", keydir, keyname)
					keyfile = filepath.Clean(keyfile)
					fmt.Printf("Generated key is in file %s\n", keyfile)
				}
			}
		}

		log.Printf("keyfile: %s, keydir: %s, keyname: %s", keyfile, keydir, keyname)

		// pkc, err = LoadSig0SigningKey(fmt.Sprintf("%s/%s", keydir, keyname))
		pkc, err = ReadPrivateKey(keyfile)
		if err != nil {
			return nil, err
		}
		log.Printf("[generatesigningkey]PrivateKey: %s", pkc.PrivateKey)

		dump.P(pkc)

		log.Printf("[GenSigKey]pkc.K: %s, pkc.PrivateKey: %s", pkc.K, pkc.PrivateKey)
		log.Printf("Generated key: %s", pkc.KeyRR.String())
		log.Printf("Generated private key string: %s", pkc.K)
		log.Printf("Generated private key: %v", pkc.PrivateKey)

	default:
		return nil, fmt.Errorf("Error: unknown keygen mode: \"%s\".", mode)
	}

	//	switch pkc.Algorithm {
	//	case dns.RSASHA256:
	//		pkc.CS = privkey.(*rsa.PrivateKey)
	//	case dns.ED25519:
	//		pkc.CS = privkey.(ed25519.PrivateKey)
	//	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
	//		pkc.CS = privkey.(*ecdsa.PrivateKey)
	//	default:
	//		return nil, fmt.Errorf("Error: no support for algorithm %s yet", dns.AlgorithmToString[alg])
	//	}

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
	)

	tx, err := kdb.Begin("GenerateSigningKey")
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	_, err = tx.Exec(addSig0KeySql, pkc.KeyRR.Header().Name, "active", pkc.KeyRR.KeyTag(),
		dns.AlgorithmToString[pkc.Algorithm], "tdnsd", pkc.PrivateKey, pkc.KeyRR.String())
	// log.Printf("tx.Exec(%s, %s, %d, %s, %s)", addSig0KeySql, kp.Keyname, kp.Keyid, "***", kp.KeyRR)
	if err != nil {
		log.Printf("Error storing generated SIG(0) key in keystore: %v", err)
		return nil, err
	}
	log.Printf("Success storing generated SIG(0) key in keystore.")

	return pkc, nil
}

func LoadSig0SigningKey(keyfile string) (*PrivateKeyCache, error) {
	var pkc *PrivateKeyCache

	if keyfile != "" {
		var err error
		pkc, err = ReadPrivateKey(keyfile)
		if err != nil {
			return nil, fmt.Errorf("Error reading SIG(0) key file '%s': %v", keyfile, err)
		}

		if pkc.KeyType != dns.TypeKEY {
			return nil, fmt.Errorf("Key must be a KEY RR")
		}
	}
	return pkc, nil
}
