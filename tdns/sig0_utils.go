/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"path/filepath"

	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// XXX: FIXME: This is only used from the CLI. It should change into code used by TDNSD and
//
//	     accessed via API.
//
//		The code should store the newly generated key in the keystore.
func (kdb *KeyDB) SendSig0KeyUpdate(childpri, parpri string, gennewkey bool) error {
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
		newpkc, err := kdb.GenerateKeypair(Globals.Zonename, "tdnsd", dns.TypeKEY, pkc.Algorithm)
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

// Generate a new private/public key pair of the right algorithm and the right rrtype and store in
// the KeyStore. Return the key as a pkc

// XXX: FIXME: This is not yet ready to generate DNSSEC keys, because in the DNSSEC case we also need the
//
//	flags field, which is not yet set here.
func (kdb *KeyDB) GenerateKeypair(owner, creator string, rrtype uint16, alg uint8) (*PrivateKeyCache, error) {
	var privkey crypto.PrivateKey
	var err error

	if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
		return nil, fmt.Errorf("Error: rrtype must be KEY or DNSKEY")
	}

	var pkc *PrivateKeyCache
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

		// kbasename := fmt.Sprintf("K%s+%03d+%03d", owner, nkey.Algorithm, nkey.KeyTag())
		// log.Printf("Key basename: %s", kbasename)

		nkey.Hdr.Rrtype = rrtype

		var pk crypto.PrivateKey
		switch privkey.(type) {
		case *rsa.PrivateKey:
			pk = privkey.(*rsa.PrivateKey)
		case ed25519.PrivateKey:
			pk = privkey.(ed25519.PrivateKey)
		case *ecdsa.PrivateKey:
			pk = privkey.(*ecdsa.PrivateKey)
		default:
			return nil, fmt.Errorf("Error: unknown private key type: %T", privkey)
		}
		privkeystr := nkey.PrivateKeyString(pk) // Convert to BIND private key format
		fmt.Printf("privkeystr: %s\n", privkeystr)

		pkc, err = PrepareKeyCache(privkeystr, nkey.String())
		if err != nil {
			return nil, fmt.Errorf("Error from PrepareKeyCache: %v", err)
		}

	case "external":
		// keygenprog := viper.GetString("roll.keygen.generator")
		keygenprog := viper.GetString("delegationsync.child.update.keygen.generator")
		if keygenprog == "" {
			return nil, fmt.Errorf("Error: key generator program not specified.")
		}

		algstr := dns.AlgorithmToString[alg]
		keydir := "/tmp"

		keytype := "-T KEY"
		if rrtype == dns.TypeDNSKEY {
			keytype = ""
		}
		cmdline := fmt.Sprintf("%s -K %s -a %s %s -n ZONE %s", keygenprog, keydir, algstr, keytype, owner)
		// fmt.Printf("cmd: %s\n", cmdline)
		cmdsl := strings.Fields(cmdline)
		command := exec.Command(cmdsl[0], cmdsl[1:]...)
		out, err := command.CombinedOutput()
		if err != nil {
			log.Printf("Error from exec: %v: %v\n", cmdsl, err)
		}

		var keyname, keyfile string

		// log.Printf("out: %s", out)
		for _, l := range strings.Split(string(out), "\n") {
			if len(l) != 0 {
				elems := strings.Fields(l)
				if strings.HasPrefix(elems[0], "K"+owner) {
					keyname = elems[0]
					keyfile = fmt.Sprintf("%s/%s.private", keydir, keyname)
					keyfile = filepath.Clean(keyfile)
					// fmt.Printf("Generated key is in file %s\n", keyfile)
				}
			}
		}

		pkc, err = ReadPrivateKey(keyfile)
		if err != nil {
			return nil, err
		} else {
			// log.Printf("Generated %s key files %s/%s.{key,private} successfully imported. May be deleted.", dns.TypeToString[rrtype], keydir, keyname)
			// Delete the generated key files
			err = os.Remove(fmt.Sprintf("%s/%s.private", keydir, keyname))
			if err != nil {
				log.Printf("Error deleting private key file: %v", err)
			}
			err = os.Remove(fmt.Sprintf("%s/%s.key", keydir, keyname))
			if err != nil {
				log.Printf("Error deleting public key file: %v", err)
			}
		}

	default:
		return nil, fmt.Errorf("Error: unknown keygen mode: \"%s\".", mode)
	}

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
		addDnssecKeySql = `
INSERT OR REPLACE INTO DnssecKeyStore (zonename, state, keyid, algorithm, flags, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	)

	tx, err := kdb.Begin("GenerateKeypair")
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	switch rrtype {
	case dns.TypeKEY:
		_, err = tx.Exec(addSig0KeySql, owner, "active", pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], creator, pkc.PrivateKey, pkc.KeyRR.String())
	case dns.TypeDNSKEY:
		_, err = tx.Exec(addDnssecKeySql, owner, "active", pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], 257, creator, pkc.PrivateKey, pkc.DnskeyRR.String())
	}
	if err != nil {
		log.Printf("Error storing generated SIG(0) key in keystore: %v", err)
		return nil, err
	}
	// log.Printf("Success storing generated SIG(0) key in keystore.")

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
