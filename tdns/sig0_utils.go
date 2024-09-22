/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"path/filepath"
	"slices"

	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/gookit/goutil/dump"
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
		newpkc, msg, err := kdb.GenerateKeypair(Globals.Zonename, "tdnsd", "active", dns.TypeKEY, pkc.Algorithm, "", nil) // nil = no tx
		if err != nil {
			return fmt.Errorf("Error from GenerateSigningKey: %v", err)
		}
		log.Printf(msg)

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
func (kdb *KeyDB) GenerateKeypair(owner, creator, state string, rrtype uint16, alg uint8, keytype string, tx *Tx) (*PrivateKeyCache, string, error) {
	if _, exist := dns.AlgorithmToString[alg]; !exist {
		return nil, "", fmt.Errorf("GenerateKeypair: Error: unknown algorithm: %d", alg)
	}

	if rrtype == dns.TypeDNSKEY && !slices.Contains([]string{"ZSK", "KSK", "CSK"}, keytype) {
		return nil, "", fmt.Errorf("GenerateKeypair: Error: unknown key type: %s", keytype)
	}

	var privkey crypto.PrivateKey
	var err error

	if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
		return nil, "", fmt.Errorf("Error: rrtype must be KEY or DNSKEY")
	}

	var pkc *PrivateKeyCache
	mode := viper.GetString("delegationsync.child.update.keygen.mode")
	if rrtype == dns.TypeDNSKEY {
		mode = viper.GetString("resignerengine.keygen.mode")
	}
	mode = strings.ToLower(mode)

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
		var nkey dns.RR

		switch rrtype {
		case dns.TypeKEY:
			nkey = new(dns.KEY)
			nkey.(*dns.KEY).Algorithm = alg
			nkey.(*dns.KEY).Flags = 256
			nkey.(*dns.KEY).Protocol = 3
		case dns.TypeDNSKEY:
			nkey = new(dns.DNSKEY)
			nkey.(*dns.DNSKEY).Algorithm = alg
			nkey.(*dns.DNSKEY).Flags = 256
			if keytype == "KSK" || keytype == "CSK" {
				nkey.(*dns.DNSKEY).Flags = 257
			}
			nkey.(*dns.DNSKEY).Protocol = 3
		default:
			return nil, "", fmt.Errorf("Error: rrtype must be KEY or DNSKEY")
		}

		nkey.Header().Name = owner
		nkey.Header().Rrtype = rrtype
		nkey.Header().Class = dns.ClassINET
		nkey.Header().Ttl = 3600

		log.Printf("Generated DNSKEY flags: %d", nkey.(*dns.DNSKEY).Flags)

		switch rrtype {
		case dns.TypeKEY:
			privkey, err = nkey.(*dns.KEY).Generate(bits)
		case dns.TypeDNSKEY:
			privkey, err = nkey.(*dns.DNSKEY).Generate(bits)
		}
		if err != nil {
			return nil, "", fmt.Errorf("Error from nkey.Generate: %v", err)
		}

		// kbasename := fmt.Sprintf("K%s+%03d+%03d", owner, nkey.Algorithm, nkey.KeyTag())
		// log.Printf("Key basename: %s", kbasename)

		var pk crypto.PrivateKey
		switch privkey.(type) {
		case *rsa.PrivateKey:
			pk = privkey.(*rsa.PrivateKey)
		case ed25519.PrivateKey:
			pk = privkey.(ed25519.PrivateKey)
		case *ecdsa.PrivateKey:
			pk = privkey.(*ecdsa.PrivateKey)
		default:
			return nil, "", fmt.Errorf("Error: unknown private key type: %T", privkey)
		}

		var privkeystr string

		switch rrtype {
		case dns.TypeKEY:
			privkeystr = nkey.(*dns.KEY).PrivateKeyString(pk) // Convert to BIND private key format
		case dns.TypeDNSKEY:
			privkeystr = nkey.(*dns.DNSKEY).PrivateKeyString(pk) // Convert to BIND private key format
		}

		pkc, err = PrepareKeyCache(privkeystr, nkey.String())
		if err != nil {
			return nil, "", fmt.Errorf("Error from PrepareKeyCache: %v", err)
		}

	case "external":
		keygenprog := viper.GetString("delegationsync.child.update.keygen.generator")
		if keygenprog == "" {
			return nil, "", fmt.Errorf("Error: key generator program not specified.")
		}

		algstr := dns.AlgorithmToString[alg]
		keydir := "/tmp"

		keytypearg := "-T KEY"
		if rrtype == dns.TypeDNSKEY {
			keytypearg = ""
		}

		flags := ""
		if keytype != "ZSK" {
			flags = "-f KSK"
		}
		cmdline := fmt.Sprintf("%s -K %s -a %s %s %s -n ZONE %s", keygenprog, keydir, algstr, keytypearg, flags, owner)
		dump.P(cmdline)
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
			return nil, "", err
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
		return nil, "", fmt.Errorf("Error: unknown keygen mode: \"%s\".", mode)
	}

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
		addDnssecKeySql = `
INSERT OR REPLACE INTO DnssecKeyStore (zonename, state, keyid, algorithm, flags, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	)

	localtx := false
	if tx == nil {
		tx, err = kdb.Begin("GenerateKeypair")
		if err != nil {
			return nil, "", err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if err != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}
	}()

	if state == "" {
		state = "active"
	}

	switch rrtype {
	case dns.TypeKEY:
		_, err = tx.Exec(addSig0KeySql, owner, state, pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], creator, pkc.PrivateKey, pkc.KeyRR.String())

	case dns.TypeDNSKEY:
		flags := 257
		if keytype == "ZSK" {
			flags = 256
		}
		_, err = tx.Exec(addDnssecKeySql, owner, state, pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], flags, creator, pkc.PrivateKey, pkc.DnskeyRR.String())
	}
	if err != nil {
		log.Printf("Error storing generated SIG(0) key in keystore: %v", err)
		return nil, "", err
	}

	// log.Printf("Success storing generated SIG(0) key in keystore.")

	return pkc, fmt.Sprintf("Generated new %s %s with keyid %d (initial state: %s)", owner, dns.TypeToString[rrtype], pkc.KeyId, state), nil
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
