/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"slices"

	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// XXX: FIXME: This is only used from the CLI. It should change into code used by TDNS-SERVER and
//
//	accessed via API. The code should store the newly generated key in the keystore.
func (kdb *KeyDB) SendSig0KeyUpdate(ctx context.Context, childpri, parpri string, gennewkey bool) error {
	pkc, err := LoadSig0SigningKey(Globals.Sig0Keyfile)
	if err != nil {
		return fmt.Errorf("error from LoadSig0SigningKeyNG(%s): %v", Globals.Sig0Keyfile, err)
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
		newpkc, msg, err := kdb.GenerateKeypair(Globals.Zonename, "tdns-auth", "active", dns.TypeKEY, pkc.Algorithm, "", nil) // nil = no tx
		if err != nil {
			return fmt.Errorf("error from GenerateSigningKey: %v", err)
		}
		lgDns.Info("GenerateKeypair result", "msg", msg)

		adds = []dns.RR{&newpkc.KeyRR}
		removes = []dns.RR{&pkc.KeyRR}
	} else {
		adds = []dns.RR{&pkc.KeyRR}
		removes = []dns.RR{}
	}

	if Globals.ImrEngine == nil {
		return fmt.Errorf("imrEngine not initialized: cannot lookup DSYNC target for parent zone %s (scheme=UPDATE)",
			Globals.ParentZone)
	}

	dsynctarget, err := Globals.ImrEngine.LookupDSYNCTarget(ctx, Globals.ParentZone, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return fmt.Errorf("error from LookupDSYNCTarget for parent zone %s (scheme=UPDATE): %v",
			Globals.ParentZone, err)
	}

	msg, err := CreateChildUpdate(Globals.ParentZone, Globals.Zonename, adds, removes)
	if err != nil {
		return fmt.Errorf("error from CreateChildUpdate(%v): %v", dsynctarget, err)
	}

	var smsg *dns.Msg

	if Globals.Sig0Keyfile != "" {
		fmt.Printf("Signing update.\n")
		smsg, err = SignMsg(*msg, Globals.Zonename, sak)
		if err != nil {
			return fmt.Errorf("error from SignMsgNG(%v): %v", dsynctarget, err)
		}
	} else {
		return fmt.Errorf("error: Keyfile not specified, signing update not possible")
	}

	rcode, _, err := SendUpdate(ctx, smsg, Globals.ParentZone, dsynctarget.Addresses)
	if err != nil {
		return fmt.Errorf("error from SendUpdate(ctx, %v): %v", dsynctarget, err)
	}
	// SendUpdate reports a parent REJECTION through the rcode with a nil error
	// (only a transport failure is an error), so the rcode must be checked
	// explicitly or a BADKEY/REFUSED would be reported to the caller as success.
	if rcode != dns.RcodeSuccess {
		return fmt.Errorf("parent %s rejected the update: rcode %s",
			Globals.ParentZone, dns.RcodeToString[rcode])
	}
	lgDns.Info("SendUpdate completed", "parent", Globals.ParentZone, "target", dsynctarget.Addresses, "rcode", dns.RcodeToString[rcode])
	return nil
}

// GenerateKeyMaterial builds private/public key material for KEY or DNSKEY without touching the DB.
func GenerateKeyMaterial(owner string, rrtype uint16, alg uint8, keytype string) (*PrivateKeyCache, error) {
	if _, exist := dns.AlgorithmToString[alg]; !exist {
		return nil, fmt.Errorf("GenerateKeyMaterial: Error: unknown algorithm: %d", alg)
	}

	if rrtype == dns.TypeDNSKEY && !slices.Contains([]string{"ZSK", "KSK", "CSK"}, keytype) {
		return nil, fmt.Errorf("GenerateKeyMaterial: error: unknown key type: %s", keytype)
	}

	var privkey crypto.PrivateKey
	var err error

	if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
		return nil, fmt.Errorf("error: rrtype must be KEY or DNSKEY")
	}

	var pkc *PrivateKeyCache
	modekey := "parentsync.update.keygen.mode"
	mode := viper.GetString(modekey)
	if rrtype == dns.TypeDNSKEY {
		modekey = "resignerengine.keygen.mode"
		mode = viper.GetString(modekey)
	}
	mode = strings.ToLower(mode)
	if mode == "" {
		mode = "internal"
		lgDns.Info("GenerateKeyMaterial: no mode specified, using default", "configKey", "resignerengine.keygen.mode", "mode", mode)
	}

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
			return nil, fmt.Errorf("error: rrtype must be KEY or DNSKEY")
		}

		nkey.Header().Name = owner
		nkey.Header().Rrtype = rrtype
		nkey.Header().Class = dns.ClassINET
		nkey.Header().Ttl = 3600

		switch rrtype {
		case dns.TypeKEY:
			lgDns.Debug("GenerateKeyMaterial: generating KEY", "flags", nkey.(*dns.KEY).Flags)
			privkey, err = nkey.(*dns.KEY).Generate(bits)
		case dns.TypeDNSKEY:
			lgDns.Debug("GenerateKeyMaterial: generating DNSKEY", "flags", nkey.(*dns.DNSKEY).Flags)
			privkey, err = nkey.(*dns.DNSKEY).Generate(bits)
		}
		if err != nil {
			return nil, fmt.Errorf("error from nkey.Generate: %v", err)
		}

		// PrivateKeyToPEM dispatches by Go type (stdlib for RSA/ECDSA/
		// Ed25519, dnssec-algorithms/pkcs8 registry for the rest), so
		// just forward whatever Generate returned.
		privkeyPEM, err := PrivateKeyToPEM(privkey)
		if err != nil {
			return nil, fmt.Errorf("error from PrivateKeyToPEM: %v", err)
		}

		pkc, err = PrepareKeyCache(privkeyPEM, nkey.String())
		if err != nil {
			return nil, fmt.Errorf("error from PrepareKeyCache: %v", err)
		}

		pkc.PrivateKey = privkeyPEM

	case "external":
		keygenprog := ParentSyncConfig().Update.Keygen.Generator
		if keygenprog == "" {
			return nil, fmt.Errorf("error: key generator program not specified (keygenprog=%s, modekey=%s)", keygenprog, modekey)
		}

		algstr := dns.AlgorithmToString[alg]
		keydir := os.TempDir()

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
			lgDns.Error("GenerateKeyMaterial: error from external keygen", "cmd", cmdsl, "err", err)
		}

		var keyname, keyfile string

		for _, l := range strings.Split(string(out), "\n") {
			if len(l) != 0 {
				elems := strings.Fields(l)
				if strings.HasPrefix(elems[0], "K"+owner) {
					keyname = elems[0]
					keyfile = fmt.Sprintf("%s/%s.private", keydir, keyname)
					keyfile = filepath.Clean(keyfile)
				}
			}
		}

		pkc, err = ReadPrivateKey(keyfile)
		if err != nil {
			return nil, err
		}
		err = os.Remove(fmt.Sprintf("%s/%s.private", keydir, keyname))
		if err != nil {
			lgDns.Warn("GenerateKeyMaterial: error deleting private key file", "err", err)
		}
		err = os.Remove(fmt.Sprintf("%s/%s.key", keydir, keyname))
		if err != nil {
			lgDns.Warn("GenerateKeyMaterial: error deleting public key file", "err", err)
		}

	default:
		return nil, fmt.Errorf("error: unknown keygen mode: \"%s\" (modekey=%s)", mode, modekey)
	}

	return pkc, nil
}

// Generate a new private/public key pair of the right algorithm and the right rrtype and store in
// the KeyStore. Return the key as a pkc

// XXX: FIXME: This is not yet ready to generate DNSSEC keys, because in the DNSSEC case we also need the
//
//	flags field, which is not yet set here.
func (kdb *KeyDB) GenerateKeypair(owner, creator, state string, rrtype uint16, alg uint8, keytype string, tx *Tx) (*PrivateKeyCache, string, error) {
	return kdb.generateKeypair(owner, creator, state, rrtype, alg, keytype, nil, tx)
}

// GenerateKeypairWithColumns is GenerateKeypair for a DNSKEY whose row
// columns (pub, sign, ds) the caller names: one INSERT carries state and
// columns, so an owner's mint (key lifecycle ownership design §3.2, Q4)
// is one write and never a row the store shaped by its own table.
func (kdb *KeyDB) GenerateKeypairWithColumns(owner, creator, state string, alg uint8, keytype string, cols KeyRowFlags, tx *Tx) (*PrivateKeyCache, string, error) {
	return kdb.generateKeypair(owner, creator, state, dns.TypeDNSKEY, alg, keytype, &cols, tx)
}

// generateKeyMaterial is the generator generateKeypair draws from; a test
// replaces it to hand out a key tag the zone already uses.
var generateKeyMaterial = GenerateKeyMaterial

// maxKeyTagDraws bounds the keys generateKeypair draws for one mint. A zone
// holding k keys meets a used tag with probability k/65536 per draw.
const maxKeyTagDraws = 16

// keyTagInUseTx reports whether zone has a row with this key tag in the store
// for rrtype. Any state counts, removed and foreign included: the store is
// unique on (zonename, keyid), and a parent or a validator may still hold the
// old key under that tag.
func keyTagInUseTx(tx *Tx, rrtype uint16, zone string, keyid uint16) (bool, error) {
	table := "DnssecKeyStore"
	if rrtype == dns.TypeKEY {
		table = "Sig0KeyStore"
	}
	var n int
	err := tx.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE zonename=? AND keyid=?", zone, int(keyid)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("keyTagInUseTx: %s keyid %d: %w", zone, keyid, err)
	}
	return n > 0, nil
}

func (kdb *KeyDB) generateKeypair(owner, creator, state string, rrtype uint16, alg uint8, keytype string, cols *KeyRowFlags, tx *Tx) (*PrivateKeyCache, string, error) {
	pkc, err := generateKeyMaterial(owner, rrtype, alg, keytype)
	if err != nil {
		return nil, "", err
	}

	// A plain INSERT: a mint never takes an existing row (tdns#709).
	const addSig0KeySql = `
INSERT INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`

	// When tx != nil (external), the caller must republishSigningKeysForZone
	// after their Commit if the active set may have changed (R1). When tx == nil
	// we own the commit and republish for DNSKEY inserts.
	localtx := false
	if tx == nil {
		tx, err = kdb.Begin("GenerateKeypair")
		if err != nil {
			return nil, "", err
		}
		localtx = true
	}
	committed := false
	defer func() {
		if localtx && !committed {
			tx.Rollback()
		}
	}()

	// A fresh key whose tag the zone already uses would collide with that
	// key, so draw again, in this transaction so a key minted earlier in it
	// counts too.
	for draws := 1; ; draws++ {
		inUse, err := keyTagInUseTx(tx, rrtype, owner, pkc.KeyId)
		if err != nil {
			return nil, "", err
		}
		if !inUse {
			break
		}
		if draws == maxKeyTagDraws {
			return nil, "", fmt.Errorf("GenerateKeypair: %s %s: %d keys drawn, each with a key tag the zone already uses (last %d)",
				owner, dns.TypeToString[rrtype], draws, pkc.KeyId)
		}
		lgDns.Info("GenerateKeypair: key tag is in use for the zone, generating another key",
			"zone", owner, "rrtype", dns.TypeToString[rrtype], "keyid", pkc.KeyId)
		if pkc, err = generateKeyMaterial(owner, rrtype, alg, keytype); err != nil {
			return nil, "", err
		}
	}

	if state == "" {
		state = "active"
	}

	switch rrtype {
	case dns.TypeKEY:
		// pkc.PrivateKey should already be in PEM format from above
		_, err = tx.Exec(addSig0KeySql, owner, state, pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], creator, pkc.PrivateKey, pkc.KeyRR.String())

	case dns.TypeDNSKEY:
		flags := 257
		if keytype == "ZSK" {
			flags = 256
		}
		// pkc.PrivateKey should already be in PEM format from above. The
		// row's pub and sign follow from its state; a key minted active is
		// active from now.
		row := KeyRow{
			Zone: owner, State: state, Keyid: pkc.KeyId, Flags: uint16(flags),
			Algorithm: dns.AlgorithmToString[pkc.Algorithm], Creator: creator,
			PrivateKey: pkc.PrivateKey, KeyRR: pkc.DnskeyRR.String(),
			RowFlags: cols,
		}
		// the stamp the state owns: a key minted into a state carries the
		// time it entered it, as a transition there would have stamped it
		now := time.Now().UTC().Format(time.RFC3339)
		switch state {
		case DnskeyStateActive:
			row.ActiveAt = now
		case DnskeyStatePublished, DnskeyStateDsPublished:
			row.PublishedAt = now
		case DnskeyStateRetired:
			row.RetiredAt = now
		}
		err = insertKeyRowTx(tx, row)
	}
	if err != nil {
		lgDns.Error("GenerateKeypair: error storing key in keystore", "err", err)
		return nil, "", err
	}

	msg := fmt.Sprintf("Generated new %s %s with keyid %d (initial state: %s)", owner, dns.TypeToString[rrtype], pkc.KeyId, state)
	if localtx {
		if err = tx.Commit(); err != nil {
			return nil, "", err
		}
		committed = true
		if rrtype == dns.TypeDNSKEY {
			// A row that did not exist before is a state change too, and the
			// one a bootstrap-minted active key makes; from is "".
			notifyKeyStateChange(owner, pkc.KeyId, "", state)
			if rerr := republishSigningKeysForZone(kdb, owner); rerr != nil {
				return pkc, msg, fmt.Errorf("GenerateKeypair: republish signing keys: %w", rerr)
			}
		}
	}

	return pkc, msg, nil
}

func LoadSig0SigningKey(keyfile string) (*PrivateKeyCache, error) {
	var pkc *PrivateKeyCache

	if keyfile != "" {
		var err error
		pkc, err = ReadPrivateKey(keyfile)
		if err != nil {
			return nil, fmt.Errorf("error reading SIG(0) key file '%s': %v", keyfile, err)
		}

		if pkc.KeyType != dns.TypeKEY {
			return nil, fmt.Errorf("key must be a KEY RR")
		}
	}
	return pkc, nil
}
