/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Rendering keystore private keys as bind9 `Private-key-format: v1.3` text,
 * for `keystore <class> export --format bind` and the bulk equivalent.
 *
 * This is the missing half of a conversion that was one-way: `import` and
 * `bulk-convert` bring bind key files in, but everything on the way out was
 * written as the PKCS#8 PEM the keystore column holds. An export directory
 * therefore LOOKED like a bind key directory -- K<name>+<alg>+<tag> filenames,
 * a .key half in zone-file presentation format -- right up until something
 * opened the .private.
 *
 * This lives daemon-side, and must. (*dns.DNSKEY).PrivateKeyString renders
 * RSA, ECDSA and ED25519 from explicit type cases, but every other algorithm
 * goes through the process-wide algorithm registry -- and tdns-cli
 * deliberately registers NO implementations (see cmdv2/cli/algs.list: it is a
 * management tool, and an empty list keeps it pure Go, with no liboqs, SQIsign
 * or QR-UOV). Rendering in the CLI would therefore have worked for the
 * classical algorithms and failed for all sixteen PQ ones. The daemon links
 * the implementations it can sign with, so it is the only component that can
 * serialize their private keys.
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Accepted values for KeystorePost.KeyFormat.
const (
	KeyFormatPEM  = "pem"
	KeyFormatBind = "bind"
)

// ValidateKeyFormat rejects an unknown format before any key is read, so a
// typo cannot produce a half-written export directory.
func ValidateKeyFormat(f string) error {
	switch f {
	case "", KeyFormatPEM, KeyFormatBind:
		return nil
	default:
		return fmt.Errorf("unknown key format %q (want %q or %q)", f, KeyFormatPEM, KeyFormatBind)
	}
}

// BindPrivateKeyText renders one stored PKCS#8 PEM private key as bind's
// Private-key-format text.
//
// The algorithm comes from the public RR, not from the private key's Go type.
// The PEM carries no DNSSEC algorithm number, and the type does not determine
// one either: ECDSAP256SHA256 and ECDSAP384SHA384 are both *ecdsa.PrivateKey,
// and PrivateKeyString needs the number to pick the right integer width.
func BindPrivateKeyText(keyRR, privPEM string) (string, error) {
	rr, err := dns.NewRR(strings.TrimSpace(keyRR))
	if err != nil {
		return "", fmt.Errorf("unparsable public key RR: %v", err)
	}
	var k *dns.DNSKEY
	switch t := rr.(type) {
	case *dns.DNSKEY:
		k = t
	case *dns.KEY:
		k = &t.DNSKEY
	default:
		return "", fmt.Errorf("public key RR is %T, want DNSKEY or KEY", rr)
	}

	priv, err := PEMToPrivateKey(privPEM)
	if err != nil {
		return "", fmt.Errorf("unusable stored private key: %v", err)
	}

	if err := checkKeyTypeMatchesAlgorithm(k.Algorithm, priv); err != nil {
		return "", err
	}

	out := k.PrivateKeyString(priv)
	if out == "" {
		// PrivateKeyString signals every failure the same way, by returning
		// the empty string: an algorithm with no registered implementation in
		// this binary, one whose implementation cannot marshal its private
		// key, and a key of the wrong type for the algorithm all look alike
		// here. Whichever it is, writing that empty string out is the one
		// thing we must not do -- an empty .private parses as nothing and
		// fails at signing time, far from the export that produced it.
		// bulk-import refuses the mirror image of this on the way in.
		return "", fmt.Errorf("algorithm %d (%s) has no bind private-key representation "+
			"in this daemon: it is either not registered here, or unable to marshal its private key",
			k.Algorithm, dns.AlgorithmToString[k.Algorithm])
	}
	return out, nil
}

// checkKeyTypeMatchesAlgorithm refuses a private key whose Go type does not
// match the algorithm the public RR declares.
//
// PrivateKeyString takes the Algorithm field from the RR but chooses the key
// FIELDS from the Go type, and the two are not cross-checked. An ED25519 key
// carrying an RSASHA256 RR therefore renders as non-empty text labelled
// RSASHA256 with a single "PrivateKey:" line where bind expects Modulus,
// PublicExponent and the rest -- and NewPrivateKey reads it back without
// complaint, because its RSA parser tolerates missing fields. The result is a
// file that looks like a key, imports like a key, and cannot sign.
//
// That mismatch means a corrupt keystore row rather than a normal operation,
// but an export is exactly where it should surface: loudly, naming both sides,
// rather than as a plausible file that fails later.
//
// Only the algorithms PrivateKeyString handles from explicit type cases are
// checked here. Everything else is dispatched through the algorithm registry,
// whose implementations type-assert their own key and return an error, which
// reaches the empty-string guard above.
func checkKeyTypeMatchesAlgorithm(alg uint8, priv crypto.PrivateKey) error {
	mismatch := func(want string) error {
		return fmt.Errorf("stored private key is %T, but the public RR declares algorithm %d (%s), which needs %s: "+
			"the keystore row is inconsistent", priv, alg, dns.AlgorithmToString[alg], want)
	}

	switch alg {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		if _, ok := priv.(*rsa.PrivateKey); !ok {
			return mismatch("an RSA key")
		}
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		k, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return mismatch("an ECDSA key")
		}
		// The curve matters as much as the type: PrivateKeyString pads the
		// scalar to a fixed width chosen from the algorithm, so a P-256 key
		// under ECDSAP384SHA384 would be silently zero-extended.
		want := elliptic.P256()
		if alg == dns.ECDSAP384SHA384 {
			want = elliptic.P384()
		}
		if k.Curve != want {
			return fmt.Errorf("stored private key is on curve %s, but the public RR declares algorithm %d (%s), "+
				"which needs %s: the keystore row is inconsistent",
				k.Curve.Params().Name, alg, dns.AlgorithmToString[alg], want.Params().Name)
		}
	case dns.ED25519:
		if _, ok := priv.(ed25519.PrivateKey); !ok {
			return mismatch("an Ed25519 key")
		}
	}
	return nil
}

// BindTimingTags renders the keystore's per-key timestamps as bind's timing
// tags, to be appended to the Private-key-format body.
//
// Only the three the keystore actually records are emitted. An absent
// timestamp produces no tag at all: bind reads a missing tag as "not
// recorded", which is true, whereas any value we invented would assert an
// event that never happened. ParseBindKeyTimes treats the two the same way on
// the way in.
//
// Created and Delete have no keystore column, and Revoke, DSPublish and
// SyncPublish describe events tdns does not track per key. They are omitted
// rather than approximated.
func BindTimingTags(publishedAt, activeAt, retiredAt string) (string, error) {
	var b strings.Builder
	for _, tag := range []struct{ name, value string }{
		{"Publish", publishedAt},
		{"Activate", activeAt},
		// bind's Inactive is "no longer signing", which is what the keystore
		// calls retired.
		{"Inactive", retiredAt},
	} {
		if strings.TrimSpace(tag.value) == "" {
			continue
		}
		bt, err := RFC3339ToBindTime(tag.value)
		if err != nil {
			return "", fmt.Errorf("%s: %v", tag.name, err)
		}
		fmt.Fprintf(&b, "%s: %s\n", tag.name, bt)
	}
	return b.String(), nil
}

// PrivateKeyForExport returns the bytes to put in a .private file in the
// requested format. Timestamps are optional and ignored for PEM; an empty
// format means PEM, so a caller that has not been taught about formats keeps
// its existing behaviour.
func PrivateKeyForExport(format, keyRR, privPEM, publishedAt, activeAt, retiredAt string) (string, error) {
	// Validated HERE, not only in the CLI. cobra rejects a typo before the
	// request is sent, but the management API takes whatever it is given, and
	// an unrecognised value used to fall through to the PEM branch: a POST
	// with keyformat "Bind" wrote PKCS#8 into a K<name>+<alg>+<tag>.private
	// that still looked like a bind key directory. That is the bug this
	// feature exists to close, on the path that does not go through cobra.
	if err := ValidateKeyFormat(format); err != nil {
		return "", err
	}
	if format != KeyFormatBind {
		return privPEM, nil
	}
	body, err := BindPrivateKeyText(keyRR, privPEM)
	if err != nil {
		return "", err
	}
	times, err := BindTimingTags(publishedAt, activeAt, retiredAt)
	if err != nil {
		return "", err
	}
	return body + times, nil
}

// BindKeyStateText renders one keystore key state as a bind9 `.state` file.
//
// This is the inverse of BindStateToDnssecState, and it is a projection into a
// larger space rather than a reconstruction: bind tracks four INDEPENDENT
// records (DNSKEY, ZRRSIG, KRRSIG, DS), each moving hidden -> rumoured ->
// omnipresent and out through unretentive, while tdns has one ordered state per
// key. There is no way to recover the four from the one.
//
// So the property this aims at is not "the bind state the key once had" -- that
// information never reached the keystore -- but that the round trip through
// tdns is stable: a key exported in state X and read back by bulk-convert must
// land in state X again. Each case below is therefore chosen so that
// BindStateToDnssecState maps it back to the state it came from, and the tests
// assert exactly that for every state.
//
// One state does not survive: STANDBY has no bind representation, because
// BindStateToDnssecState never produces it -- bind's four records cannot say
// "published, ready, waiting to be promoted". A standby key is written as
// published, which is what it looks like in the zone, and comes back as
// published. That is a real narrowing and is called out here rather than
// hidden, since it is the one case where export/import is not identity.
func BindKeyStateText(state string, isKSK bool, publishedAt, activeAt, retiredAt string) (string, error) {
	// dnskey/signing/ds are the three records the forward mapping reads;
	// goal is recorded for bind's benefit and ignored on the way back.
	var dnskey, signing, ds, goal string

	switch state {
	case DnskeyStateCreated:
		dnskey, signing, ds, goal = "hidden", "hidden", "hidden", "hidden"
	case DnskeyStatePublished, DnskeyStateStandby:
		// Not omnipresent on the signing record: that is what separates
		// published from active in the forward mapping.
		dnskey, signing, ds, goal = "rumoured", "hidden", "hidden", "omnipresent"
	case DnskeyStateDsPublished:
		if !isKSK {
			return "", fmt.Errorf("state %q is only meaningful for a KSK", state)
		}
		// DS present but the key not yet signing: the forward mapping checks
		// the signing record first, so it must not be omnipresent here.
		dnskey, signing, ds, goal = "omnipresent", "rumoured", "omnipresent", "omnipresent"
	case DnskeyStateActive:
		dnskey, signing, goal = "omnipresent", "omnipresent", "omnipresent"
		if isKSK {
			ds = "omnipresent"
		} else {
			ds = "hidden"
		}
	case DnskeyStateRetired:
		// Any unretentive record means "being withdrawn" to the forward
		// mapping, and it is checked before everything else.
		dnskey, signing, ds, goal = "unretentive", "unretentive", "hidden", "hidden"
	case DnskeyStateRemoved:
		// Identical tags to created; the timestamps below are what tell the
		// two apart on the way back, so a removed key must carry one.
		dnskey, signing, ds, goal = "hidden", "hidden", "hidden", "hidden"
	default:
		return "", fmt.Errorf("unknown key state %q", state)
	}

	var b strings.Builder
	b.WriteString("; This is the state of a key managed by tdns.\n")
	if isKSK {
		b.WriteString("KSK: yes\nZSK: no\n")
	} else {
		b.WriteString("KSK: no\nZSK: yes\n")
	}
	b.WriteString("DNSKEYState: " + dnskey + "\n")
	if isKSK {
		b.WriteString("KRRSIGState: " + signing + "\nZRRSIGState: hidden\n")
	} else {
		b.WriteString("ZRRSIGState: " + signing + "\nKRRSIGState: hidden\n")
	}
	b.WriteString("DSState: " + ds + "\n")
	b.WriteString("GoalState: " + goal + "\n")

	// Timestamps, gated by the state. A key carries only the milestones it has
	// actually passed: writing Retired on a created key does not merely add
	// noise, it changes the answer, because the forward mapping reads a
	// timestamp on a hidden DNSKEY as "this key was withdrawn" and hands back
	// removed. The keystore can hold a stale value in a column the current
	// state has not reached, so the gate is on the state, not on emptiness.
	reached := map[string]int{
		DnskeyStateCreated: 0, DnskeyStatePublished: 1, DnskeyStateStandby: 1,
		DnskeyStateDsPublished: 1, DnskeyStateActive: 2,
		DnskeyStateRetired: 3, DnskeyStateRemoved: 3,
	}[state]

	for i, tag := range []struct{ name, value string }{
		{"Published", publishedAt},
		{"Active", activeAt},
		{"Retired", retiredAt},
	} {
		if i >= reached {
			continue
		}
		if strings.TrimSpace(tag.value) == "" {
			continue
		}
		bt, err := RFC3339ToBindTime(tag.value)
		if err != nil {
			return "", fmt.Errorf("%s: %v", tag.name, err)
		}
		b.WriteString(tag.name + ": " + bt + "\n")
	}
	if state == DnskeyStateRemoved && strings.TrimSpace(retiredAt) == "" {
		// removed and created carry identical record tags; only a timestamp
		// separates them on the way back. With none recorded, this key would
		// read as created -- a withdrawn key returning as one about to be
		// published. Refuse rather than invent a date: an epoch here would
		// read as a real event in 1970, which is the mistake
		// BindTimeToRFC3339 exists to avoid on the way in.
		return "", fmt.Errorf("key state %q has no retired timestamp, so it cannot be "+
			"distinguished from %q in a bind state file", state, DnskeyStateCreated)
	}
	return b.String(), nil
}
