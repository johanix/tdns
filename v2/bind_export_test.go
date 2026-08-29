/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// storedKeyPair produces a key pair the way the keystore holds it: a DNSKEY RR
// for the public half, PKCS#8 PEM for the private one.
func storedKeyPair(t *testing.T, alg uint8, bits int) (keyRR, privPEM string, priv any) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: alg,
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	return k.String(), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), priv
}

// A key exported in bind format must parse back to the key that went in.
// Without this the two directions can drift apart silently: the export
// produces a file that looks right, and the failure surfaces only when
// something tries to sign with it.
func TestBindPrivateKeyTextRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  uint8
		bits int
	}{
		{"ED25519", dns.ED25519, 256},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, 256},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, 384},
		{"RSASHA256", dns.RSASHA256, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyRR, privPEM, orig := storedKeyPair(t, tc.alg, tc.bits)

			out, err := BindPrivateKeyText(keyRR, privPEM)
			if err != nil {
				t.Fatalf("BindPrivateKeyText: %v", err)
			}
			if !strings.HasPrefix(out, "Private-key-format: v1.3") {
				t.Errorf("output does not start with the bind format header:\n%s", out)
			}

			rr, err := dns.NewRR(keyRR)
			if err != nil {
				t.Fatalf("NewRR: %v", err)
			}
			back, err := rr.(*dns.DNSKEY).NewPrivateKey(out)
			if err != nil {
				t.Fatalf("re-parsing the exported key: %v", err)
			}

			switch o := orig.(type) {
			case ed25519.PrivateKey:
				b, ok := back.(ed25519.PrivateKey)
				if !ok || !o.Equal(b) {
					t.Error("ed25519 key changed across the round trip")
				}
			case *ecdsa.PrivateKey:
				b, ok := back.(*ecdsa.PrivateKey)
				if !ok || o.D.Cmp(b.D) != 0 {
					t.Error("ecdsa key changed across the round trip")
				}
			case *rsa.PrivateKey:
				b, ok := back.(*rsa.PrivateKey)
				if !ok || o.D.Cmp(b.D) != 0 {
					t.Error("rsa key changed across the round trip")
				}
			default:
				t.Fatalf("unexpected key type %T", orig)
			}
		})
	}
}

// A timestamp the keystore does not hold must produce no tag at all. bind reads
// a missing tag as "not recorded"; a fabricated one asserts an event.
func TestBindTimingTags(t *testing.T) {
	got, err := BindTimingTags("2026-01-02T03:04:05Z", "", "2026-03-04T05:06:07Z")
	if err != nil {
		t.Fatalf("BindTimingTags: %v", err)
	}
	if !strings.Contains(got, "Publish: 20260102030405\n") {
		t.Errorf("Publish tag missing or malformed:\n%s", got)
	}
	if strings.Contains(got, "Activate:") {
		t.Errorf("empty timestamp produced a tag:\n%s", got)
	}
	if !strings.Contains(got, "Inactive: 20260304050607\n") {
		t.Errorf("Inactive tag missing or malformed:\n%s", got)
	}

	if _, err := BindTimingTags("not a timestamp", "", ""); err == nil {
		t.Error("an unparsable timestamp was accepted")
	}
}

// RFC3339ToBindTime and BindTimeToRFC3339 must agree, including on the empty
// value: "not recorded" is a distinct fact from any particular time.
func TestBindTimeRoundTrips(t *testing.T) {
	const bindT = "20260102030405"
	rfc, err := BindTimeToRFC3339(bindT)
	if err != nil {
		t.Fatalf("BindTimeToRFC3339: %v", err)
	}
	back, err := RFC3339ToBindTime(rfc)
	if err != nil {
		t.Fatalf("RFC3339ToBindTime: %v", err)
	}
	if back != bindT {
		t.Errorf("round trip changed %q to %q", bindT, back)
	}
	if got, err := RFC3339ToBindTime(""); err != nil || got != "" {
		t.Errorf(`empty became %q (err %v); it must stay empty`, got, err)
	}
}

// Every failure must be an error, never a shorter file. An empty or truncated
// .private parses as nothing and fails later, at signing time, far from the
// export that produced it.
func TestBindExportFailsRatherThanWritingNothing(t *testing.T) {
	_, privPEM, _ := storedKeyPair(t, dns.ED25519, 256)

	for _, tc := range []struct{ name, keyRR, pem string }{
		{"unparsable RR", "this is not a resource record", privPEM},
		{"wrong RR type", "example. 3600 IN A 192.0.2.1", privPEM},
		{"unusable PEM", "example. 3600 IN DNSKEY 257 3 15 " +
			"aIufB25wu/A9nLOZOm7ZlAxkdQyeCqAQcH7wMCg8DVo=",
			"-----BEGIN PRIVATE KEY-----\nbroken\n-----END PRIVATE KEY-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := BindPrivateKeyText(tc.keyRR, tc.pem)
			if err == nil {
				t.Fatalf("accepted bad input, returning %q", out)
			}
			if out != "" {
				t.Errorf("returned content alongside an error: %q", out)
			}
		})
	}
}

// A private key whose type does not match the algorithm in the public RR must
// be refused. Without the check, PrivateKeyString takes the Algorithm field
// from the RR and the key FIELDS from the Go type, producing text labelled
// RSASHA256 that carries a single ed25519-style "PrivateKey:" line -- which
// NewPrivateKey then reads back without complaint, because its RSA parser
// tolerates missing fields. The result imports cleanly and cannot sign.
func TestBindExportRefusesKeyTypeAlgorithmMismatch(t *testing.T) {
	_, ed25519PEM, _ := storedKeyPair(t, dns.ED25519, 256)
	_, rsaPEM, _ := storedKeyPair(t, dns.RSASHA256, 2048)
	rsaRR, _, _ := storedKeyPair(t, dns.RSASHA256, 2048)
	ecP256RR, _, _ := storedKeyPair(t, dns.ECDSAP256SHA256, 256)
	_, ecP384PEM, _ := storedKeyPair(t, dns.ECDSAP384SHA384, 384)

	for _, tc := range []struct{ name, keyRR, pem, want string }{
		{"ed25519 key under an RSA RR", rsaRR, ed25519PEM, "RSA"},
		{"RSA key under an ECDSA RR", ecP256RR, rsaPEM, "ECDSA"},
		{"P-384 key under a P-256 RR", ecP256RR, ecP384PEM, "curve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := BindPrivateKeyText(tc.keyRR, tc.pem)
			if err == nil {
				t.Fatalf("mismatch accepted, returning:\n%s", out)
			}
			if out != "" {
				t.Errorf("returned content alongside an error: %q", out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not explain the mismatch (want mention of %q): %v", tc.want, err)
			}
		})
	}
}

// NOTE on the empty-string guard in BindPrivateKeyText: with the type check
// above in front of it, the guard now covers only the registry algorithms --
// a codec that parses the PKCS#8 but whose implementation cannot render the
// key. That is not reachable from this package's test binary, where no
// algorithm implementations are registered at all: such a key fails earlier,
// in PEMToPrivateKey, for want of a codec for its OID.

// The default format must hand back exactly what the keystore holds, so the
// existing export/bulk-import round trip is untouched by this change. An empty
// format means the same thing, for callers not yet taught about formats.
func TestPrivateKeyForExportPEMIsVerbatim(t *testing.T) {
	keyRR, privPEM, _ := storedKeyPair(t, dns.ED25519, 256)

	for _, format := range []string{KeyFormatPEM, ""} {
		got, err := PrivateKeyForExport(format, keyRR, privPEM, "2026-01-02T03:04:05Z", "", "")
		if err != nil {
			t.Fatalf("PrivateKeyForExport(%q): %v", format, err)
		}
		if got != privPEM {
			t.Errorf("format %q altered the stored key", format)
		}
	}

	bindOut, err := PrivateKeyForExport(KeyFormatBind, keyRR, privPEM, "2026-01-02T03:04:05Z", "", "")
	if err != nil {
		t.Fatalf("PrivateKeyForExport(bind): %v", err)
	}
	if !strings.Contains(bindOut, "Publish: 20260102030405") {
		t.Errorf("bind format dropped the timing tag:\n%s", bindOut)
	}
}

// An unknown format must be an error at the renderer, not just at the CLI.
// cobra rejects a typo before the request leaves, but the management API takes
// what it is given, and an unrecognised value falling through to the PEM
// branch writes PKCS#8 into a file named and shaped like a bind key -- the
// exact confusion this feature exists to remove.
func TestPrivateKeyForExportRejectsUnknownFormat(t *testing.T) {
	keyRR, privPEM, _ := storedKeyPair(t, dns.ED25519, 256)

	for _, format := range []string{"bind9", "Bind", "BIND", "pkcs8"} {
		out, err := PrivateKeyForExport(format, keyRR, privPEM, "", "", "")
		if err == nil {
			t.Errorf("format %q accepted, returned %d bytes", format, len(out))
		}
		if out != "" {
			t.Errorf("format %q returned content alongside an error", format)
		}
	}
}

func TestValidateKeyFormat(t *testing.T) {
	for _, ok := range []string{KeyFormatPEM, KeyFormatBind, ""} {
		if err := ValidateKeyFormat(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	if err := ValidateKeyFormat("bind9"); err == nil {
		t.Error("a typo in the format was accepted; it would surface as a half-written export")
	}
}

// The property that makes the state file worth writing: a key exported in
// state X must come back as state X when bulk-convert reads it. The bind state
// this produces is a representative, not a reconstruction -- what has to hold
// is that the forward mapping agrees with it.
func TestBindKeyStateRoundTripsThroughTdns(t *testing.T) {
	const (
		pub = "2026-01-02T03:04:05Z"
		act = "2026-02-03T04:05:06Z"
		ret = "2026-03-04T05:06:07Z"
	)
	for _, tc := range []struct {
		state string
		isKSK bool
		want  string // differs from state only where bind cannot express it
	}{
		{DnskeyStateCreated, false, DnskeyStateCreated},
		{DnskeyStateCreated, true, DnskeyStateCreated},
		{DnskeyStatePublished, false, DnskeyStatePublished},
		{DnskeyStatePublished, true, DnskeyStatePublished},
		{DnskeyStateDsPublished, true, DnskeyStateDsPublished},
		{DnskeyStateActive, false, DnskeyStateActive},
		{DnskeyStateActive, true, DnskeyStateActive},
		{DnskeyStateRetired, false, DnskeyStateRetired},
		{DnskeyStateRetired, true, DnskeyStateRetired},
		{DnskeyStateRemoved, false, DnskeyStateRemoved},
		{DnskeyStateRemoved, true, DnskeyStateRemoved},
		// bind has no way to say "published, ready, waiting to be promoted",
		// so standby narrows to published. Asserted so the narrowing is a
		// decision on record rather than a surprise in the field.
		{DnskeyStateStandby, false, DnskeyStatePublished},
		{DnskeyStateStandby, true, DnskeyStatePublished},
	} {
		role := "ZSK"
		if tc.isKSK {
			role = "KSK"
		}
		t.Run(tc.state+"/"+role, func(t *testing.T) {
			text, err := BindKeyStateText(tc.state, tc.isKSK, pub, act, ret)
			if err != nil {
				t.Fatalf("BindKeyStateText: %v", err)
			}
			st, err := ParseBindKeyState([]byte(text))
			if err != nil {
				t.Fatalf("ParseBindKeyState on our own output: %v\n%s", err, text)
			}
			got, err := BindStateToDnssecState(st, tc.isKSK)
			if err != nil {
				t.Fatalf("BindStateToDnssecState: %v\n%s", err, text)
			}
			if got != tc.want {
				t.Errorf("state %q (%s) came back as %q, want %q\n%s",
					tc.state, role, got, tc.want, text)
			}
		})
	}
}

func TestBindKeyStateTextRejectsWhatItCannotExpress(t *testing.T) {
	// removed with no timestamp is indistinguishable from created.
	if _, err := BindKeyStateText(DnskeyStateRemoved, false, "", "", ""); err == nil {
		t.Error("removed without a retired timestamp was accepted; it reads back as created")
	}
	// ds-published is a KSK notion.
	if _, err := BindKeyStateText(DnskeyStateDsPublished, false, "", "", ""); err == nil {
		t.Error("ds-published accepted for a ZSK")
	}
	if _, err := BindKeyStateText("no-such-state", false, "", "", ""); err == nil {
		t.Error("an unknown state was accepted")
	}
}
