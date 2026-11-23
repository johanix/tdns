package tdns

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// testPin returns a well-formed SPKI pin derived from seed.
func testPin(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestParseAndValidateAccessFile(t *testing.T) {
	pa, pb := testPin("a"), testPin("b")
	for _, tc := range []struct {
		name    string
		yaml    string
		wantErr string // "" = valid
	}{
		{name: "empty file is an empty policy", yaml: ""},
		{name: "two clients", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: read-write}\n  - {name: bob, pin: " + pb + ", role: read-only, disabled: true, comment: laptop}\n"},
		{name: "admin is refused, and says where it lives", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: admin}\n", wantErr: "only on the local socket"},
		{name: "role required", yaml: "clients:\n  - {name: anna, pin: " + pa + "}\n", wantErr: "role is required"},
		{name: "unknown role", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: operator}\n", wantErr: "unknown role"},
		{name: "name required", yaml: "clients:\n  - {pin: " + pa + ", role: read-only}\n", wantErr: "name is required"},
		{name: "name twice", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: read-only}\n  - {name: anna, pin: " + pb + ", role: read-only}\n", wantErr: "used twice"},
		{name: "pin twice", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: read-only}\n  - {name: bob, pin: " + pa + ", role: read-only}\n", wantErr: "one key, one client"},
		{name: "malformed pin", yaml: "clients:\n  - {name: anna, pin: not-a-pin, role: read-only}\n", wantErr: "not a SPKI SHA-256 pin"},
		{name: "pin required", yaml: "clients:\n  - {name: anna, role: read-only}\n", wantErr: "pin is required"},
		// A misspelt key must not be ignored: "disable" for "disabled" would
		// leave a revoked client enabled.
		{name: "unknown key", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: read-only, disable: true}\n", wantErr: "disable"},
		{name: "unknown top-level key", yaml: "keyauthh: false\n", wantErr: "keyauthh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			af, err := ParseAccessFile([]byte(tc.yaml))
			if err == nil {
				err = ValidateAccessFile(af)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestAccessFileKeyAuth(t *testing.T) {
	for in, want := range map[string]bool{"": true, "keyauth: true\n": true, "keyauth: false\n": false} {
		af, err := ParseAccessFile([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if af.KeyAuthOn() != want {
			t.Errorf("%q: KeyAuthOn = %v, want %v", in, af.KeyAuthOn(), want)
		}
	}
}

func TestValidateAccessSettings(t *testing.T) {
	const access, sock = "/etc/tdns/tdns-auth-access.yaml", "/var/run/tdns/tdns-auth.sock"
	tcp := []string{"127.0.0.1:8989"}
	for _, tc := range []struct {
		name    string
		conf    ApiServerConf
		wantErr string
	}{
		{name: "nothing", conf: ApiServerConf{}},
		{name: "access file and socket", conf: ApiServerConf{AccessFile: access, Socket: sock}},
		{name: "access file, no socket", conf: ApiServerConf{AccessFile: access}, wantErr: "requires apiserver.socket"},
		{name: "relative access file", conf: ApiServerConf{AccessFile: "access.yaml", Socket: sock}, wantErr: "absolute"},
		{name: "socket only", conf: ApiServerConf{Socket: sock}},
		// An access file requires TLS on TCP, loopback included: the
		// socket, not plaintext, is the way in when TLS is broken.
		{name: "access file, TCP with TLS", conf: ApiServerConf{AccessFile: access, Socket: sock, Addresses: tcp, UseTLS: true}},
		{name: "access file, TCP without TLS", conf: ApiServerConf{AccessFile: access, Socket: sock, Addresses: tcp}, wantErr: "requires TLS"},
		{name: "access file, no TCP, usetls false", conf: ApiServerConf{AccessFile: access, Socket: sock}},
		{name: "no access file, TCP without TLS", conf: ApiServerConf{Socket: sock, Addresses: tcp}},
	} {
		err := tc.conf.validateAccessSettings()
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

// Only the canonical spelling of a pin is a pin. The decoder also takes a
// last character that differs in its two unused bits, and embedded newlines;
// each would be a second string for one key.
func TestCheckSpkiPinIsCanonical(t *testing.T) {
	sum := sha256.Sum256([]byte("a public key"))
	pin := base64.StdEncoding.EncodeToString(sum[:])
	if err := checkSpkiPin(pin); err != nil {
		t.Fatalf("canonical pin refused: %v", err)
	}
	// The 43rd character carries 4 data bits and 2 unused ones: flip the
	// lowest unused bit and the string still decodes to the same digest.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, pin[42])
	variant := pin[:42] + string(alphabet[last^1]) + pin[43:]
	if b, err := base64.StdEncoding.DecodeString(variant); err != nil || string(b) != string(sum[:]) {
		t.Fatalf("test setup: %q should decode to the same digest (err %v)", variant, err)
	}
	for name, s := range map[string]string{
		"padding bits": variant,
		"newline":      pin[:20] + "\n" + pin[20:],
	} {
		if err := checkSpkiPin(s); err == nil {
			t.Errorf("%s variant %q accepted", name, s)
		}
	}
}
