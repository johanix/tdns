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
	for _, tc := range []struct {
		access, socket string
		wantErr        string
	}{
		{},
		{access: "/etc/tdns/tdns-auth-access.yaml", socket: "/var/run/tdns/tdns-auth.sock"},
		{access: "/etc/tdns/tdns-auth-access.yaml", wantErr: "requires apiserver.socket"},
		{access: "access.yaml", socket: "/var/run/tdns/tdns-auth.sock", wantErr: "absolute"},
		{socket: "/var/run/tdns/tdns-auth.sock"},
	} {
		err := ApiServerConf{AccessFile: tc.access, Socket: tc.socket}.validateAccessSettings()
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("access %q socket %q: err = %v, want %q", tc.access, tc.socket, err, tc.wantErr)
		}
	}
}
