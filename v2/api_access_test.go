package tdns

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
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
		{name: "pin twice", yaml: "clients:\n  - {name: anna, pin: " + pa + ", role: read-only}\n  - {name: bob, pin: " + pa + ", role: read-only}\n", wantErr: "one certificate, one client"},
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

// An access file with the obsolete keyauth: line still parses: the line is
// ignored (and dropped at the daemon's next write).
func TestAccessFileObsoleteKeyAuthParses(t *testing.T) {
	for _, in := range []string{"keyauth: true\n", "keyauth: false\nclients: []\n"} {
		af, err := ParseAccessFile([]byte(in))
		if err != nil || af.KeyAuth == nil {
			t.Errorf("%q: %+v %v, want it parsed with KeyAuth set", in, af, err)
		}
	}
}

// The access file is always on: next to the config file unless
// apiserver.access-file moves it, which must then be absolute.
func TestApiAccessFilePath(t *testing.T) {
	if got := ApiAccessFilePath("", "/etc/tdns/tdns-auth.yaml"); got != "/etc/tdns/tdns-auth-access.yaml" {
		t.Errorf("default = %q", got)
	}
	if got := ApiAccessFilePath("/srv/a.yaml", "/etc/tdns/tdns-auth.yaml"); got != "/srv/a.yaml" {
		t.Errorf("configured = %q", got)
	}
	if got := ApiAccessFilePath("", ""); got != "" {
		t.Errorf("no config file = %q", got)
	}
}

func TestValidateAccessSettings(t *testing.T) {
	const access, sock = "/etc/tdns/tdns-auth-access.yaml", "/var/run/tdns/tdns-auth.sock"
	for _, tc := range []struct {
		name    string
		conf    ApiServerConf
		wantErr string
	}{
		{name: "nothing", conf: ApiServerConf{}},
		{name: "access file and socket", conf: ApiServerConf{AccessFile: access, Socket: sock}},
		// No socket: no admin anywhere, which is the operator's choice.
		{name: "access file, no socket", conf: ApiServerConf{AccessFile: access}},
		{name: "relative access file", conf: ApiServerConf{AccessFile: "access.yaml", Socket: sock}, wantErr: "absolute"},
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

// A command printed for the operator runs as pasted: a path with a space in
// it is quoted, in the touch line and in the chmod a refusal gives.
func TestAccessHintsQuoteThePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my tdns")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tdns-auth-access.yaml")
	if msg := accessFileMissing(path); !strings.Contains(msg, "\n   touch '"+path+"'") {
		t.Errorf("missing-file refusal:\n%s\nwant the path quoted in the touch line", msg)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := CheckAccessFileMode(path); err == nil || !strings.Contains(err.Error(), "\n   chmod go-w '"+path+"'") {
		t.Errorf("writable file: %v, want the path quoted in the chmod line", err)
	}
	if got := shellWord("it's"); got != `'it'\''s'` {
		t.Errorf("shellWord(it's) = %s", got)
	}
}
