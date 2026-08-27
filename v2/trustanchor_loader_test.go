package tdns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// The daemons load Config through viper, so the mapstructure tags are what
// decide whether a configured trust anchor reaches the resolver at all.
func TestViperMapsTrustAnchorKeys(t *testing.T) {
	doc := `
imrengine:
   trust-anchor-ds: ". IN DS 56910 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
   trust-anchor-dnskey: ". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA="
   trust-anchor-file: /etc/domain/keys/root.trusted-keys
`
	f := filepath.Join(t.TempDir(), "imr.yaml")
	os.WriteFile(f, []byte(doc), 0o644)
	// An isolated instance, not viper.Reset() on the package global: other
	// tests in this package drive that global, and resetting it here would
	// reach into them. The global merely delegates to a singleton built the
	// same way, so this exercises the identical mapping path.
	v := viper.New()
	v.SetConfigFile(f)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	var c Config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for name, got := range map[string]string{
		"trust-anchor-ds":     c.Imr.TrustAnchorDS,
		"trust-anchor-dnskey": c.Imr.TrustAnchorDNSKEY,
		"trust-anchor-file":   c.Imr.TrustAnchorFile,
	} {
		if got == "" {
			t.Errorf("%s: viper did not populate the field", name)
		} else {
			t.Logf("%-20s -> %.40q", name, got)
		}
	}
}

// dog's standalone lookup must honour the same three settings the IMR does.
func TestImrConfigAnchorsReadsAllThree(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "root.key")
	os.WriteFile(kf, []byte("; comment\n. IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA=\n"), 0o644)

	cases := []struct {
		name, body string
		wantDS     int
		wantKeys   int
	}{
		{"ds only", "imrengine:\n   trust-anchor-ds: \". IN DS 56910 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\"\n", 1, 0},
		{"dnskey only", "imrengine:\n   trust-anchor-dnskey: \". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA=\"\n", 0, 1},
		{"file only", "imrengine:\n   trust-anchor-file: " + kf + "\n", 0, 1},
		{"all three additive", "imrengine:\n   trust-anchor-ds: \". IN DS 56910 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\"\n   trust-anchor-dnskey: \". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA=\"\n   trust-anchor-file: " + kf + "\n", 1, 2},
		{"none", "imrengine:\n   verbose: true\n", 0, 0},
	}
	for _, tc := range cases {
		cf := filepath.Join(dir, "imr-"+tc.name+".yaml")
		os.WriteFile(cf, []byte(tc.body), 0o644)
		ds, keys, src := imrConfigAnchors(cf, func(string, ...any) {})
		if len(ds) != tc.wantDS || len(keys) != tc.wantKeys {
			t.Errorf("%-20s: got %d DS / %d DNSKEY, want %d / %d", tc.name, len(ds), len(keys), tc.wantDS, tc.wantKeys)
			continue
		}
		t.Logf("%-20s: %d DS, %d DNSKEY, source=%q", tc.name, len(ds), len(keys), src)
	}
}
