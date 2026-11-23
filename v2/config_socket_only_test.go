package tdns

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// A daemon with apiserver.socket and no apiserver.addresses serves the
// socket alone (APIdispatcher), so the config validation tdns-auth and the
// agent run must accept it. With neither, addresses are still required.
func TestApiServerAddressesMayBeLeftOutWithASocket(t *testing.T) {
	v, err := NewCustomValidator()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StructPartial(ApiServerConf{Socket: "/var/run/tdns/tdns-auth.sock"}, "Addresses"); err != nil {
		t.Errorf("socket-only apiserver refused: %v", err)
	}
	if err := v.StructPartial(ApiServerConf{}, "Addresses"); err == nil {
		t.Error("apiserver with neither addresses nor socket accepted")
	}
	if err := v.StructPartial(ApiServerConf{Addresses: []string{"127.0.0.1:8989"}}, "Addresses"); err != nil {
		t.Errorf("apiserver with addresses refused: %v", err)
	}
}

// The whole apiserver section, as ValidateBySection validates it. A
// socket-only daemon needs the key (the router builders refuse to start
// without one) but no certificate: only the TCP listeners use it. The same
// config starts the socket in TestAPIdispatcherServesTheSocket.
func TestSocketOnlyApiServerNeedsNoCertificate(t *testing.T) {
	v, err := NewCustomValidator()
	if err != nil {
		t.Fatal(err)
	}
	const sock = "/var/run/tdns/tdns-auth.sock"
	for _, tc := range []struct {
		name string
		conf ApiServerConf
		ok   bool
	}{
		{"socket and key, no certificate", ApiServerConf{Socket: sock, ApiKey: "k"}, true},
		// `addresses: []` decodes to a non-nil empty slice: still no listener.
		{"socket and key, addresses: [], no certificate", ApiServerConf{Addresses: []string{}, Socket: sock, ApiKey: "k"}, true},
		{"socket, no key", ApiServerConf{Socket: sock}, false},
		{"addresses and key, no certificate", ApiServerConf{Addresses: []string{"127.0.0.1:8989"}, ApiKey: "k"}, false},
		{"socket and key, a certificate that is not there", ApiServerConf{Socket: sock, ApiKey: "k", CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}, false},
	} {
		err := v.Struct(tc.conf)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}

// The same through the daemon's own decoder: `addresses: []` in the file is a
// non-nil empty slice, and it must not demand a certificate.
func TestSocketOnlyApiServerFromYAML(t *testing.T) {
	v, err := NewCustomValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, doc string
		ok        bool
	}{
		{"addresses: []", "apiserver:\n   addresses: []\n   apikey: k\n   socket: /var/run/tdns/tdns-auth.sock\n", true},
		{"no addresses key", "apiserver:\n   apikey: k\n   socket: /var/run/tdns/tdns-auth.sock\n", true},
		{"an address, no certificate", "apiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   apikey: k\n   socket: /var/run/tdns/tdns-auth.sock\n", false},
	} {
		var raw map[string]any
		if err := yaml.Unmarshal([]byte(tc.doc), &raw); err != nil {
			t.Fatalf("%s: yaml: %v", tc.name, err)
		}
		var conf Config
		if err := decodeConfigMap(raw, &conf, nil); err != nil {
			t.Fatalf("%s: decodeConfigMap: %v", tc.name, err)
		}
		if tc.name == "addresses: []" && conf.ApiServer.Addresses == nil {
			t.Fatalf("%s decoded to a nil slice; this test no longer covers the non-nil case", tc.name)
		}
		err := v.Struct(conf.ApiServer)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}
