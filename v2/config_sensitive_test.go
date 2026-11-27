package tdns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A SensitiveString is redacted in JSON as it is in logs: anything that sends a
// config struct as JSON must not carry the secret.
func TestSensitiveStringMarshalJSON(t *testing.T) {
	const secret = "s3cret-api-key-value"
	type holder struct {
		Val SensitiveString
		Ptr *SensitiveString
		Map map[string]SensitiveString
	}
	v := SensitiveString(secret)
	b, err := json.Marshal(holder{Val: v, Ptr: &v, Map: map[string]SensitiveString{"k": v}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("secret in JSON: %s", b)
	}
	if strings.Count(string(b), `"[REDACTED]"`) != 3 {
		t.Errorf("want three redacted values, got %s", b)
	}

	// Unset stays visibly unset, so "is a key configured?" still has an answer.
	if b, _ := json.Marshal(SensitiveString("")); string(b) != `""` {
		t.Errorf("empty SensitiveString = %s, want \"\"", b)
	}
}

// `config status` carries the whole apiserver: block; an API key in a config
// written before keys went is not decoded at all, so it cannot be in the
// reply. Drive the real handler and look at the bytes it writes.
func TestConfigStatusCarriesNoApiKey(t *testing.T) {
	const secret = "s3cret-api-key-value"
	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte("apiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   apikey: "+secret+"\n"), &raw); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	if err := decodeConfigMap(raw, conf, nil); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(ConfigPost{Command: "status"})
	rec := httptest.NewRecorder()
	APIconfig(conf)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/config", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("config status reply contains the API key: %s", rec.Body.String())
	}
	var resp ConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ApiServer.Addresses) != 1 {
		t.Errorf("addresses lost: %+v", resp.ApiServer)
	}
}

// `config status` says which config file the daemon runs, absolute: a client
// editing the daemon's files checks that it reaches the daemon it edits.
func TestConfigStatusNamesTheConfigFile(t *testing.T) {
	conf := &Config{}
	conf.Internal.CfgFile = "tdns-auth.yaml" // relative, as from the command line
	body, _ := json.Marshal(ConfigPost{Command: "status"})
	rec := httptest.NewRecorder()
	APIconfig(conf)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/config", bytes.NewReader(body)))
	var resp ConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs("tdns-auth.yaml")
	if resp.ConfigFile != want {
		t.Errorf("ConfigFile %q, want %q", resp.ConfigFile, want)
	}
}
