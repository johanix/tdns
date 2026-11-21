package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

// With RootCAs set the client takes the caller's parsed roots and does not
// read RootCA again: a read failure there exits the process, which is what a
// caller that already read the file (tdns-ncli's newApiClientFor) avoids. The
// path below does not exist, so a second read would end this test binary.
func TestClientOptionsRootCAsAreNotReadAgain(t *testing.T) {
	pool := x509.NewCertPool()
	api := NewClientWithOptions("x", "https://127.0.0.1:1/api/v1", ClientOptions{
		ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "/nonexistent/ca.pem", RootCAs: pool,
	})
	tr, ok := api.Client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("transport = %T, want an *http.Transport with a TLS config", api.Client.Transport)
	}
	var cfg *tls.Config = tr.TLSClientConfig
	if cfg.RootCAs != pool || cfg.InsecureSkipVerify {
		t.Errorf("TLS config: RootCAs is the given pool = %v, InsecureSkipVerify = %v", cfg.RootCAs == pool, cfg.InsecureSkipVerify)
	}
}
