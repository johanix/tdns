package tdns

import (
	"strings"
	"testing"
)

// A client made with NewClientWithOptions verifies the daemon by its pin and
// is the client certificate it presents.
func TestClientPinsAndCertificate(t *testing.T) {
	certs, pins := clientCerts(t, "bob")
	e := newAuthEnv(t, "clients:\n  - {name: bob, pin: "+pins["bob"]+", role: read-write}\n", certs)
	serverPin := SPKISHA256(e.srv.Certificate())
	bob := certs["bob"]

	api := NewClientWithOptions("bob", e.srv.URL+"/api/v1", ClientOptions{
		Pins: []string{serverPin}, ClientCert: &bob,
	})
	status, body, err := api.Post("/t-rw", nil)
	if err != nil || status != 200 || !strings.Contains(string(body), "authenticated as bob (read-write) by certificate") {
		t.Errorf("pinned daemon, certificate client: %d %q %v", status, body, err)
	}

	// No pins: every daemon is refused, before anything is sent.
	api = NewClientWithOptions("bob", e.srv.URL+"/api/v1", ClientOptions{ClientCert: &bob})
	if _, _, err := api.Post("/t-rw", nil); err == nil || !strings.Contains(err.Error(), "no certificate pin") {
		t.Errorf("no pins: err = %v, want the daemon refused", err)
	}

	// The wrong pin: the connection is refused before anything is sent.
	api = NewClientWithOptions("bob", e.srv.URL+"/api/v1", ClientOptions{
		Pins: []string{testPin("not-the-daemon")}, ClientCert: &bob,
	})
	if _, _, err := api.Post("/t-rw", nil); err == nil || !strings.Contains(err.Error(), "not one of") {
		t.Errorf("wrong pin: err = %v, want a pin mismatch", err)
	}
	// With PinFix, the refusal names how to take the daemon's new pins.
	api = NewClientWithOptions("bob", e.srv.URL+"/api/v1", ClientOptions{
		Pins: []string{testPin("not-the-daemon")}, ClientCert: &bob,
		PinFix: "tdns-ncli config update bob --repin",
	})
	if _, _, err := api.Post("/t-rw", nil); err == nil || !strings.Contains(err.Error(), "fix: tdns-ncli config update bob --repin") {
		t.Errorf("wrong pin with PinFix: err = %v, want the fix named", err)
	}

	// No client certificate: the daemon sees no credentials at all.
	api = NewClientWithOptions("nobody", e.srv.URL+"/api/v1", ClientOptions{Pins: []string{serverPin}})
	if status, _, _ := api.Post("/t-ro", nil); status != 403 {
		t.Errorf("certificate entry without a certificate: %d, want 403", status)
	}
}
