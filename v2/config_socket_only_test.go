package tdns

import (
	"testing"
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
