/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func checkLines72(t *testing.T, what, text string) {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if len(l) > 72 {
			t.Errorf("%s: line over 72 columns: %q", what, l)
		}
	}
}

// A keystore refusal prints once, verdict first, in lines of at most 72
// characters: the access check's 403 as the daemon worded it (not after
// "Error:"), and the handler's own refusal after "Error:" with its hint on
// a line of its own.
func TestKeystoreRefusalsPrintReadably(t *testing.T) {
	const needsAdmin = "/api/v1/keystore tsig-mgmt purge needs admin, which is available only on the daemon's local admin socket"
	handlerMsg := "zone ops.example.: API owner is api, not cert:provisioner\n  an operator can hand it over with zone setowner"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var kp tdns.KeystorePost
		json.NewDecoder(r.Body).Decode(&kp)
		if kp.SubCommand == "purge" {
			http.Error(w, needsAdmin, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tdns.KeystoreResponse{Error: true, ErrorMsg: handlerMsg})
	}))
	defer srv.Close()
	api := &tdns.ApiClient{Name: "tdns-auth", BaseUrl: srv.URL, AuthMethod: "none", Client: srv.Client()}

	_, err := SendKeystoreCmd(api, tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "purge"})
	got := keystoreErrorText(err)
	if !strings.HasPrefix(got, "refused (HTTP 403):\n  /api/v1/keystore tsig-mgmt purge needs admin") || strings.Contains(got, "Error:") {
		t.Errorf("an access check refusal prints\n%s", got)
	}
	checkLines72(t, "access check refusal", got)

	_, err = SendKeystoreCmd(api, tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "export", Zone: "ops.example."})
	got = keystoreErrorText(err)
	want := "Error: zone ops.example.: API owner is api, not cert:provisioner\n  an operator can hand it over with zone setowner"
	if got != want {
		t.Errorf("a handler refusal prints\n%s\nwant\n%s", got, want)
	}

	long := errors.New("zone a-rather-long-zone-name-for-a-customer.example.: API owner is api, not cert:provisioner\n" +
		"  an operator can hand it over with zone setowner, or an operator grants it in the config")
	got = keystoreErrorText(long)
	if !strings.HasPrefix(got, "Error: zone a-rather-long") || strings.Count(got, "\n") < 2 {
		t.Errorf("a long error prints\n%s", got)
	}
	checkLines72(t, "long error", got)
}

// A bulk import's dispositions: verdict first, one key per line, sorted,
// unchanged keys left out; a refused key's reason on its own lines below
// it, within 72 columns.
func TestBulkImportDispositionsShowRefusals(t *testing.T) {
	out := formatBulkDispositions([]tdns.BulkKeyDisposition{
		{Name: "own.example.", Keyid: 12345, Status: tdns.BulkStatusImported},
		{Name: "other.example.", Keyid: 2002, Status: tdns.BulkStatusRefused, Detail: "not a zone of API owner cert:provisioner"},
		{Name: "granted.example.", Keyid: 4711, Status: tdns.BulkStatusUnchanged},
		{Name: "ops.example.", Keyid: 3003, Status: tdns.BulkStatusRefused, Detail: "not a zone of API owner cert:provisioner"},
		{Name: "theirs.", Status: tdns.BulkStatusRefused, Detail: "exists with another secret or algorithm; not a key of API owner cert:provisioner"},
		{Name: "mine.", Status: tdns.BulkStatusConflict, Detail: "secret"},
	})
	want := strings.Join([]string{
		"  conflict  mine.  (differs: secret)",
		"  imported  own.example. keyid 12345",
		"  refused   ops.example. keyid 3003",
		"            not a zone of API owner cert:provisioner",
		"  refused   other.example. keyid 2002",
		"            not a zone of API owner cert:provisioner",
		"  refused   theirs.",
		"            exists with another secret or algorithm; not a key of API",
		"            owner cert:provisioner",
	}, "\n")
	if out != want {
		t.Errorf("dispositions\n%s\nwant\n%s", out, want)
	}
	checkLines72(t, "dispositions", out)
}
