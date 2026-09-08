/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func postChildSync(t *testing.T, req ZoneChildSyncPost) ZoneChildSyncResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/zone/childsync", bytes.NewReader(body))
	w := httptest.NewRecorder()
	APIzoneChildSync(context.Background(), &Globals.App)(w, r)
	var resp ZoneChildSyncResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding the response: %v (body %q)", err, w.Body.String())
	}
	return resp
}

// The operator surface of a childsync-proxy over the management API:
// proxy-status reports, advert renders what the primary lacks, reconcile
// runs the hook's body. All three are refused on a zone that is not a proxy.
func TestChildSyncProxyAPICommands(t *testing.T) {
	zd := proxyAdvertZone(t, partiallyAdvertisedParent)
	withManualBackend(zd)

	zd.Options[OptChildSyncProxy] = false
	if resp := postChildSync(t, ZoneChildSyncPost{Command: "proxy-status", Zone: "example."}); !resp.Error || !strings.Contains(resp.ErrorMsg, "not a childsync-proxy") {
		t.Fatalf("a non-proxy zone must refuse: %+v", resp)
	}
	zd.Options[OptChildSyncProxy] = true

	advert := postChildSync(t, ZoneChildSyncPost{Command: "advert", Zone: "example."})
	if advert.Error {
		t.Fatalf("advert: %s", advert.ErrorMsg)
	}
	for _, want := range []string{"zone example.\n", "update add _dsync.example.", "\tKEY\t"} {
		if !strings.Contains(advert.Advert, want) {
			t.Errorf("advert lacks %q:\n%s", want, advert.Advert)
		}
	}

	rec := postChildSync(t, ZoneChildSyncPost{Command: "reconcile", Zone: "example."})
	if rec.Error || rec.ProxyStatus == nil || rec.ProxyStatus.State != ChildSyncProxyWaiting || rec.PushStatus == nil {
		t.Fatalf("reconcile: %+v", rec)
	}

	st := postChildSync(t, ZoneChildSyncPost{Command: "proxy-status", Zone: "example."})
	if st.Error || st.ProxyStatus == nil || st.ProxyStatus.Delta != 11 || st.ProxyStatus.Instruction == "" {
		t.Fatalf("proxy-status: %+v", st)
	}
	if len(zd.KeyDB.UpdateQ) != 0 {
		t.Fatal("an operator command published into the agent's own copy of the zone")
	}
}
