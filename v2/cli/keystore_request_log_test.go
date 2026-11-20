/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The debug line before a keystore command must carry no key material.
 */

package cli

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
)

func TestKeystoreRequestDebugLogCarriesNoKeyMaterial(t *testing.T) {
	secrets := []string{"SECRET-JWK-d", "SECRET-PEM", "SECRET-TSIG", "SECRET-TSIG-IMPORT", "SECRET-BULK-DNSSEC", "SECRET-BULK-SIG0"}
	post := tdns.KeystorePost{
		Command: "sig0-mgmt", SubCommand: "add", Zone: "zone.example.", Keyname: "zone.example.",
		Keyid: 4711, Algorithm: 15, State: "created",
		JWK:             `{"kty":"OKP","crv":"Ed25519","d":"` + secrets[0] + `"}`,
		PrivateKey:      secrets[1],
		TsigSecret:      secrets[2],
		TsigImportData:  secrets[3],
		PrivateKeyCache: &tdns.PrivateKeyCache{},
		BulkDnssecKeys:  []tdns.BulkDnssecKey{{PrivateKey: secrets[4]}},
		BulkSig0Keys:    []tdns.BulkSig0Key{{PrivateKey: secrets[5]}},
	}

	oldDebug, oldOut, oldFlags := tdns.Globals.Debug, log.Writer(), log.Flags()
	t.Cleanup(func() { tdns.Globals.Debug = oldDebug; log.SetOutput(oldOut); log.SetFlags(oldFlags) })
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)

	tdns.Globals.Debug = true
	logKeystoreRequest("sig0KeyMgmt", post)
	got := buf.String()
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Errorf("debug line carries key material %q: %s", s, got)
		}
	}
	for _, want := range []string{"sig0KeyMgmt", `subcommand="add"`, `zone="zone.example."`, "keyid=4711", "key-material=true"} {
		if !strings.Contains(got, want) {
			t.Errorf("debug line lacks %q: %s", want, got)
		}
	}

	buf.Reset()
	tdns.Globals.Debug = false
	logKeystoreRequest("sig0KeyMgmt", post)
	if buf.Len() != 0 {
		t.Errorf("nothing may be logged without --debug: %q", buf.String())
	}
	if s := keystoreRequestSummary(tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "list"}); !strings.Contains(s, "key-material=false") {
		t.Errorf("a request without keys says %s", s)
	}
}
