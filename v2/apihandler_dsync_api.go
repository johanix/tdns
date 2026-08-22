/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// APIdsyncApiCredential manages DSYNC API credentials over the MANAGEMENT API.
//
// Two credential systems are in play here and they must not be confused. This
// endpoint sits behind apiserver.apikey -- the trusted-operator credential --
// and its job is to issue and revoke the OTHER kind, the per-registrant
// <username, key> tuples that authenticate against the DSYNC API listener and
// are confined by the zone's update policy. Provisioning is an operator act;
// using what was provisioned is not.
func (kdb *KeyDB) APIdsyncApiCredential() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp DsyncApiCredentialPost
		if err := decoder.Decode(&cp); err != nil {
			// Returning here rather than continuing with a zero-value cp. That
			// left Command empty, so the switch below fell to default and the
			// client was told `unknown command: ""` -- naming a symptom of the
			// real fault (a malformed body) and sending the operator looking
			// for a command name that was never sent.
			lgApi.Warn("error decoding dsync-api credential post", "err", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(DsyncApiCredentialResponse{
				AppName:  Globals.App.Name,
				Time:     time.Now(),
				Error:    true,
				ErrorMsg: fmt.Sprintf("malformed request body: %v", err),
			}); encErr != nil {
				lgApi.Error("error writing dsync-api credential error response", "err", encErr)
			}
			return
		}

		// Username is logged, the key never is: "add" mints one and it exists
		// in plaintext only in the response body.
		lgApi.Debug("received /dsync-api/credential request", "cmd", cp.Command,
			"zone", cp.Zone, "user", cp.Username, "from", r.RemoteAddr)

		resp := DsyncApiCredentialResponse{
			AppName: Globals.App.Name,
			Time:    time.Now(),
			Zone:    cp.Zone,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				lgApi.Error("error encoding dsync-api credential response", "err", err)
			}
		}()

		fail := func(format string, args ...interface{}) {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf(format, args...)
		}

		switch cp.Command {
		case "add":
			var expires time.Time
			if cp.ExpiresAt != 0 {
				expires = time.Unix(cp.ExpiresAt, 0)
			}
			key, err := kdb.AddDsyncApiCredential(cp.Zone, cp.Username, cp.Principal, cp.Comment, expires)
			if err != nil {
				fail("%v", err)
				return
			}
			resp.Key = key
			resp.Msg = fmt.Sprintf("Credential for %q in zone %s created. The key is shown once and is not recoverable.",
				cp.Username, cp.Zone)
			lgApi.Info("DSYNC API credential created", "zone", cp.Zone, "user", cp.Username)

		case "list":
			creds, err := kdb.ListDsyncApiCredentials(cp.Zone)
			if err != nil {
				fail("%v", err)
				return
			}
			resp.Credentials = creds

		case "delete":
			ok, err := kdb.DeleteDsyncApiCredential(cp.Zone, cp.Username)
			if err != nil {
				fail("%v", err)
				return
			}
			if !ok {
				fail("no credential for %q in zone %s", cp.Username, cp.Zone)
				return
			}
			resp.Msg = fmt.Sprintf("Credential for %q in zone %s deleted.", cp.Username, cp.Zone)
			lgApi.Info("DSYNC API credential deleted", "zone", cp.Zone, "user", cp.Username)

		case "disable", "enable":
			disable := cp.Command == "disable"
			ok, err := kdb.SetDsyncApiCredentialDisabled(cp.Zone, cp.Username, disable)
			if err != nil {
				fail("%v", err)
				return
			}
			if !ok {
				fail("no credential for %q in zone %s", cp.Username, cp.Zone)
				return
			}
			resp.Msg = fmt.Sprintf("Credential for %q in zone %s %sd.", cp.Username, cp.Zone, cp.Command)
			lgApi.Info("DSYNC API credential "+cp.Command+"d", "zone", cp.Zone, "user", cp.Username)

		default:
			lgApi.Warn("unknown dsync-api credential command", "cmd", cp.Command)
			fail("unknown command: %q", cp.Command)
		}
	}
}
