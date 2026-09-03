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

// APIdsyncApiCertCredential manages DSYNC API certificate credentials over the
// MANAGEMENT API. Same socket and operator key as APIdsyncApiCredential; a
// different table and a different lookup key (zone, mech, identity).
func (kdb *KeyDB) APIdsyncApiCertCredential() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp DsyncApiCertCredentialPost
		if err := decoder.Decode(&cp); err != nil {
			lgApi.Warn("error decoding dsync-api cert-credential post", "err", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(DsyncApiCredentialResponse{
				AppName:  Globals.App.Name,
				Time:     time.Now(),
				Error:    true,
				ErrorMsg: fmt.Sprintf("malformed request body: %v", err),
			}); encErr != nil {
				lgApi.Error("error writing dsync-api cert-credential error response", "err", encErr)
			}
			return
		}

		lgApi.Debug("received /dsync-api/cert-credential request", "cmd", cp.Command,
			"zone", cp.Zone, "mech", cp.Mech, "identity", cp.Identity, "from", r.RemoteAddr)

		resp := DsyncApiCredentialResponse{
			AppName: Globals.App.Name,
			Time:    time.Now(),
			Zone:    cp.Zone,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				lgApi.Error("error encoding dsync-api cert-credential response", "err", err)
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
			if err := kdb.AddDsyncApiCertCredential(cp.Zone, cp.Mech, cp.Identity, cp.Principal, cp.Comment, expires); err != nil {
				fail("%v", err)
				return
			}
			resp.Msg = fmt.Sprintf("Certificate credential (%s) for %q in zone %s created.",
				cp.Mech, cp.Identity, cp.Zone)
			lgApi.Info("DSYNC API certificate credential created",
				"zone", cp.Zone, "mech", cp.Mech, "identity", cp.Identity)

		case "list":
			creds, err := kdb.ListDsyncApiAllCredentials(cp.Zone)
			if err != nil {
				fail("%v", err)
				return
			}
			resp.Credentials = creds

		case "delete":
			ok, err := kdb.DeleteDsyncApiCertCredential(cp.Zone, cp.Mech, cp.Identity)
			if err != nil {
				fail("%v", err)
				return
			}
			if !ok {
				fail("no %s credential for %q in zone %s", cp.Mech, cp.Identity, cp.Zone)
				return
			}
			resp.Msg = fmt.Sprintf("Certificate credential (%s) for %q in zone %s deleted.",
				cp.Mech, cp.Identity, cp.Zone)
			lgApi.Info("DSYNC API certificate credential deleted",
				"zone", cp.Zone, "mech", cp.Mech, "identity", cp.Identity)

		case "disable", "enable":
			disable := cp.Command == "disable"
			ok, err := kdb.SetDsyncApiCertCredentialDisabled(cp.Zone, cp.Mech, cp.Identity, disable)
			if err != nil {
				fail("%v", err)
				return
			}
			if !ok {
				fail("no %s credential for %q in zone %s", cp.Mech, cp.Identity, cp.Zone)
				return
			}
			resp.Msg = fmt.Sprintf("Certificate credential (%s) for %q in zone %s %sd.",
				cp.Mech, cp.Identity, cp.Zone, cp.Command)
			lgApi.Info("DSYNC API certificate credential "+cp.Command+"d",
				"zone", cp.Zone, "mech", cp.Mech, "identity", cp.Identity)

		default:
			lgApi.Warn("unknown dsync-api cert-credential command", "cmd", cp.Command)
			fail("unknown command: %q", cp.Command)
		}
	}
}
