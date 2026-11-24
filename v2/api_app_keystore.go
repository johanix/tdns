/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The keystore for application clients: their own keys, and nobody else's.
 * Design: docs/2026-11-23-tdns-api-ownership-design.md sections 4.4, 4.6
 * and 4.7, risks R4 and R9.
 */
package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// appOwnZoneNames lists, by their canonical names, the zones served here
// whose API owner is cert:<app>: the zones whose SIG(0) and DNSSEC keys are
// the application's (design 4.4). A key of a zone not served here is in no
// one's list.
func appOwnZoneNames(app string) []string {
	me := ApiOwnerCertPrefix + app
	names := []string{}
	for item := range Zones.IterBuffered() {
		if item.Val != nil && item.Val.EffectiveApiOwner() == me {
			names = append(names, core.CanonicalizeName(item.Key))
		}
	}
	sort.Strings(names)
	return names
}

// appOwnZonesFilter is the condition that keeps a query of SIG(0) or DNSSEC
// key rows to the zones of the application client app, and its one
// argument: the filter is in the query, not applied to what it returns
// (design R4). The names go in as one JSON array, so that an application
// with many zones needs no more SQL variables than one with a few. A row
// matches by its zone name folded to lower case, which is what
// core.CanonicalizeName does to the names in Zones: a row stored in another
// case is a key of the same zone.
func appOwnZonesFilter(app string) (string, any) {
	b, _ := json.Marshal(appOwnZoneNames(app)) // a []string always marshals
	return "lower(zonename) IN (SELECT value FROM json_each(?))", string(b)
}

// appTsigOwnerFilter is the condition that keeps a query of TSIG keys to
// those of API owner cert:<app>, and its argument.
func appTsigOwnerFilter(app string) (string, any) {
	return "owner = ?", ApiOwnerCertPrefix + app
}

// appKeyZoneRefusal is why the application client app may not touch a
// SIG(0) or DNSSEC key of the zone called zone, or nil when it may (app ""
// is no application client, and may). The key's API owner is its zone's
// (design 4.4), so this is B's zone refusal, on the name the keystore
// command acts on: a zone not served here and another application's get
// the same answer, whether or not the key exists.
func appKeyZoneRefusal(app, zone string) error {
	if app == "" {
		return nil
	}
	name := core.CanonicalizeName(dns.Fqdn(zone))
	zd, _ := Zones.Get(name)
	return appZoneRefusal(app, name, zd)
}

// appKeyZonesRefusal is appKeyZoneRefusal for a command that names its zone
// in more than one field: each must be the application's, so that the
// field the command looks up and the field it writes cannot differ.
func appKeyZonesRefusal(app string, zones ...string) error {
	for _, z := range zones {
		if err := appKeyZoneRefusal(app, z); err != nil {
			return err
		}
	}
	return nil
}

// appBulkKeyRefusal is the per-key check of an application client's SIG(0)
// or DNSSEC bulk import (design 4.6): the reason it may not add a key of
// zone, for the key's disposition, or "" when it may.
func appBulkKeyRefusal(app, zone string) string {
	if err := appKeyZoneRefusal(app, zone); err != nil {
		return fmt.Sprintf("not a zone of API owner %s%s", ApiOwnerCertPrefix, app)
	}
	return ""
}

// appTsigTaken is the reason, for its disposition, that the application
// client app may not import a TSIG key: a key of that name with another
// secret or algorithm belongs to another API owner.
func appTsigTaken(app string) string {
	return "exists with another secret or algorithm; not a key of API owner " + ApiOwnerCertPrefix + app
}

// appTsigKeyIsOwn says whether the TSIG key row is the application client
// app's: true when app is "" (no application client).
func appTsigKeyIsOwn(app string, row TsigKeystoreRow) bool {
	return app == "" || tsigKeystoreEffectiveOwner(row) == ApiOwnerCertPrefix+app
}

// appKeystoreGate refuses an application client a keystore command that
// the application table does not open to it. The middleware has already
// done so; this is the handler's own check on what it decoded, so that a
// path to the handler that skips the middleware does not skip the table.
//
// It also refuses a SIG(0) or DNSSEC command that names a Zone that is not
// the client's, whatever the subcommand checks. After the commit, the
// handler republishes the signing keys of, and re-signs, the zone the
// request names in Zone, while setstate checks the key by Keyname and add
// by the DNSKEY's owner name: an application could otherwise name its own
// key and someone else's zone, and have that zone re-signed.
func appKeystoreGate(app string, kp KeystorePost) error {
	if app == "" {
		return nil
	}
	if ApiAppScopeOf("/api/v1/keystore", kp.Command, kp.SubCommand) == AppRefused {
		return appRefusal(fmt.Sprintf("%s: not available to application clients",
			apiCommandName("/api/v1/keystore", kp.Command, kp.SubCommand)), "")
	}
	switch kp.Command {
	case "sig0-mgmt", "dnssec-mgmt":
		if kp.Zone != "" {
			return appKeyZoneRefusal(app, kp.Zone)
		}
	}
	return nil
}

// writeKeystoreRefusal answers a keystore request refused before the
// handler began, as JSON like its every other answer.
func writeKeystoreRefusal(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(&KeystoreResponse{Error: true, ErrorMsg: err.Error()})
}

// logKeyExports logs, at Info, every private key and TSIG secret a
// successful keystore export hands out, one line per key, with who asked
// (design R9): a stolen certificate that is used to take keys leaves a
// trace of which keys went. Bulk exports log every key, not one line for
// the lot: that one line is what the bulk-export code warns about.
func logKeyExports(ctx context.Context, kp KeystorePost, resp *KeystoreResponse) {
	if resp == nil || resp.Error {
		return
	}
	id, _ := ApiIdentityFrom(ctx)
	log := func(msg, kind string, args ...any) {
		lgApi.Info(msg, append([]any{"client", id.Name, "via", id.Via, "app", id.App, "kind", kind}, args...)...)
	}
	switch kp.SubCommand {
	case "export":
		for _, k := range resp.Sig0keys {
			log("keystore: private key exported", "sig0", "zone", k.Name, "keyid", k.Keyid)
		}
		for _, k := range resp.Dnskeys {
			log("keystore: private key exported", "dnssec", "zone", k.Name, "keyid", k.Keyid)
		}
		if ex := resp.TsigExport; ex != nil {
			log("keystore: TSIG secret exported", "tsig", "key", ex.Name)
		}
	case "bulk-export":
		for _, k := range resp.BulkSig0Keys {
			log("keystore: private key exported", "sig0", "zone", k.Zone, "keyid", k.Keyid, "bulk", true)
		}
		for _, k := range resp.BulkDnssecKeys {
			log("keystore: private key exported", "dnssec", "zone", k.Zone, "keyid", k.Keyid, "bulk", true)
		}
		for _, k := range resp.BulkTsigKeys {
			log("keystore: TSIG secret exported", "tsig", "key", k.Keyname, "bulk", true)
		}
	}
}
