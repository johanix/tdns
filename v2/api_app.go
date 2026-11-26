/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Application clients: what each management API command lets one do, and
 * the zone-scope checks the handlers make for them. Design:
 * docs/2026-11-23-tdns-api-ownership-design.md sections 4.2, 4.5 and 4.10.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// AppScope is how a command is scoped for an application client (an
// access-file client that apiserver.app-clients names).
type AppScope int

const (
	// AppRefused: not available to application clients. The zero value,
	// so that a missing entry and an explicit refusal are the same thing.
	AppRefused AppScope = iota
	// AppOpen: touches no zone and no key (ping).
	AppOpen
	// AppOwnZone: the handler resolves the zone it will act on and refuses
	// unless its API owner is the caller.
	AppOwnZone
	// AppOwnList: a listing the handler filters to the caller's zones.
	AppOwnList
	// AppNewZone: creates a zone that does not exist yet (zone add,
	// catalog create); the caller becomes its API owner.
	AppNewZone
	// AppOwnCatalog: the catalog zone must be the caller's.
	AppOwnCatalog
	// AppMemberAndCatalog: the member zone and the catalog zone must both
	// be the caller's.
	AppMemberAndCatalog
	// AppOwnKey: a keystore command on one key, which the handler refuses
	// unless the key is the caller's: a TSIG key of that API owner, a
	// SIG(0) or DNSSEC key of a zone of that API owner (design 4.4).
	AppOwnKey
	// AppNewKey: adds keys, each the caller's: a TSIG key takes the
	// caller as its API owner, a SIG(0) or DNSSEC key must be for a zone
	// of the caller's (design 4.7).
	AppNewKey
	// AppBySubCommand: the command is scoped by the body's SubCommand too,
	// in apiAppSubScopes.
	AppBySubCommand
)

func (s AppScope) String() string {
	switch s {
	case AppOpen:
		return "open"
	case AppOwnZone:
		return "own zone"
	case AppOwnList:
		return "filtered list"
	case AppNewZone:
		return "new zone"
	case AppOwnCatalog:
		return "own catalog zone"
	case AppMemberAndCatalog:
		return "own member and catalog zone"
	case AppOwnKey:
		return "own key"
	case AppNewKey:
		return "new key"
	case AppBySubCommand:
		return "by subcommand"
	}
	return "refused"
}

// apiAppScopes is the application table: for each route and command (as in
// apiRouteRoles, whose keys it has), how an application client is scoped.
//
// FAIL CLOSED: the middleware refuses an application client anything that
// has no entry here, as RequiredApiRole does for roles. An entry that is not
// AppRefused only lets the request reach its handler; the handler then checks
// the zone it resolved (appZoneRefusal), never a field the middleware peeked
// at. TestApiAppTableMatchesTheRoleTable fails when a route or command of
// apiRouteRoles, or one the handlers switch on, has no entry here, so a new
// command is refused for applications until someone decides otherwise.
//
// Refused because they act on the whole server (design 4.5), or because
// they say things about it beyond the caller's zones: command status/api,
// config *, debug *, scanner *, imr *. Refused because they are trust or
// credentials: truststore (list-dnskey included: it lists the DNSKEYs the
// server holds for other zones, not keys an application owns), the DSYNC
// credentials. The keystore is split by SubCommand (apiAppSubScopes). zone
// setowner is the operator's.
var apiAppScopes = map[string]map[string]AppScope{
	"/api/v1/ping": {"*": AppOpen, "": AppOpen},

	"/api/v1/command": {"status": AppRefused, "api": AppRefused, "stop": AppRefused},
	"/api/v1/config": {
		"status":                   AppRefused,
		"identity":                 AppRefused,
		"transport-signal":         AppRefused,
		"reload":                   AppRefused,
		"reload-zones":             AppRefused,
		"transport-signal-release": AppRefused,
		"reload-tsig":              AppRefused,
	},
	"/api/v1/config/paths": {"": AppRefused},
	"/api/v1/debug": {
		"rrset":           AppRefused,
		"validate-rrset":  AppRefused,
		"lav":             AppRefused,
		"show-ta":         AppRefused,
		"show-rrsetcache": AppRefused,
		"zone-txlog":      AppRefused,
	},
	"/api/v1/zone": {
		// list-zones with a zone named is `zone desc` of that zone: own
		// zone only; without one, the caller's zones.
		"list-zones":      AppOwnList,
		"list-dynamic":    AppOwnList,
		"get-name":        AppOwnZone,
		"get-delegation":  AppOwnZone,
		"journal":         AppOwnZone,
		"show-nsec-chain": AppOwnZone,
		"zonemd":          AppOwnZone,
		"proxy-key":       AppOwnZone,
		"bump":            AppOwnZone,
		"write-zone":      AppOwnZone,
		"sync":            AppOwnZone,
		"update":          AppOwnZone, // and every RR at or below the apex
		"sign-zone":       AppOwnZone,
		"resign-zone":     AppOwnZone,
		"policy-set":      AppOwnZone,
		"change-policy":   AppOwnZone,
		"policy-reset":    AppOwnZone,
		"freeze":          AppOwnZone,
		"thaw":            AppOwnZone,
		"reload":          AppOwnZone,
		"add":             AppNewZone,
		"delete":          AppOwnZone, // never --keep-keys
		"modify":          AppOwnZone,
		"setowner":        AppRefused,
	},
	"/api/v1/zone/parentsync": {
		"status":    AppOwnZone,
		"inquire":   AppOwnZone,
		"bootstrap": AppOwnZone,
		"roll-key":  AppOwnZone,
	},
	"/api/v1/zone/childsync": {
		"proxy-status": AppOwnZone,
		"publish":      AppOwnZone,
		"unpublish":    AppOwnZone,
		"advert":       AppOwnZone,
		"reconcile":    AppOwnZone,
	},
	"/api/v1/delegation": {
		"status": AppOwnZone,
		// export writes a file at a path the caller names, on the server:
		// not an application's to do, whatever the zone.
		"export": AppRefused,
		"sync":   AppOwnZone,
		// The log of every child's delegation syncs, answered before the
		// handler resolves a zone: it is not scoped to the caller's zones.
		"sync-log": AppRefused,
	},
	"/api/v1/catalog": {
		// A catalog zone the caller owns is shown whole: its members are
		// that zone's data.
		"zone-list":   AppOwnCatalog,
		"group-list":  AppOwnCatalog,
		"notify-list": AppOwnCatalog,
		"create":      AppNewZone,
		"delete":      AppOwnCatalog,
		"zone-add":    AppMemberAndCatalog,
		// The catalog zone's owner may remove any member (Johan,
		// 2026-11-24): the entry is the catalog zone's data, and a member
		// zone the removal also deletes (catalog-member-auto-delete) is
		// one this catalog created, which has the catalog zone's owner.
		"zone-delete":       AppOwnCatalog,
		"zone-group-add":    AppMemberAndCatalog,
		"zone-group-delete": AppOwnCatalog,
		"group-add":         AppOwnCatalog,
		"group-delete":      AppOwnCatalog,
		"notify-add":        AppOwnCatalog,
		"notify-remove":     AppOwnCatalog,
	},
	"/api/v1/rollover/status":  {"": AppOwnZone},
	"/api/v1/rollover/when":    {"": AppOwnZone},
	"/api/v1/rollover/asap":    {"*": AppOwnZone, "": AppOwnZone},
	"/api/v1/rollover/cancel":  {"*": AppOwnZone, "": AppOwnZone},
	"/api/v1/rollover/reset":   {"*": AppOwnZone, "": AppOwnZone},
	"/api/v1/rollover/unstick": {"*": AppOwnZone, "": AppOwnZone},
	"/api/v1/scanner/poll": {
		"":              AppRefused,
		"status":        AppRefused,
		"on":            AppRefused,
		"off":           AppRefused,
		"follow-config": AppRefused,
	},
	"/api/v1/scanner":        {"status": AppRefused, "scan": AppRefused},
	"/api/v1/scanner/delete": {"": AppRefused},
	"/api/v1/imr": {
		"imr-query":              AppRefused,
		"imr-show":               AppRefused,
		"imr-dump-tuning":        AppRefused,
		"imr-dump-zone-backoffs": AppRefused,
		"imr-resolve":            AppRefused,
		"imr-forward-list":       AppRefused,
		"imr-forward-status":     AppRefused,
		"imr-forward-probe":      AppRefused,
		"imr-stub-list":          AppRefused,
		"imr-stub-status":        AppRefused,
		"imr-stub-probe":         AppRefused,
		"imr-client-stats":       AppRefused,
		"imr-auth-transports":    AppRefused,
		"imr-transport-stats":    AppRefused,
		"imr-flush":              AppRefused,
		"imr-reset":              AppRefused,
	},
	"/api/v1/scanner/status": {"": AppRefused},

	"/api/v1/keystore":                  {"*": AppBySubCommand, "": AppRefused},
	"/api/v1/truststore":                {"*": AppRefused, "": AppRefused},
	"/api/v1/dsync-api/credential":      {"*": AppRefused, "": AppRefused},
	"/api/v1/dsync-api/cert-credential": {"*": AppRefused, "": AppRefused},
	// The access file: credentials, admin on the local socket alone.
	"/api/v1/access": {"*": AppRefused, "": AppRefused},
}

// apiAppSubScopes splits the commands that apiAppScopes marks
// AppBySubCommand by the body's SubCommand: route, then Command, then
// SubCommand, with "*" and "" as in apiAppScopes. It fails closed in the
// same way: a command or subcommand with no entry is refused.
// TestApiAppKeystoreTableMatchesTheHandlers fails when the keystore handler
// or one of its *KeyMgmt functions has a command or subcommand that is not
// here, or when one listed here is gone.
//
// The keystore for application clients (design 4.6): its own keys only.
// Lists and exports are filtered to them in the DB query, adds take the
// caller as the key's API owner (TSIG) or need a zone of its own (SIG(0),
// DNSSEC), and a key command on one key needs a key of its own. Refused
// because they act across API owners: setowner, purge, clear,
// policy-cleanup, check. The handler checks the key or zone once it has
// resolved it (appKeystoreRefusal and its callers in keystore.go and
// tsig_keystore_mgmt.go); this table only lets the request reach it.
var apiAppSubScopes = map[string]map[string]map[string]AppScope{
	"/api/v1/keystore": {
		"tsig-mgmt": {
			"list":        AppOwnList,
			"bulk-export": AppOwnList,
			"export":      AppOwnKey,
			"delete":      AppOwnKey,
			"add":         AppNewKey,
			"generate":    AppNewKey,
			"import":      AppNewKey,
			"bulk-import": AppNewKey,
			"setowner":    AppRefused,
			"purge":       AppRefused,
		},
		"sig0-mgmt": {
			"list":           AppOwnList,
			"bulk-export":    AppOwnList,
			"export":         AppOwnKey,
			"delete":         AppOwnKey,
			"setstate":       AppOwnKey,
			"setparentstate": AppOwnKey,
			"add":            AppNewKey,
			"generate":       AppNewKey,
			"bulk-import":    AppNewKey,
		},
		"dnssec-mgmt": {
			"list":           AppOwnList,
			"bulk-export":    AppOwnList,
			"export":         AppOwnKey,
			"delete":         AppOwnKey,
			"setstate":       AppOwnKey,
			"rollover":       AppOwnKey,
			"add":            AppNewKey,
			"generate":       AppNewKey,
			"bulk-import":    AppNewKey,
			"clear":          AppRefused,
			"policy-cleanup": AppRefused,
			"purge":          AppRefused,
			"check":          AppRefused,
		},
		// No key material: what this server can sign with and the
		// policies it has loaded.
		"list-algorithms": {"*": AppOpen, "": AppOpen},
		"list-policies":   {"*": AppOpen, "": AppOpen},
	},
}

// ApiAppScopeOf is how the command cmd with the subcommand sub (any case)
// on route is scoped for an application client. sub matters only where the
// command is AppBySubCommand. A route or command with no entry is
// AppRefused, routes added outside this package (RegisterApiRouteRoles)
// included.
func ApiAppScopeOf(route, cmd, sub string) AppScope {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	s := lookupAppScope(apiAppScopes[route], cmd)
	if s != AppBySubCommand {
		return s
	}
	subs, ok := apiAppSubScopes[route][cmd]
	if !ok {
		return AppRefused
	}
	s = lookupAppScope(subs, strings.ToLower(strings.TrimSpace(sub)))
	if s == AppBySubCommand {
		return AppRefused // a subcommand is not split again
	}
	return s
}

// lookupAppScope is key's entry in m: its own, else "*" for a non-empty
// key, else AppRefused.
func lookupAppScope(m map[string]AppScope, key string) AppScope {
	if s, ok := m[key]; ok {
		return s
	}
	if key != "" {
		if s, ok := m["*"]; ok {
			return s
		}
	}
	return AppRefused
}

// splitBySubCommand says whether some command on route is scoped by the
// body's SubCommand for application clients.
func splitBySubCommand(route string) bool {
	_, ok := apiAppSubScopes[route]
	return ok
}

// apiCommandName is route, cmd and (where it decides) sub as an operator
// knows the command: "zone bump", "rollover asap", "keystore tsig-mgmt
// purge".
func apiCommandName(route, cmd, sub string) string {
	name := strings.ReplaceAll(strings.Trim(strings.TrimPrefix(route, "/api/v1"), "/"), "/", " ")
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	switch {
	case cmd == unknownCommand:
		return name + " (a command that cannot be read)"
	case cmd != "":
		// "imr imr-flush" reads "imr flush": some routes repeat their
		// own name in their commands.
		cmd = strings.TrimPrefix(cmd, name[strings.LastIndex(name, " ")+1:]+"-")
		return name + " " + apiCommandLabel(route, cmd, strings.ToLower(sub))
	}
	return name
}

// AppClientOf is the name of the application client the request in ctx
// runs for, or "" for every other caller: an operator's certificate, the
// API key, the socket, or a path inside the daemon.
func AppClientOf(ctx context.Context) string {
	if id, ok := ApiIdentityFrom(ctx); ok && id.App && id.Via == ApiViaCertificate {
		return id.Name
	}
	return ""
}

// appRefusal is a refusal of an application client's request: the verdict,
// then what can be done about it on a line of its own, so that a CLI that
// prints it after a prefix keeps both readable.
func appRefusal(verdict, hint string) error {
	if hint == "" {
		return &appRefusedError{verdict}
	}
	return &appRefusedError{fmt.Sprintf("%s\n  %s", verdict, hint)}
}

// appRefusedError is an application client's request refused because of
// what it may do (appRefusal): the client's doing, not the server's
// failure, so the keystore logs it at Info, not at Error.
type appRefusedError struct{ msg string }

func (e *appRefusedError) Error() string { return e.msg }

// logKeyMgmtFailure logs a failed keystore command: at Info when it was an
// application client's request refused (appRefusedError), else at Error.
func logKeyMgmtFailure(what string, err error) {
	var refused *appRefusedError
	if errors.As(err, &refused) {
		lgApi.Info(what+": refused to an application client", "err", err)
		return
	}
	lgApi.Error(what+" failed", "err", err)
}

// appOwnsZone says whether app may see and manage zd: when app is "" (not an
// application client), or when zd's effective API owner is cert:<app>.
func appOwnsZone(app string, zd *ZoneData) bool {
	if app == "" {
		return true
	}
	return zd != nil && zd.EffectiveApiOwner() == ApiOwnerCertPrefix+app
}

// appZoneRefusal is why the application client app may not act on the zone
// called name, which the handler resolved to zd (nil when no zone of that
// name is served here), or nil when it may (app "" is no application
// client, and may).
//
// A zone that is not served here and a zone of another certificate client
// get the same answer, which names neither, so that an application cannot
// probe for other applications' zones. An api or config zone says how an
// operator can hand it over (design R7); the DNS answers for those anyway.
func appZoneRefusal(app, name string, zd *ZoneData) error {
	if appOwnsZone(app, zd) {
		return nil
	}
	me := ApiOwnerCertPrefix + app
	owner := ""
	if zd != nil {
		owner = zd.EffectiveApiOwner()
	}
	switch owner {
	case ApiOwnerApi:
		return appRefusal(fmt.Sprintf("zone %s: API owner is api, not %s", name, me),
			"an operator can hand it over with zone setowner")
	case ApiOwnerConfig:
		return appRefusal(fmt.Sprintf("zone %s: API owner is config, not %s", name, me),
			fmt.Sprintf("an operator grants it with api-owner: %s in the config", me))
	}
	return appRefusal(fmt.Sprintf("zone %s: not a zone of API owner %s", name, me), "")
}

// appZoneRefusalByName is appZoneRefusal for a handler that names its zone
// and looks it up as Zones.Get(name): the name it acts on, resolved the way
// it resolves it.
func appZoneRefusalByName(app, name string) error {
	if app == "" {
		return nil
	}
	zd, _ := Zones.Get(name)
	return appZoneRefusal(app, name, zd)
}

// appUpdateRefusal checks that every RR of a zone update is at or below the
// apex of the zone it goes to. BuildZoneUpdateActions checks the same for
// every verb it knows; this is the application's own check, on what is
// about to be applied, so that a verb added later without one cannot write
// into another zone on an application's behalf.
func appUpdateRefusal(app, zone string, actions []dns.RR) error {
	if app == "" {
		return nil
	}
	for _, rr := range actions {
		if !dns.IsSubDomain(zone, rr.Header().Name) {
			return appRefusal(fmt.Sprintf("zone %s: update refused: %s is not in the zone", zone, rr.Header().Name),
				"every RR of an update must be at or below the apex; nothing was applied")
		}
	}
	return nil
}

// errKeepKeysForApp refuses `zone delete --keep-keys` to an application
// client (design 4.10): it could not re-add the zone while the kept keys
// remain, so they would only be left for an operator to clean up.
var errKeepKeysForApp = appRefusal("zone delete --keep-keys: not available to application clients",
	"kept keys would block your own re-add of the zone")

// appAddRefusal is why the application client app may not add the zone
// name, checked under templateApplyMu, where a delete removes a zone's keys
// and an add registers it: the zone appeared since the add looked, or a
// previous zone of that name left SIG(0) or DNSSEC keys in the keystore
// (design 4.10, R3), which the new zone would inherit by its name. An
// operator's add is never refused for kept keys.
func (conf *Config) appAddRefusal(app, name string) error {
	if app == "" {
		return nil
	}
	if _, exists := Zones.Get(name); exists {
		return fmt.Errorf("zone %s already exists", name)
	}
	kdb := conf.Internal.KeyDB
	if kdb == nil {
		return nil
	}
	dnssec, sig0, err := kdb.countZoneKeys(core.CanonicalizeName(name))
	if err != nil {
		return fmt.Errorf("zone %s not added: the keystore could not be checked for keys of an earlier zone of that name: %v", name, err)
	}
	if n := dnssec + sig0; n > 0 {
		return appRefusal(fmt.Sprintf("zone %s: not added: %d key(s) of an earlier zone remain", name, n),
			"an operator deletes them, or re-adds the zone and uses zone setowner")
	}
	return nil
}

// appTsigKeyRefusal checks the TSIG keys that an application client's zone
// add or modify names for its primaries: each must be the caller's own key,
// or the inline key of the same request (whose secret the caller has just
// shown it knows). Otherwise the server would transfer with someone else's
// secret on the application's behalf.
//
// An add checks twice: once before it takes templateApplyMu, so that a key
// it does not own gets one answer whether or not the key exists, and again
// under the lock, where every add and modify commits its inline key
// (commitStagedTsigKey). Another application's add may register the same
// key name and secret in between, and commitStagedTsigKey takes an
// identical existing key as it is, whoever owns it.
func (conf *Config) appTsigKeyRefusal(app, zone string, primaries []PeerConf, staged *TsigDetails) error {
	if app == "" {
		return nil
	}
	me := ApiOwnerCertPrefix + app
	// An inline key that exists under another API owner is refused, even
	// when identical (Johan, 2026-11-24): the add would be a no-op that
	// keeps the other owner, attach the key to the application's zone,
	// and then block the owner's own delete of the key ("in use").
	if staged != nil {
		if kdb := conf.Internal.KeyDB; kdb != nil {
			if row, err := getTsigKeystoreByName(kdb, staged.Name); err == nil && tsigKeystoreEffectiveOwner(row) != me {
				return appRefusal(fmt.Sprintf("zone %s: TSIG key %s exists and is not a key of API owner %s", zone, staged.Name, me),
					"give the key another name")
			}
		}
	}
	for _, p := range primaries {
		if p.Key == "" || p.Key == NOKEY {
			continue
		}
		if staged != nil && tsigKeyKey(p.Key) == tsigKeyKey(staged.Name) {
			continue
		}
		owner := ""
		if kdb := conf.Internal.KeyDB; kdb != nil {
			if row, err := getTsigKeystoreByName(kdb, p.Key); err == nil {
				owner = row.Owner
			}
		}
		if owner != me {
			return appRefusal(fmt.Sprintf("zone %s: TSIG key %s is not a key of API owner %s", zone, p.Key, me),
				"name a key of your own, or give the key inline")
		}
	}
	return nil
}
