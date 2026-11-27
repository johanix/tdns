/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Which role each management API command needs. Design:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md section 3.4.
 */
package tdns

import (
	"strings"
	"sync"
)

// apiRouteRoles maps a route (its mux path template) to the role each command
// on it needs. The command is the request body's Command field, lower-cased;
// "" is a request without one (a GET route, an empty body), and "*" stands for
// every command of the route.
//
// DEFAULT DENY: a route or a command that is not here needs admin, which only
// the local socket has. A forgotten entry makes something too strict, never
// too open. TestApiRoleTableMatchesTheHandlers parses the handlers and fails
// when one of them has a command that is not listed here, or when a command
// listed here is gone, so a new command is a decision rather than an accident.
//
// The rule for "keys": whatever reads, writes or deletes stored key material,
// or decides what is trusted, is admin. Whatever runs the key lifecycle
// through the zone machinery (rollover, roll-key) is an operation, and
// read-write.
var apiRouteRoles = map[string]map[string]ApiRole{
	"/api/v1/ping": {"*": RoleReadOnly, "": RoleReadOnly},

	"/api/v1/command": {
		"status": RoleReadOnly,
		"api":    RoleReadOnly,
		"stop":   RoleAdmin, // cannot be undone through the API
	},
	"/api/v1/config": {
		"status":                   RoleReadOnly,
		"identity":                 RoleReadOnly, // which daemon this is
		"transport-signal":         RoleReadOnly, // a preview
		"reload":                   RoleReadWrite,
		"reload-zones":             RoleReadWrite,
		"transport-signal-release": RoleReadWrite,
		"reload-tsig":              RoleAdmin, // reconciles TSIG secrets into the keystore
	},
	"/api/v1/config/paths": {"": RoleReadOnly},
	"/api/v1/debug": {
		"rrset":           RoleReadOnly,
		"validate-rrset":  RoleReadOnly,
		"lav":             RoleReadOnly,
		"show-ta":         RoleReadOnly,
		"show-rrsetcache": RoleReadOnly,
		"zone-txlog":      RoleReadOnly, // the zone's pending changes
	},
	"/api/v1/zone": {
		"list-zones":      RoleReadOnly,
		"get-name":        RoleReadOnly,
		"get-delegation":  RoleReadOnly,
		"journal":         RoleReadOnly,
		"show-nsec-chain": RoleReadOnly,
		"zonemd":          RoleReadOnly,
		"proxy-key":       RoleReadOnly, // the proxy key's status, not the key
		"list-dynamic":    RoleReadOnly,
		"bump":            RoleReadWrite,
		"write-zone":      RoleReadWrite,
		"sync":            RoleReadWrite,
		"update":          RoleReadWrite,
		"sign-zone":       RoleReadWrite,
		"resign-zone":     RoleReadWrite,
		"policy-set":      RoleReadWrite,
		"change-policy":   RoleReadWrite,
		"policy-reset":    RoleReadWrite,
		"freeze":          RoleReadWrite,
		"thaw":            RoleReadWrite,
		"reload":          RoleReadWrite,
		"add":             RoleReadWrite,
		"delete":          RoleReadWrite,
		"modify":          RoleReadWrite,
		// Hands a zone to an application or takes it back: the operator
		// decides that (docs/2026-11-23-tdns-api-ownership-design.md 4.8).
		"setowner": RoleAdmin,
	},
	"/api/v1/zone/parentsync": {
		"status":    RoleReadOnly,
		"inquire":   RoleReadOnly,
		"bootstrap": RoleReadWrite,
		"roll-key":  RoleReadWrite,
	},
	"/api/v1/zone/childsync": {
		"proxy-status": RoleReadOnly,
		"publish":      RoleReadWrite,
		"unpublish":    RoleReadWrite,
		"advert":       RoleReadWrite,
		"reconcile":    RoleReadWrite,
	},
	"/api/v1/delegation": {
		"status": RoleReadOnly,
		"export": RoleReadOnly,
		"sync":   RoleReadWrite,
		// The delegation-sync log of every child, answered before the
		// handler's zone lookup. Admin, as it was by default before it
		// was listed; whether to open it is a decision of its own.
		"sync-log": RoleAdmin,
	},
	"/api/v1/catalog": {
		"zone-list":         RoleReadOnly,
		"group-list":        RoleReadOnly,
		"notify-list":       RoleReadOnly,
		"create":            RoleReadWrite,
		"delete":            RoleReadWrite,
		"zone-add":          RoleReadWrite,
		"zone-delete":       RoleReadWrite,
		"group-add":         RoleReadWrite,
		"group-delete":      RoleReadWrite,
		"zone-group-add":    RoleReadWrite,
		"zone-group-delete": RoleReadWrite,
		"notify-add":        RoleReadWrite,
		"notify-remove":     RoleReadWrite,
	},
	"/api/v1/rollover/status":  {"": RoleReadOnly},
	"/api/v1/rollover/when":    {"": RoleReadOnly},
	"/api/v1/rollover/asap":    {"*": RoleReadWrite, "": RoleReadWrite},
	"/api/v1/rollover/cancel":  {"*": RoleReadWrite, "": RoleReadWrite},
	"/api/v1/rollover/reset":   {"*": RoleReadWrite, "": RoleReadWrite},
	"/api/v1/rollover/unstick": {"*": RoleReadWrite, "": RoleReadWrite},
	"/api/v1/scanner/poll": {
		"":              RoleReadOnly, // an empty body is "status"
		"status":        RoleReadOnly,
		"on":            RoleReadWrite,
		"off":           RoleReadWrite,
		"follow-config": RoleReadWrite,
	},
	"/api/v1/scanner": {
		"status": RoleReadOnly,
		"scan":   RoleReadWrite,
	},
	"/api/v1/scanner/delete": {"": RoleReadWrite},
	"/api/v1/imr": {
		"imr-query":              RoleReadOnly,
		"imr-show":               RoleReadOnly,
		"imr-dump-tuning":        RoleReadOnly,
		"imr-dump-zone-backoffs": RoleReadOnly,
		"imr-resolve":            RoleReadOnly,
		"imr-forward-list":       RoleReadOnly,
		"imr-forward-status":     RoleReadOnly,
		"imr-forward-probe":      RoleReadOnly,
		"imr-stub-list":          RoleReadOnly,
		"imr-stub-status":        RoleReadOnly,
		"imr-stub-probe":         RoleReadOnly,
		"imr-client-stats":       RoleReadOnly,
		"imr-auth-transports":    RoleReadOnly,
		"imr-transport-stats":    RoleReadOnly,
		"imr-flush":              RoleReadWrite,
		"imr-reset":              RoleReadWrite,
	},
	"/api/v1/scanner/status": {"": RoleReadOnly},

	// Admin, said out loud: key material, trust, and credentials. An
	// application client gets its own keys in the keystore without admin
	// (apiAppSubRoles); nobody else does.
	"/api/v1/keystore":                  {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/truststore":                {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/dsync-api/credential":      {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/dsync-api/cert-credential": {"*": RoleAdmin, "": RoleAdmin},
	// The access file, which the daemon writes: admin for every command,
	// list included, so the local socket only (authenticateApiRequest).
	"/api/v1/access": {"*": RoleAdmin, "": RoleAdmin},
}

var (
	extraRolesMu sync.RWMutex
	extraRoles   = map[string]map[string]ApiRole{}
)

// RegisterApiRouteRoles declares the roles of routes added outside this
// package (tdns-mp's management routes, for one). Without it such a route
// needs admin, which only the local socket has. Call it before the API
// serves; a route of this package cannot be redeclared.
func RegisterApiRouteRoles(route string, roles map[string]ApiRole) {
	extraRolesMu.Lock()
	defer extraRolesMu.Unlock()
	if _, ok := apiRouteRoles[route]; ok {
		return
	}
	m := map[string]ApiRole{}
	for k, v := range roles {
		m[strings.ToLower(strings.TrimSpace(k))] = v
	}
	extraRoles[route] = m
}

// apiAppSubRoles is the role an application client needs on a route whose
// commands the application table splits by SubCommand (apiAppSubScopes), for
// what that table opens to it. What it does not open needs what
// apiRouteRoles says, and so does everything for every other caller.
//
// The keystore is admin (above) for everyone but an application client: an
// application manages its own keys over TCP, without admin (design
// docs/2026-11-23-tdns-api-ownership-design.md 4.6). Read-write for all of
// it, lists and exports included: only a read-write application client gets
// the keystore, as only a read-write operator gets the zones' writes.
var apiAppSubRoles = map[string]ApiRole{
	"/api/v1/keystore": RoleReadWrite,
}

// RequiredApiRole is the role a request needs: route is the matched mux path
// template, cmd the body's Command and sub its SubCommand (any case), app
// whether the caller is an application client. sub matters only to an
// application client on a route of apiAppSubRoles. Anything not declared
// needs admin.
func RequiredApiRole(route, cmd, sub string, app bool) ApiRole {
	if r, ok := apiAppSubRoles[route]; ok && app && ApiAppScopeOf(route, cmd, sub) != AppRefused {
		return r
	}
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	cmds, ok := apiRouteRoles[route]
	if !ok {
		extraRolesMu.RLock()
		cmds, ok = extraRoles[route]
		extraRolesMu.RUnlock()
	}
	if !ok {
		return RoleAdmin
	}
	if r, ok := cmds[cmd]; ok {
		return r
	}
	if cmd != "" {
		if r, ok := cmds["*"]; ok {
			return r
		}
	}
	return RoleAdmin
}

// apiCommandLabel is cmd as a refusal or a log line names it: with sub on a
// route that splits its commands by SubCommand, where cmd alone does not say
// which command was refused ("keystore tsig-mgmt" is list and purge alike).
func apiCommandLabel(route, cmd, sub string) string {
	cmd, sub = strings.TrimSpace(cmd), strings.TrimSpace(sub)
	if !splitBySubCommand(route) || sub == "" {
		return cmd
	}
	if sub == unknownCommand {
		return cmd + " (a subcommand that cannot be read)"
	}
	return cmd + " " + sub
}
