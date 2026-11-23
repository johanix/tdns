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

	// Admin, said out loud: key material, trust, and credentials.
	"/api/v1/keystore":                  {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/truststore":                {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/dsync-api/credential":      {"*": RoleAdmin, "": RoleAdmin},
	"/api/v1/dsync-api/cert-credential": {"*": RoleAdmin, "": RoleAdmin},
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

// RequiredApiRole is the role a request needs: route is the matched mux path
// template, cmd the body's Command (any case). Anything not declared needs
// admin.
func RequiredApiRole(route, cmd string) ApiRole {
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
