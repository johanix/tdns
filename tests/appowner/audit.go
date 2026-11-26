/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The audit view: state read over the daemon's local admin socket, which
 * sees everything. A refusal is checked against it (nothing changed), and so
 * is an accepted request (the change is there, with the right API owner).
 * Reads only: the operator's steps go through tdns-ncli.
 */
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

type audit struct{ c *client }

// zones is every zone the daemon serves, with its effective API owner.
func (a audit) zones() (map[string]tdns.ZoneConf, error) {
	resp, o := a.c.zone(tdns.ZonePost{Command: "list-zones"})
	if !o.OK {
		return nil, fmt.Errorf("audit list-zones: %s", o.Msg)
	}
	return resp.Zones, nil
}

// dynamic is the dynamic zones (API-created and catalog members).
func (a audit) dynamic() (map[string]tdns.ZoneConf, error) {
	resp, o := a.c.zone(tdns.ZonePost{Command: "list-dynamic"})
	if !o.OK {
		return nil, fmt.Errorf("audit list-dynamic: %s", o.Msg)
	}
	return resp.Zones, nil
}

// owner is the API owner of zone, and whether the daemon serves it.
func (a audit) owner(zone string) (string, bool, error) {
	zs, err := a.zones()
	if err != nil {
		return "", false, err
	}
	zc, ok := zs[zone]
	return zc.ApiOwner, ok, nil
}

// primaries is the primary addresses (addr/key) of the dynamic zone zone.
func (a audit) primaries(zone string) (string, error) {
	zs, err := a.dynamic()
	if err != nil {
		return "", err
	}
	zc, ok := zs[zone]
	if !ok {
		return "", fmt.Errorf("zone %s is not a dynamic zone here", zone)
	}
	return peerList(zc.Primaries), nil
}

func peerList(ps []tdns.PeerConf) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Addr+"/"+p.Key)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// tsig is every TSIG key, by name.
func (a audit) tsig() (map[string]tdns.TsigKeyInfo, error) {
	resp, o := a.c.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	if !o.OK {
		return nil, fmt.Errorf("audit tsig list: %s", o.Msg)
	}
	out := map[string]tdns.TsigKeyInfo{}
	for _, k := range resp.TsigKeys {
		out[k.Name] = k
	}
	return out, nil
}

// tsigSecret is the secret of the TSIG key name.
func (a audit) tsigSecret(name string) (string, error) {
	resp, o := a.c.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: name})
	if !o.OK {
		return "", fmt.Errorf("audit tsig export %s: %s", name, o.Msg)
	}
	if resp.TsigExport == nil {
		return "", fmt.Errorf("audit tsig export %s: no key in the reply", name)
	}
	return resp.TsigExport.Secret, nil
}

// keyIDs maps "zone::keyid" keys of a keystore listing to zone -> key IDs.
func keyIDs[T any](m map[string]T) map[string][]int {
	out := map[string][]int{}
	for k := range m {
		zone, id, ok := strings.Cut(k, "::")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			continue
		}
		out[zone] = append(out[zone], n)
	}
	for z := range out {
		sort.Ints(out[z])
	}
	return out
}

// dnssec is the DNSSEC key IDs of every zone that has keys, by zone.
func (a audit) dnssec() (map[string][]int, error) {
	resp, o := a.c.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	if !o.OK {
		return nil, fmt.Errorf("audit dnssec list: %s", o.Msg)
	}
	return keyIDs(resp.Dnskeys), nil
}

// dnssecState is the state of zone's DNSSEC key id ("" when there is none).
func (a audit) dnssecState(zone string, id int) (string, error) {
	resp, o := a.c.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	if !o.OK {
		return "", fmt.Errorf("audit dnssec list: %s", o.Msg)
	}
	return resp.Dnskeys[fmt.Sprintf("%s::%d", zone, id)].State, nil
}

// sig0 is the SIG(0) key IDs of every zone that has keys, by zone.
func (a audit) sig0() (map[string][]int, error) {
	resp, o := a.c.keystore(tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "list"})
	if !o.OK {
		return nil, fmt.Errorf("audit sig0 list: %s", o.Msg)
	}
	return keyIDs(resp.Sig0keys), nil
}

// rrsets is what zone publishes at name, by RR type.
func (a audit) rrsets(zone, name string) (map[string][]string, error) {
	resp, o := a.c.zone(tdns.ZonePost{Command: "get-name", Zone: zone, UpdateName: name})
	if !o.OK {
		return nil, fmt.Errorf("audit get-name %s in %s: %s", name, zone, o.Msg)
	}
	if resp.Name == nil {
		return map[string][]string{}, nil
	}
	return resp.Name.RRsets, nil
}

// members is the member zones of the catalog zone cat.
func (a audit) members(cat string) ([]string, error) {
	resp, o := a.c.catalog(tdns.CatalogPost{Command: "zone-list", CatalogZone: cat})
	if !o.OK {
		return nil, fmt.Errorf("audit catalog zone-list %s: %s", cat, o.Msg)
	}
	var out []string
	for z := range resp.Zones {
		out = append(out, z)
	}
	sort.Strings(out)
	return out, nil
}

// memberGroups is the groups of zone in the catalog zone cat.
func (a audit) memberGroups(cat, zone string) ([]string, error) {
	resp, o := a.c.catalog(tdns.CatalogPost{Command: "zone-list", CatalogZone: cat})
	if !o.OK {
		return nil, fmt.Errorf("audit catalog zone-list %s: %s", cat, o.Msg)
	}
	m, ok := resp.Zones[zone]
	if !ok || m == nil {
		return nil, fmt.Errorf("%s is not a member of catalog %s", zone, cat)
	}
	return m.ServiceGroups, nil
}

// scannerPolling says whether the scanner's poll scan is on.
func (a audit) scannerPolling() (bool, error) {
	resp, o := a.c.scannerPoll("status")
	if !o.OK {
		return false, fmt.Errorf("audit scanner poll status: %s", o.Msg)
	}
	return resp.Enabled, nil
}
