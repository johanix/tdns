/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import "github.com/miekg/dns"

// tsigKeyZoneRefCount returns how many live zones (plus catalog groups) reference
// keyname. Used by config-key reconcile to withhold dropping referenced keys (§8).
func (conf *Config) tsigKeyZoneRefCount(keyname string) int {
	c := dns.CanonicalName(keyname)
	if c == "" || tsigNameIsReserved(keyname) {
		return 0
	}
	n := 0
	for item := range Zones.IterBuffered() {
		zd := item.Val
		if zd != nil && zoneDataReferencesTsigKey(zd, c) {
			n++
		}
	}
	if conf.Catalog != nil {
		for _, cg := range conf.Catalog.ConfigGroups {
			if cg != nil && dns.CanonicalName(cg.TsigKey) == c {
				n++
			}
		}
	}
	return n
}

func (conf *Config) tsigKeyReferencedByZone(keyname string) bool {
	return conf.tsigKeyZoneRefCount(keyname) > 0
}

func zoneDataReferencesTsigKey(zd *ZoneData, cname string) bool {
	for _, p := range zd.PrimariesConf {
		if dns.CanonicalName(p.Key) == cname {
			return true
		}
	}
	for _, p := range zd.Upstreams {
		if dns.CanonicalName(p.Key) == cname {
			return true
		}
	}
	for _, p := range zd.Notify {
		if dns.CanonicalName(p.Key) == cname {
			return true
		}
	}
	for _, e := range zd.AllowNotify {
		if dns.CanonicalName(e.Key) == cname {
			return true
		}
	}
	for _, e := range zd.Downstreams {
		if dns.CanonicalName(e.Key) == cname {
			return true
		}
	}
	return false
}
