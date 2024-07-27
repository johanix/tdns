/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
)

var DnskeyCache = NewDnskeyCache()

func NewDnskeyCache() *DnskeyCacheT {
	return &DnskeyCacheT{
		Map: cmap.New[TrustAnchor](),
	}
}

func (dkc *DnskeyCacheT) Get(zonename string, keyid uint16) *TrustAnchor {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	tmp, ok := dkc.Map.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		dkc.Map.Remove(lookupKey)
		log.Printf("DnskeyCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (dkc *DnskeyCacheT) Set(zonename string, keyid uint16, ta *TrustAnchor) {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	dkc.Map.Set(lookupKey, *ta)
}

var Sig0Store = NewSig0StoreT()

func NewSig0StoreT() *Sig0StoreT {
	return &Sig0StoreT{
		Map: cmap.New[Sig0Key](),
	}
}

var RRsetCache = NewRRsetCache()

func NewRRsetCache() *RRsetCacheT {
	return &RRsetCacheT{
		Map: cmap.New[CachedRRset](),
	}
}

func (rsc *RRsetCacheT) Get(qname string, qtype uint16) *CachedRRset {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	tmp, ok := rsc.Map.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		rsc.Map.Remove(lookupKey)
		log.Printf("RRsetCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (rsc *RRsetCacheT) Set(qname string, qtype uint16, rrset *CachedRRset) {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	rsc.Map.Set(lookupKey, *rrset)
}
