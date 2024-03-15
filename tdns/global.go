/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
// "github.com/go-redis/redis"
   "github.com/orcaman/concurrent-map/v2"
)

type GlobalStuff struct {
	//	Rdb  	*redis.Client
	IMR     string
	Verbose bool
	Debug   bool
}

var Globals = GlobalStuff{
	IMR:     "8.8.8.8:53",
	Verbose: false,
	Debug:   false,
}

var Zones = cmap.New[*ZoneData]()

var TAStore = NewTAStore()

func NewTAStore() *TAStoreT {
     return &TAStoreT{
		Map:	cmap.New[TrustAnchor](),
     	    }
}

var Sig0Store = NewSig0StoreT()

func NewSig0StoreT() *Sig0StoreT {
     return &Sig0StoreT{
		Map:	cmap.New[Sig0Key](),
	    }
}
