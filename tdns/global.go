/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
// "github.com/go-redis/redis"
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
