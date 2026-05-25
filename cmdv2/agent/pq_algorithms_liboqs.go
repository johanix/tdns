//go:build liboqs

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * liboqs-backed PQ algorithms. CGO + system liboqs required at
 * build time; resulting binaries link against liboqs (statically on
 * NetBSD pkgsrc, dynamically on macOS MacPorts).
 *
 * Build with `make WITH_LIBOQS=1` (which passes `-tags liboqs`).
 * See dnssec-algorithms/liboqs/liboqs-env.sh for environment setup.
 */

package main

import (
	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"

	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(201, falcon512.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(202, mayo1.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(203, snova24_5_4.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
