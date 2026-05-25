//go:build !liboqs

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Default build: liboqs-backed PQ algorithms are NOT compiled in.
 * Only their codepoints and names are registered as metadata so the
 * CLI argument validator and --help text still recognize them. Any
 * attempt to sign or verify with codepoints 201, 202, or 203 will
 * fail at runtime.
 *
 * Build with `make WITH_LIBOQS=1` (-tags liboqs) to wire in the real
 * implementations from pq_algorithms_liboqs.go.
 */

package main

import (
	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.RegisterMetadata(201, "FALCON512", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(202, "MAYO1", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(203, "SNOVA24_5_4", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
