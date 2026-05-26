//go:build !sqisign

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Default build: the SQIsign-backed PQ algorithm (SQIsign-I) is NOT
 * compiled in. Only its codepoint and name are registered as metadata
 * so the CLI argument validator and --help text still recognize it.
 * Any attempt to sign or verify with codepoint 204 will fail at
 * runtime.
 *
 * Build with `make WITH_SQISIGN=1` (-tags sqisign) to wire in the
 * real implementation from pq_algorithms_sqisign.go.
 */

package main

import (
	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.RegisterMetadata(204, "SQISIGN1", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
