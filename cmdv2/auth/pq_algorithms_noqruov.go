//go:build !qruov

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Default build: the QR-UOV-backed PQ algorithm (QR-UOV-I) is NOT
 * compiled in. Only its codepoint and name are registered as metadata
 * so the CLI argument validator and --help text still recognize it.
 * Any attempt to sign or verify with codepoint 205 will fail at
 * runtime.
 *
 * Build with `make WITH_QRUOV=1` (-tags qruov) to wire in the real
 * implementation from pq_algorithms_qruov.go.
 */

package main

import (
	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.RegisterMetadata(205, "QRUOV1", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
