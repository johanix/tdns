//go:build sqisign

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * SQIsign-backed PQ algorithm. CGO + the SQIsign reference C library
 * required at build time; resulting binaries link against
 * libsqisign_lvl1*.a (statically) and libgmp (dynamically).
 *
 * tdns-imr needs the real implementation (not just metadata) because
 * iterative resolution includes DNSSEC validation — it must be able
 * to verify SQIsign signatures on incoming responses. The same
 * dns.Algorithm interface that auth uses to sign serves imr's
 * verify path.
 *
 * Build with `make WITH_SQISIGN=1` (which passes `-tags sqisign`).
 * See dnssec-algorithms/sqisignc/sqisign-env.sh for environment setup
 * and dnssec-algorithms/sqisignc/build-sqisign.sh for installing the
 * SQIsign reference library.
 */

package main

import (
	"github.com/johanix/dnssec-algorithms/sqisign1"

	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(204, sqisign1.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
