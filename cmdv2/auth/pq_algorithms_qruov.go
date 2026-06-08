//go:build qruov

/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * QR-UOV-backed PQ algorithm. CGO + the QR-UOV round2 reference C
 * library required at build time; resulting binaries link against
 * libqruov.a (statically) and libcrypto (OpenSSL).
 *
 * Build with `make WITH_QRUOV=1` (which passes `-tags qruov`).
 * See dnssec-algorithms/qruovc/qruov-env.sh for environment setup
 * and dnssec-algorithms/qruovc/build-qruov.sh for installing the
 * QR-UOV reference library (pinned to the q=31 L=3 parameter set).
 */

package main

import (
	"github.com/johanix/dnssec-algorithms/qruov1"

	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(205, qruov1.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
