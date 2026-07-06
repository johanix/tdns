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
	"github.com/johanix/dnssec-algorithms/cross_rsdpg_128_small"
	"github.com/johanix/dnssec-algorithms/falcon1024"
	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mayo2"
	"github.com/johanix/dnssec-algorithms/mayo3"
	"github.com/johanix/dnssec-algorithms/mayo5"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"
	"github.com/johanix/dnssec-algorithms/snova25_8_3"
	"github.com/johanix/dnssec-algorithms/snova37_17_2"

	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(201, falcon512.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(202, mayo1.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(203, snova24_5_4.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(206, mayo2.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(207, mayo3.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(208, mayo5.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(209, falcon1024.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(210, snova37_17_2.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(211, snova25_8_3.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	// CROSS RSDP-G-128-small: code-based, KSK-role candidate. imr must
	// register it to VALIDATE such signatures encountered in the wild.
	// See dnssec-algorithms/docs/pqc-algorithm-families.md.
	algs.Register(214, cross_rsdpg_128_small.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}
