/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"os"
	"text/tabwriter"

	algorithms "github.com/johanix/tdns/v2/algorithms"
)

// PrintVersionAndExit prints the application's exact version plus the
// signature algorithms this binary supports, then exits cleanly. It is
// the shared implementation behind each daemon's --version flag: it
// reads Globals.App (already populated by the app's main) and the
// in-process algorithm registry, so it needs no configuration, no
// database, and no running server — the answer to "what does this exact
// binary support" without starting it.
//
// Only genuinely usable (registered implementation) algorithms are
// listed; metadata-only entries a binary knows the name of but cannot
// sign or verify with are excluded, matching what a server advertises.
func PrintVersionAndExit() {
	fmt.Printf("%s version %s (built %s)\n",
		Globals.App.Name, Globals.App.Version, Globals.App.Date)

	algs := algorithms.All()
	fmt.Printf("\nSupported DNSSEC signature algorithms (%d):\n\n", len(algs))

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  CODE\tNAME\tSIG(0)\tDNSSEC\tKSK\tZSK")
	for _, a := range algs {
		fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%s\t%s\n",
			a.Number, a.Name,
			yn(a.ForSIG0), yn(a.ForDNSSEC), yn(a.ForKSK), yn(a.ForZSK))
	}
	w.Flush()

	os.Exit(0)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}
