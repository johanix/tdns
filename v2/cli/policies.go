/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	tdns "github.com/johanix/tdns/v2"
)

// fetchServerPolicies returns the DNSSEC policies the running server loaded,
// including any rejected at parse (PolicyError set). It hard-fails when the
// server is unreachable — there is no offline fallback, because the point of
// this command is to see what THIS server actually loaded.
func fetchServerPolicies(role string) ([]tdns.DnssecPolicyInfo, error) {
	api, err := GetApiClient(role, false)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s server: %v", role, err)
	}
	resp, err := SendKeystoreCmd(api, tdns.KeystorePost{Command: "list-policies"})
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s server: %v", role, err)
	}
	return resp.Policies, nil
}

// printServerPolicies renders the server's DNSSEC policies as a table. A policy
// with an error shows ERROR in the STATUS column and its reason on a
// continuation line, so a broken policy is impossible to miss.
func printServerPolicies(role string) error {
	pols, err := fetchServerPolicies(role)
	if err != nil {
		return err
	}
	if len(pols) == 0 {
		fmt.Printf("%s server has no DNSSEC policies configured.\n", role)
		return nil
	}
	sort.Slice(pols, func(i, j int) bool { return pols[i].Name < pols[j].Name })

	fmt.Printf("DNSSEC policies on the %s server:\n", role)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tKSK-ALG\tZSK-ALG\tMODE\tKSK-LIFE\tZSK-LIFE\tROLLOVER")
	for _, p := range pols {
		status := "ok"
		if p.PolicyError != "" {
			status = "ERROR"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Name, status, p.KSKAlgorithm, p.ZSKAlgorithm, p.Mode,
			p.KSKLifetime, p.ZSKLifetime, p.RolloverMethod)
	}
	tw.Flush()

	// Error reasons go below the table, not inside it: a long reason in a
	// tab column would stretch every row's NAME width.
	for _, p := range pols {
		if p.PolicyError != "" {
			fmt.Printf("  %s: %s\n", p.Name, p.PolicyError)
		}
	}
	return nil
}
