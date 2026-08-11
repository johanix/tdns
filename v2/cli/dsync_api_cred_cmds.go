/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var (
	dsyncApiCredZone      string
	dsyncApiCredUser      string
	dsyncApiCredPrincipal string
	dsyncApiCredComment   string
	dsyncApiCredExpires   string
)

// NewDsyncApiCmd builds the "dsync-api" subtree: operator management of the
// credentials registrants use against the DSYNC API scheme
// (docs/2026-08-11-dsync-api-scheme.md).
func NewDsyncApiCmd(role string) *cobra.Command {
	dsyncApi := &cobra.Command{
		Use:   "dsync-api",
		Short: "Manage the DSYNC API scheme",
		Long: `Operator commands for the DSYNC API scheme: the HTTPS channel a child uses to
change its delegation when it cannot sign a DNS message and therefore cannot
use the DSYNC UPDATE scheme.

These commands travel on the management API and require the operator API key.
The credentials they issue authenticate somewhere else entirely -- the DSYNC
API listener -- and every one of them is confined by the parent zone's
updatepolicy.child.`,
	}

	cred := &cobra.Command{
		Use:   "credential",
		Short: "Manage DSYNC API credentials",
	}

	add := &cobra.Command{
		Use:   "add",
		Short: "Issue a credential for one child of one parent zone",
		Long: `Create a <username, key> credential. The key is generated here, shown once, and
stored only as a hash -- there is no way to retrieve it afterwards. If it is
lost, delete the credential and issue another.

The username identifies the principal that the parent zone's updatepolicy.child
is evaluated against, exactly where the SIG(0) signer name goes on the DDNS
path. Name it after the child zone and the policy needs no explanation:

  tdns-cli auth dsync-api credential add --zone example. --user child1.example.

With updatepolicy.child.type "selfsub", that credential may change the allowed
RR types at or below child1.example. and nowhere else.

Use --principal when the account should have a human-readable name:

  tdns-cli auth dsync-api credential add --zone example. \
      --user acme-registrar --principal child1.example.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runDsyncApiCredAdd(role) },
	}
	add.Flags().StringVar(&dsyncApiCredPrincipal, "principal", "",
		"DNS name the update policy is evaluated against (default: the username)")
	add.Flags().StringVar(&dsyncApiCredComment, "comment", "", "Free-text note stored with the credential")
	add.Flags().StringVar(&dsyncApiCredExpires, "expires", "",
		"Expiry as a duration (\"720h\") or RFC3339 timestamp; default: never")

	list := &cobra.Command{
		Use:   "list",
		Short: "List credentials, for one parent zone or for all",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runDsyncApiCredList(role) },
	}

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete a credential outright",
		Long: `Remove the credential and its row. Prefer "disable" when the question "who had
access, and when" might be asked later: disabling stops the credential working
and keeps the record.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runDsyncApiCredSimple(role, "delete") },
	}

	disable := &cobra.Command{
		Use:   "disable",
		Short: "Stop a credential working, keeping its record",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runDsyncApiCredSimple(role, "disable") },
	}

	enable := &cobra.Command{
		Use:   "enable",
		Short: "Re-enable a disabled credential",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runDsyncApiCredSimple(role, "enable") },
	}

	for _, sub := range []*cobra.Command{add, list, del, disable, enable} {
		sub.Flags().StringVarP(&dsyncApiCredZone, "zone", "z", "", "Parent zone the credential is scoped to")
		cred.AddCommand(sub)
	}
	// Every command except list names a single credential.
	for _, sub := range []*cobra.Command{add, del, disable, enable} {
		sub.Flags().StringVarP(&dsyncApiCredUser, "user", "u", "", "Username (required)")
	}

	dsyncApi.AddCommand(cred)
	return dsyncApi
}

// parseCredExpiry accepts a duration from now or an absolute RFC3339 time.
// Both spellings appear in operator habits and neither is obviously the one to
// pick, so both work.
func parseCredExpiry(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("--expires %q is not in the future", s)
		}
		return time.Now().Add(d).Unix(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("--expires %q is neither a duration (\"720h\") nor an RFC3339 timestamp", s)
	}
	if !t.After(time.Now()) {
		return 0, fmt.Errorf("--expires %q is in the past", s)
	}
	return t.Unix(), nil
}

func requireCredArgs(needUser bool) {
	if strings.TrimSpace(dsyncApiCredZone) == "" {
		fmt.Println("Error: --zone is required")
		os.Exit(1)
	}
	if needUser && strings.TrimSpace(dsyncApiCredUser) == "" {
		fmt.Println("Error: --user is required")
		os.Exit(1)
	}
}

func runDsyncApiCredAdd(role string) {
	requireCredArgs(true)

	expires, err := parseCredExpiry(dsyncApiCredExpires)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	resp := sendDsyncApiCredCommand(role, tdns.DsyncApiCredentialPost{
		Command:   "add",
		Zone:      dsyncApiCredZone,
		Username:  dsyncApiCredUser,
		Principal: dsyncApiCredPrincipal,
		Comment:   dsyncApiCredComment,
		ExpiresAt: expires,
	})

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
	// Printed on its own line, unlabelled by anything that would make a
	// copy-paste pick up stray text. This is the only time it exists.
	fmt.Printf("\nUsername: %s\nKey:      %s\n\n", dsyncApiCredUser, resp.Key)
	fmt.Printf("Store the key now. It is not recoverable -- if it is lost, delete this\n" +
		"credential and issue another.\n")
}

func runDsyncApiCredList(role string) {
	// No --zone lists every zone: an operator asking "who has access here"
	// usually wants the whole picture, not one zone at a time.
	resp := sendDsyncApiCredCommand(role, tdns.DsyncApiCredentialPost{
		Command: "list",
		Zone:    dsyncApiCredZone,
	})

	if len(resp.Credentials) == 0 {
		if dsyncApiCredZone == "" {
			fmt.Println("No DSYNC API credentials.")
		} else {
			fmt.Printf("No DSYNC API credentials for zone %s.\n", dsyncApiCredZone)
		}
		return
	}

	out := []string{"Parent zone|Username|Principal|Status|Expires|Comment"}
	for _, c := range resp.Credentials {
		status := "active"
		switch {
		case c.Disabled:
			status = "DISABLED"
		case c.Expired(time.Now()):
			status = "EXPIRED"
		}
		expires := "never"
		if !c.Expires.IsZero() {
			expires = c.Expires.Format(time.RFC3339)
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|%s",
			c.ParentZone, c.Username, c.Principal, status, expires, c.Comment))
	}
	fmt.Println(columnize.SimpleFormat(out))
}

func runDsyncApiCredSimple(role, command string) {
	requireCredArgs(true)
	resp := sendDsyncApiCredCommand(role, tdns.DsyncApiCredentialPost{
		Command:  command,
		Zone:     dsyncApiCredZone,
		Username: dsyncApiCredUser,
	})
	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
}

// sendDsyncApiCredCommand posts to the management API and exits on any error.
// Every caller treats a failure the same way, so the handling lives here rather
// than being repeated five times.
func sendDsyncApiCredCommand(role string, data tdns.DsyncApiCredentialPost) tdns.DsyncApiCredentialResponse {
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		log.Fatalf("Error encoding request: %v", err)
	}

	status, buf, err := api.Post("/dsync-api/credential", bytebuf.Bytes())
	if err != nil {
		// The role, not resp.AppName: on a transport error the response is the
		// zero value and would render the app name as empty.
		fmt.Printf("Error from %s: %v\n", role, err)
		os.Exit(1)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var resp tdns.DsyncApiCredentialResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		fmt.Printf("Error parsing response from %s: %v (json: %q)\n", role, err, string(buf))
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("Error from %s: %s\n", role, resp.ErrorMsg)
		os.Exit(1)
	}
	return resp
}
