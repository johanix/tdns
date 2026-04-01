/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Transaction diagnostic CLI commands for agents and combiners.
 * Provides visibility into open outgoing/incoming transactions and error history.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var AgentTransactionCmd = &cobra.Command{
	Use:   "transaction",
	Short: "Transaction diagnostics",
	Long:  `Commands for diagnosing open transactions, pending confirmations, and errors.`,
}

var CombinerTransactionCmd = &cobra.Command{
	Use:   "transaction",
	Short: "Transaction diagnostics",
	Long:  `Commands for diagnosing transaction errors on the combiner.`,
}

// --- Agent commands ---

var agentTransactionOpenCmd = &cobra.Command{
	Use:   "open",
	Short: "Show open transactions",
	Long:  `Show transactions that have not yet been confirmed.`,
}

var agentTransactionOpenOutgoingCmd = &cobra.Command{
	Use:   "outgoing",
	Short: "Show open outgoing transactions",
	Long:  `Show outgoing transactions that have not yet been confirmed by the receiver.`,
	Run: func(cmd *cobra.Command, args []string) {
		showOpenTransactions(cmd, "agent", "open-outgoing")
	},
}

var agentTransactionOpenIncomingCmd = &cobra.Command{
	Use:   "incoming",
	Short: "Show open incoming transactions (remote syncs awaiting combiner)",
	Long:  `Show incoming remote syncs that have been forwarded to the combiner but not yet confirmed.`,
	Run: func(cmd *cobra.Command, args []string) {
		showOpenTransactions(cmd, "agent", "open-incoming")
	},
}

var agentTransactionErrorsCmd = &cobra.Command{
	Use:   "errors",
	Short: "Show recent transaction errors (combiner only)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Error journal is only available on the combiner. Use 'combiner transaction errors' instead.")
	},
}

// --- Combiner commands ---

var combinerTransactionErrorsCmd = &cobra.Command{
	Use:   "errors",
	Short: "Show recent transaction errors",
	Long:  `Show errors from recent CHUNK NOTIFY processing. Use --last to filter by time window (default: 30m).`,
	Run: func(cmd *cobra.Command, args []string) {
		showTransactionErrors(cmd)
	},
}

var combinerTransactionErrorDetailsCmd = &cobra.Command{
	Use:   "details",
	Short: "Show details for a specific transaction error",
	Long:  `Look up a specific distribution ID in the error journal and show full details.`,
	Run: func(cmd *cobra.Command, args []string) {
		showTransactionErrorDetails(cmd)
	},
}

// --- Implementation ---

func showOpenTransactions(cmd *cobra.Command, component, command string) {
	prefixcmd, _ := GetCommandContext("transaction")
	api, err := GetApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	endpoint := fmt.Sprintf("/%s/transaction", component)
	req := map[string]interface{}{
		"command": command,
	}

	_, buf, err := api.RequestNG("POST", endpoint, req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}

	txnsRaw, ok := resp["transactions"].([]interface{})
	if !ok || len(txnsRaw) == 0 {
		if command == "open-outgoing" {
			fmt.Println("No open outgoing transactions")
		} else {
			fmt.Println("No open incoming transactions")
		}
		return
	}

	var rows []string
	if command == "open-outgoing" {
		rows = append(rows, "DistID | State | Age | Receiver | Operation")
	} else {
		rows = append(rows, "DistID | State | Age | Sender | Operation | Zone")
	}

	for _, tRaw := range txnsRaw {
		if t, ok := tRaw.(map[string]interface{}); ok {
			distID := getStringValue(t, "distribution_id")
			if distID == "" {
				continue
			}
			peer := getStringValue(t, "peer")
			operation := getStringValue(t, "operation")
			age := getStringValue(t, "age")
			state := getStringValue(t, "state")
			if state == "" {
				state = "pending"
			}

			if command == "open-outgoing" {
				rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s",
					distID, state, age, peer, operation))
			} else {
				zone := getStringValue(t, "zone")
				rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
					distID, state, age, peer, operation, zone))
			}
		}
	}

	if len(rows) > 1 {
		output := columnize.SimpleFormat(rows)
		fmt.Println(output)
	}
}

func showTransactionErrors(cmd *cobra.Command) {
	prefixcmd, _ := GetCommandContext("transaction")
	api, err := GetApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	last, _ := cmd.Flags().GetString("last")
	if last == "" {
		last = "30m"
	}

	req := map[string]interface{}{
		"command": "errors",
		"last":    last,
	}

	_, buf, err := api.RequestNG("POST", "/combiner/transaction", req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}

	errorsRaw, ok := resp["errors"].([]interface{})
	if !ok || len(errorsRaw) == 0 {
		fmt.Println("No errors found")
		return
	}

	var rows []string
	rows = append(rows, "DistID | Age | Sender | Operation | QNAME CHUNK")

	for _, eRaw := range errorsRaw {
		if e, ok := eRaw.(map[string]interface{}); ok {
			distID := getStringValue(e, "distribution_id")
			age := getStringValue(e, "age")
			sender := getStringValue(e, "sender")
			msgType := getStringValue(e, "message_type")
			qname := getStringValue(e, "qname")

			rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s CHUNK",
				distID, age, sender, msgType, qname))
		}
	}

	if len(rows) > 1 {
		output := columnize.SimpleFormat(rows)
		fmt.Println(output)
	}
}

func showTransactionErrorDetails(cmd *cobra.Command) {
	prefixcmd, _ := GetCommandContext("transaction")
	api, err := GetApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	distID, _ := cmd.Flags().GetString("distid")
	if distID == "" {
		log.Fatalf("--distid is required")
	}

	req := map[string]interface{}{
		"command": "error-details",
		"dist_id": distID,
	}

	_, buf, err := api.RequestNG("POST", "/combiner/transaction", req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}

	detail, ok := resp["error_detail"].(map[string]interface{})
	if !ok || detail == nil {
		return
	}

	fmt.Printf("\n  Distribution ID: %s\n", getStringValue(detail, "distribution_id"))
	fmt.Printf("  Sender:          %s\n", getStringValue(detail, "sender"))
	fmt.Printf("  Message Type:    %s\n", getStringValue(detail, "message_type"))
	fmt.Printf("  Error:           %s\n", getStringValue(detail, "error_msg"))
	fmt.Printf("  QNAME:           %s CHUNK\n", getStringValue(detail, "qname"))
	fmt.Printf("  Age:             %s\n", getStringValue(detail, "age"))
	fmt.Printf("  Timestamp:       %s\n", getStringValue(detail, "timestamp"))
}

func init() {
	// Agent transaction commands
	agentTransactionOpenCmd.AddCommand(agentTransactionOpenOutgoingCmd, agentTransactionOpenIncomingCmd)
	AgentTransactionCmd.AddCommand(agentTransactionOpenCmd, agentTransactionErrorsCmd)

	// Combiner transaction commands
	combinerTransactionErrorsCmd.AddCommand(combinerTransactionErrorDetailsCmd)
	CombinerTransactionCmd.AddCommand(combinerTransactionErrorsCmd)

	// Flags
	combinerTransactionErrorsCmd.Flags().String("last", "30m", "Time window for error listing (e.g. 30m, 2h, 1h30m)")
	combinerTransactionErrorDetailsCmd.Flags().String("distid", "", "Distribution ID to look up")
	combinerTransactionErrorDetailsCmd.MarkFlagRequired("distid")
}
