/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"zgo.at/acidtab"
)

var ScannerCmd = &cobra.Command{
	Use:   "scanner",
	Short: "Interact with tdns-scanner via API",
}

var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Send scan requests to tdns-scanner",
}

var ScanCdsCmd = &cobra.Command{
	Use:   "cds [zone...]",
	Short: "Send CDS scan request with ScanTuple data to tdns-scanner",
	Long:  `Send CDS scan request for one or more zones. Zones can be specified as arguments or via --zone flag.`,
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// Get API client for scanner
		api, err := getApiClient("scanner", true)
		if err != nil {
			log.Fatalf("Error getting API client for scanner: %v", err)
		}

		// Get zones from command arguments
		var zones []string

		// First, use zones from command arguments if provided
		if len(args) > 0 {
			for _, arg := range args {
				zone := strings.TrimSpace(arg)
				if zone != "" {
					zones = append(zones, zone)
				}
			}
		}

		// If no zones from arguments, fall back to --zone flag (single zone)
		if len(zones) == 0 {
			if tdns.Globals.Zonename == "" {
				log.Fatal("Error: specify zones as arguments or use --zone flag")
			}
			zones = []string{tdns.Globals.Zonename}
		}

		if tdns.Globals.Verbose {
			fmt.Printf("Scanning %d zones: %v\n", len(zones), zones)
		}

		// Create scan tuples for all zones
		scanTuples := make([]tdns.ScanTuple, 0, len(zones))
		for _, zone := range zones {
			zone = dns.Fqdn(zone)
			// Create a ScanTuple for CDS scan
			// CurrentData is nil initially (no current data)
			scanTuple := tdns.ScanTuple{
				Zone: zone,
				// Type: tdns.ScanCDS,
				CurrentData: tdns.CurrentScanData{
					CDS: nil, // No current CDS data
				},
			}
			scanTuples = append(scanTuples, scanTuple)
		}

		// Create ScannerPost with the new ScanTuples field
		post := tdns.ScannerPost{
			Command:    "SCAN",
			ScanType:   tdns.ScanCDS,
			ScanTuples: scanTuples,
		}

		// Send request to scanner API
		status, buf, err := api.RequestNG("POST", "/scanner", post, true)
		if err != nil {
			log.Fatalf("Error from scanner API: %v", err)
		}

		if tdns.Globals.Verbose {
			fmt.Printf("Status: %d\n", status)
		}

		var resp tdns.ScannerResponse
		err = json.Unmarshal(buf, &resp)
		if err != nil {
			log.Fatalf("Error unmarshaling response: %v", err)
		}

		if resp.Error {
			log.Fatalf("Error from scanner: %s", resp.ErrorMsg)
		}

		fmt.Printf("Scanner response: %s\n", resp.Msg)
		if resp.Status != "" {
			fmt.Printf("Status: %s\n", resp.Status)
		}
		if resp.JobID != "" {
			fmt.Printf("Job ID: %s\n", resp.JobID)
			fmt.Printf("Use 'tdns-cli scanner status %s' to check job status\n", resp.JobID)
		}
	},
}

var StatusCmd = &cobra.Command{
	Use:   "status [job-id]",
	Short: "Get status of scan job(s)",
	Long:  `Get status of a specific scan job by job ID, or list all jobs if no job ID is provided`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get API client for scanner
		api, err := getApiClient("scanner", true)
		if err != nil {
			log.Fatalf("Error getting API client for scanner: %v", err)
		}

		var endpoint string
		if len(args) > 0 {
			// Specific job
			endpoint = fmt.Sprintf("/scanner/status?job_id=%s", args[0])
		} else {
			// All jobs
			endpoint = "/scanner/status"
		}

		// Send GET request
		status, buf, err := api.RequestNG("GET", endpoint, nil, true)
		if err != nil {
			log.Fatalf("Error from scanner API: %v", err)
		}

		if status == http.StatusNotFound {
			log.Fatalf("Job not found")
		}
		if status == http.StatusBadRequest {
			log.Fatalf("Bad request: %s", string(buf))
		}
		if status != http.StatusOK {
			log.Fatalf("Unexpected status code: %d", status)
		}

		if len(args) > 0 {
			// Single job - show detailed status
			var job tdns.ScanJobStatus
			err = json.Unmarshal(buf, &job)
			if err != nil {
				log.Fatalf("Error unmarshaling job status: %v", err)
			}

			fmt.Printf("Job ID: %s\n", job.JobID)
			fmt.Printf("Status: %s\n", job.Status)
			fmt.Printf("Created: %s\n", job.CreatedAt.Format("2006-01-02 15:04:05"))
			if job.StartedAt != nil {
				fmt.Printf("Started: %s\n", job.StartedAt.Format("2006-01-02 15:04:05"))
			}
			if job.CompletedAt != nil {
				fmt.Printf("Completed: %s\n", job.CompletedAt.Format("2006-01-02 15:04:05"))
			}
			fmt.Printf("Progress: %d/%d tuples processed\n", job.ProcessedTuples, job.TotalTuples)

			if job.Error {
				fmt.Printf("Error: %s\n", job.ErrorMsg)
			}

			if len(job.Responses) > 0 {
				fmt.Printf("\nResults (%d responses):\n", len(job.Responses))
				for i, resp := range job.Responses {
					fmt.Printf("\n  Response %d:\n", i+1)
					fmt.Printf("    Qname: %s\n", resp.Qname)
					fmt.Printf("    Scan Type: %s\n", tdns.ScanTypeToString[resp.ScanType])
					fmt.Printf("    Data Changed: %t\n", resp.DataChanged)
					if resp.AllNSInSync {
						fmt.Printf("    All NS In Sync: true\n")
					} else if len(resp.Options) > 0 {
						for _, opt := range resp.Options {
							if opt == "all-ns" {
								fmt.Printf("    All NS In Sync: false\n")
								break
							}
						}
					}
					if resp.Error {
						fmt.Printf("    Error: %s\n", resp.ErrorMsg)
					}
				}
			}
		} else {
			// All jobs - show summary table
			var jobs []*tdns.ScanJobStatus
			err = json.Unmarshal(buf, &jobs)
			if err != nil {
				log.Fatalf("Error unmarshaling job list: %v", err)
			}

			if len(jobs) == 0 {
				fmt.Println("No jobs found")
				return
			}

			// Sort jobs by creation timestamp (newest first)
			sort.Slice(jobs, func(i, j int) bool {
				return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
			})

			t := acidtab.New("JOB ID", "STATUS", "CREATED", "PROGRESS", "ERROR")
			for _, job := range jobs {
				progress := fmt.Sprintf("%d/%d", job.ProcessedTuples, job.TotalTuples)
				errorStr := ""
				if job.Error {
					errorStr = job.ErrorMsg
					if len(errorStr) > 30 {
						errorStr = errorStr[:27] + "..."
					}
				}
				created := job.CreatedAt.Format("2006-01-02 15:04:05")
				t.Row(job.JobID, job.Status, created, progress, errorStr)
			}
			fmt.Println(t.String())
		}
	},
}

var ResultsCmd = &cobra.Command{
	Use:   "results [job-id]",
	Short: "Get results of a completed scan job",
	Long:  `Get detailed results of a completed scan job by job ID. Use --delete to delete the job after retrieving results.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get API client for scanner
		api, err := getApiClient("scanner", true)
		if err != nil {
			log.Fatalf("Error getting API client for scanner: %v", err)
		}

		jobID := args[0]
		endpoint := fmt.Sprintf("/scanner/status?job_id=%s", jobID)

		// Send GET request
		status, buf, err := api.RequestNG("GET", endpoint, nil, true)
		if err != nil {
			log.Fatalf("Error from scanner API: %v", err)
		}

		if status == http.StatusNotFound {
			log.Fatalf("Job not found: %s", jobID)
		}
		if status != http.StatusOK {
			log.Fatalf("Unexpected status code: %d", status)
		}

		var job tdns.ScanJobStatus
		err = json.Unmarshal(buf, &job)
		if err != nil {
			log.Fatalf("Error unmarshaling job status: %v", err)
		}

		if job.Status != "completed" {
			fmt.Printf("Job %s is not completed yet. Status: %s\n", jobID, job.Status)
			fmt.Printf("Progress: %d/%d tuples processed\n", job.ProcessedTuples, job.TotalTuples)
			return
		}

		if job.Error {
			fmt.Printf("Job %s completed with error: %s\n", jobID, job.ErrorMsg)
			return
		}

		// Check if --delete flag is set
		deleteFlag, _ := cmd.Flags().GetBool("delete")
		if deleteFlag {
			// Delete the job after retrieving results
			deleteEndpoint := fmt.Sprintf("/scanner/delete?job_id=%s", jobID)
			delStatus, delBuf, err := api.RequestNG("DELETE", deleteEndpoint, nil, true)
			if err != nil {
				log.Printf("Warning: Error deleting job %s: %v", jobID, err)
			} else if delStatus == http.StatusOK {
				fmt.Printf("Job %s deleted successfully\n", jobID)
			} else {
				log.Printf("Warning: Failed to delete job %s: status %d, response: %s", jobID, delStatus, string(delBuf))
			}
		}

		// Output results as JSON for easy parsing
		if tdns.Globals.Verbose {
			// Pretty print JSON
			var prettyJSON bytes.Buffer
			json.Indent(&prettyJSON, buf, "", "  ")
			fmt.Println(prettyJSON.String())
		} else {
			// Show summary
			fmt.Printf("Job ID: %s\n", job.JobID)
			fmt.Printf("Status: %s\n", job.Status)
			fmt.Printf("Total Responses: %d\n\n", len(job.Responses))

			for i, resp := range job.Responses {
				fmt.Printf("Response %d: %s (%s)\n", i+1, resp.Qname, tdns.ScanTypeToString[resp.ScanType])
				if resp.DataChanged {
					fmt.Printf("  Data changed: Yes\n")
				} else {
					fmt.Printf("  Data changed: No\n")
				}
				if resp.AllNSInSync {
					fmt.Printf("  All NS in sync: Yes\n")
				} else if len(resp.Options) > 0 {
					for _, opt := range resp.Options {
						if opt == "all-ns" {
							fmt.Printf("  All NS in sync: No\n")
							break
						}
					}
				}
				if resp.Error {
					fmt.Printf("  Error: %s\n", resp.ErrorMsg)
				}
				fmt.Println()
			}
		}
	},
}

var DeleteCmd = &cobra.Command{
	Use:   "delete [job-id]",
	Short: "Delete scan job(s)",
	Long:  `Delete a specific scan job by job ID, or all jobs if --all is used`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get API client for scanner
		api, err := getApiClient("scanner", true)
		if err != nil {
			log.Fatalf("Error getting API client for scanner: %v", err)
		}

		deleteAll, _ := cmd.Flags().GetBool("all")

		var endpoint string
		if deleteAll {
			endpoint = "/scanner/delete?all=true"
		} else if len(args) > 0 {
			endpoint = fmt.Sprintf("/scanner/delete?job_id=%s", args[0])
		} else {
			log.Fatal("Error: either specify a job ID or use --all flag")
		}

		// Send DELETE request
		status, buf, err := api.RequestNG("DELETE", endpoint, nil, true)
		if err != nil {
			log.Fatalf("Error from scanner API: %v", err)
		}

		if status == http.StatusNotFound {
			log.Fatalf("Job not found")
		}
		if status == http.StatusBadRequest {
			log.Fatalf("Bad request: %s", string(buf))
		}
		if status != http.StatusOK {
			log.Fatalf("Unexpected status code: %d", status)
		}

		var resp tdns.ScannerResponse
		err = json.Unmarshal(buf, &resp)
		if err != nil {
			log.Fatalf("Error unmarshaling response: %v", err)
		}

		if resp.Error {
			log.Fatalf("Error: %s", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

func init() {
	// Add scan subcommands
	ScanCmd.AddCommand(ScanCdsCmd)

	// Add --delete flag to ResultsCmd
	ResultsCmd.Flags().Bool("delete", false, "Delete the job after retrieving results")

	// Add --all flag to DeleteCmd
	DeleteCmd.Flags().Bool("all", false, "Delete all jobs")

	// Add scan to scanner
	ScannerCmd.AddCommand(ScanCmd)

	// Add status command to scanner
	ScannerCmd.AddCommand(StatusCmd)

	// Add results command to scanner
	ScannerCmd.AddCommand(ResultsCmd)

	// Add delete command to scanner
	ScannerCmd.AddCommand(DeleteCmd)

	// Add ping to scanner (PingCmd is defined in ping.go)
	ScannerCmd.AddCommand(PingCmd)

	// Add daemon commands to scanner (DaemonCmd is defined in start_cmds.go)
	ScannerCmd.AddCommand(DaemonCmd)
}
