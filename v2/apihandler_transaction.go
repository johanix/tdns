/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Transaction diagnostic API endpoints for agents and combiners.
 * Provides visibility into open outgoing/incoming transactions and error history.
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// TransactionPost represents a request to the transaction API
type TransactionPost struct {
	Command string `json:"command"`           // "open-outgoing", "open-incoming", "errors", "error-details"
	Last    string `json:"last,omitempty"`    // Duration filter for errors (e.g. "30m", "2h")
	DistID  string `json:"dist_id,omitempty"` // For error-details: specific distribution ID
}

// TransactionSummary contains summary information about an open transaction
type TransactionSummary struct {
	DistributionID string `json:"distribution_id"`
	Peer           string `json:"peer"` // Receiver (outgoing) or Sender (incoming)
	Operation      string `json:"operation"`
	Zone           string `json:"zone,omitempty"`
	Age            string `json:"age"`
	CreatedAt      string `json:"created_at"`
	State          string `json:"state,omitempty"`
}

// TransactionErrorSummary contains summary information about a transaction error
type TransactionErrorSummary struct {
	DistributionID string `json:"distribution_id"`
	Age            string `json:"age"`
	Sender         string `json:"sender"`
	MessageType    string `json:"message_type"`
	ErrorMsg       string `json:"error_msg"`
	QNAME          string `json:"qname"`
	Timestamp      string `json:"timestamp"`
}

// TransactionResponse represents a response from the transaction API
type TransactionResponse struct {
	Time         time.Time                  `json:"time"`
	Error        bool                       `json:"error,omitempty"`
	ErrorMsg     string                     `json:"error_msg,omitempty"`
	Msg          string                     `json:"msg,omitempty"`
	Transactions []*TransactionSummary      `json:"transactions,omitempty"`
	Errors       []*TransactionErrorSummary `json:"errors,omitempty"`
	ErrorDetail  *TransactionErrorSummary   `json:"error_detail,omitempty"`
}

// APIagentTransaction handles transaction diagnostic requests for agents
func (conf *Config) APIagentTransaction(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req TransactionPost
		err := decoder.Decode(&req)
		if err != nil {
			log.Println("APIagentTransaction: error decoding request:", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("API: received /agent/transaction request (cmd: %s) from %s.", req.Command, r.RemoteAddr)

		resp := TransactionResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		switch req.Command {
		case "open-outgoing":
			if cache == nil {
				resp.Error = true
				resp.ErrorMsg = "Distribution cache not configured"
				return
			}
			senderID := string(conf.Agent.Identity)
			infos := cache.List(senderID)
			now := time.Now()

			var summaries []*TransactionSummary
			for _, info := range infos {
				if info.State == "confirmed" {
					continue // Only show non-confirmed
				}
				age := now.Sub(info.CreatedAt)
				summaries = append(summaries, &TransactionSummary{
					DistributionID: info.DistributionID,
					Peer:           info.ReceiverID,
					Operation:      info.Operation,
					Age:            formatDuration(age),
					CreatedAt:      info.CreatedAt.Format(time.RFC3339),
					State:          info.State,
				})
			}
			resp.Transactions = summaries
			resp.Msg = fmt.Sprintf("Found %d open outgoing transaction(s)", len(summaries))

		case "open-incoming":
			// Query PendingRemoteConfirms on the agent side
			zdr := conf.Internal.ZoneDataRepo
			if zdr == nil {
				resp.Error = true
				resp.ErrorMsg = "ZoneDataRepo not configured"
				return
			}
			now := time.Now()

			var summaries []*TransactionSummary
			if zdr.PendingRemoteConfirms != nil {
				for combinerDistID, prc := range zdr.PendingRemoteConfirms {
					summaries = append(summaries, &TransactionSummary{
						DistributionID: combinerDistID,
						Peer:           prc.OriginatingSender,
						Operation:      "remote-sync",
						Zone:           string(prc.Zone),
						Age:            formatDuration(now.Sub(now)), // We don't track creation time on PendingRemoteConfirmation
						CreatedAt:      "",
						State:          "awaiting-combiner",
					})
				}
			}
			resp.Transactions = summaries
			resp.Msg = fmt.Sprintf("Found %d open incoming transaction(s)", len(summaries))

		case "errors":
			resp.Error = true
			resp.ErrorMsg = "Error journal is only available on the combiner. Use 'combiner transaction errors' instead."

		case "error-details":
			resp.Error = true
			resp.ErrorMsg = "Error journal is only available on the combiner. Use 'combiner transaction errors details' instead."

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// APIcombinerTransaction handles transaction diagnostic requests for combiners
func (conf *Config) APIcombinerTransaction() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req TransactionPost
		err := decoder.Decode(&req)
		if err != nil {
			log.Println("APIcombinerTransaction: error decoding request:", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("API: received /combiner/transaction request (cmd: %s) from %s.", req.Command, r.RemoteAddr)

		resp := TransactionResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		combinerState := conf.Internal.CombinerState
		if combinerState == nil || combinerState.ErrorJournal == nil {
			resp.Error = true
			resp.ErrorMsg = "Combiner state or error journal not configured"
			return
		}

		switch req.Command {
		case "errors":
			duration, err := parseDuration(req.Last)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Invalid duration %q: %v", req.Last, err)
				return
			}

			entries := combinerState.ErrorJournal.ListSince(duration)
			now := time.Now()

			var errors []*TransactionErrorSummary
			for _, e := range entries {
				errors = append(errors, &TransactionErrorSummary{
					DistributionID: e.DistributionID,
					Age:            formatDuration(now.Sub(e.Timestamp)),
					Sender:         e.Sender,
					MessageType:    e.MessageType,
					ErrorMsg:       e.ErrorMsg,
					QNAME:          e.QNAME,
					Timestamp:      e.Timestamp.Format(time.RFC3339),
				})
			}
			resp.Errors = errors
			resp.Msg = fmt.Sprintf("Found %d error(s) in the last %s", len(errors), req.Last)

		case "error-details":
			if req.DistID == "" {
				resp.Error = true
				resp.ErrorMsg = "dist_id is required for error-details command"
				return
			}

			entry, found := combinerState.ErrorJournal.LookupByDistID(req.DistID)
			if !found {
				resp.Msg = fmt.Sprintf("No error record for distID %s (which itself is diagnostic — the transaction may have succeeded or never arrived)", req.DistID)
				return
			}
			now := time.Now()
			resp.ErrorDetail = &TransactionErrorSummary{
				DistributionID: entry.DistributionID,
				Age:            formatDuration(now.Sub(entry.Timestamp)),
				Sender:         entry.Sender,
				MessageType:    entry.MessageType,
				ErrorMsg:       entry.ErrorMsg,
				QNAME:          entry.QNAME,
				Timestamp:      entry.Timestamp.Format(time.RFC3339),
			}
			resp.Msg = fmt.Sprintf("Error details for distID %s", req.DistID)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// formatDuration formats a duration in a human-readable way (e.g. "2m30s", "1h15m")
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s > 0 {
			return fmt.Sprintf("%dm%ds", m, s)
		}
		return fmt.Sprintf("%dm", m)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if m > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dh", h)
}

// parseDuration parses a duration string like "30m", "2h", "1h30m".
// Defaults to 30m if empty.
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 30 * time.Minute, nil
	}
	return time.ParseDuration(s)
}
