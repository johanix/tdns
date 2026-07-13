/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Exit-code policy (design doc §11): 0 = every evaluated invariant held
// (skips listed), 1 = at least one violation, 2 = setup error (bad config,
// unreachable target, guard-rail refusal).
const (
	ExitOK        = 0
	ExitViolation = 1
	ExitSetup     = 2
)

type Violation struct {
	Invariant string    `json:"invariant"` // "I6", ...
	Time      time.Time `json:"time"`
	Summary   string    `json:"summary"`
	Context   string    `json:"context,omitempty"` // observation vs ledger state(s), serials, actor timeline
}

type Report struct {
	Tool         string            `json:"tool"` // name + version
	TestId       string            `json:"test_id,omitempty"`
	Command      string            `json:"command"` // churn | ddns | probe | ...
	Zone         string            `json:"zone,omitempty"`
	Seed         int64             `json:"seed,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	Duration     time.Duration     `json:"duration"`
	Capabilities *CapabilityMatrix `json:"capabilities,omitempty"`
	Skipped      []string          `json:"skipped,omitempty"` // checks not evaluated + why
	Stats        map[string]int64  `json:"stats,omitempty"`
	Violations   []Violation       `json:"violations,omitempty"`
}

func NewReport(tool, command string) *Report {
	return &Report{
		Tool:      tool,
		Command:   command,
		StartedAt: time.Now(),
		Stats:     map[string]int64{},
	}
}

func (r *Report) Skip(what, why string) {
	r.Skipped = append(r.Skipped, fmt.Sprintf("%s: %s", what, why))
}

func (r *Report) Violate(invariant, summary, context string) {
	r.Violations = append(r.Violations, Violation{
		Invariant: invariant, Time: time.Now(), Summary: summary, Context: context,
	})
}

func (r *Report) ExitCode() int {
	if len(r.Violations) > 0 {
		return ExitViolation
	}
	return ExitOK
}

func (r *Report) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r *Report) RenderText(w io.Writer) {
	fmt.Fprintf(w, "== tdns-debug report: %s", r.Command)
	if r.TestId != "" {
		fmt.Fprintf(w, " (%s)", r.TestId)
	}
	if r.Zone != "" {
		fmt.Fprintf(w, " zone %s", r.Zone)
	}
	fmt.Fprintf(w, " ==\n")
	if r.Seed != 0 {
		fmt.Fprintf(w, "seed: %d\n", r.Seed)
	}
	if r.Duration > 0 {
		fmt.Fprintf(w, "duration: %s\n", r.Duration.Round(time.Millisecond))
	}
	if r.Capabilities != nil {
		fmt.Fprint(w, r.Capabilities.Render())
	}
	if len(r.Stats) > 0 {
		fmt.Fprintf(w, "stats:\n")
		for k, v := range r.Stats {
			fmt.Fprintf(w, "  %-32s %d\n", k, v)
		}
	}
	// No silent scope shrink: skips are always shown, so a green run against
	// a limited target cannot read as full coverage.
	for _, s := range r.Skipped {
		fmt.Fprintf(w, "SKIPPED: %s\n", s)
	}
	if len(r.Violations) == 0 {
		fmt.Fprintf(w, "result: OK — all evaluated invariants held\n")
		return
	}
	fmt.Fprintf(w, "result: %d VIOLATION(S)\n", len(r.Violations))
	for _, v := range r.Violations {
		fmt.Fprintf(w, "VIOLATION [%s] %s\n  at %s\n", v.Invariant, v.Summary, v.Time.Format(time.RFC3339Nano))
		if v.Context != "" {
			fmt.Fprintf(w, "  %s\n", v.Context)
		}
	}
}
