/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: orchestrator.
 *
 * Apps populate a Spec and call Run. The library handles:
 *
 *   1. read existing configs (Spec.ReadExisting)
 *   2. interview (Spec.RunInterview, using the Prompter)
 *   3. render templates (Spec.RenderAll)
 *   4. diff preview + top-level confirmation
 *   5. live-server gate (Spec.LiveTargets)
 *   6. generation of missing material (Spec.GenerateMaterial)
 *   7. atomic write + backup of every changed file
 *
 * State is passed opaquely as `any` — the app owns the shape.
 * The library never inspects it.
 */
package configure

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// Spec describes one app's configure flow. All callbacks receive
// the app-owned state (from ReadExisting, then through Interview).
type Spec struct {
	// Paths is the ordered list of files the flow owns. Iteration
	// order is deterministic for diff output; the first entry
	// usually matches the "primary" role.
	Paths []string

	// ReadExisting is called once at the start to seed the
	// interview with defaults from any existing config files.
	ReadExisting func() (state any, err error)

	// RunInterview drives the prompts. The returned state is
	// passed forward to the render/generate hooks.
	RunInterview func(p *Prompter, seed any) (any, error)

	// RenderAll returns rendered content keyed by Path.
	RenderAll func(state any) (map[string]string, error)

	// LiveTargets returns the ping-gate inputs for each role whose
	// config is about to change. Apps that don't want a gate can
	// return nil.
	LiveTargets func(state any) []LiveTarget

	// GenerateMaterial runs after the top-level confirm and the
	// live-server gate but before the atomic write. Apps call the
	// EnsureXxx helpers here to create missing JOSE keys, TLS
	// certs, etc. Existing files must be left untouched.
	GenerateMaterial func(state any) error
}

// Run drives the full bootstrap flow.
func Run(spec Spec) error {
	return run(spec, os.Stdout, bufio.NewReader(os.Stdin))
}

// run is the testable body of Run — takes explicit io/reader.
func run(spec Spec, w io.Writer, in *bufio.Reader) error {
	if err := validateSpec(spec); err != nil {
		return err
	}

	fmt.Fprintln(w, "Reading any existing configuration…")
	existing := make(map[string]string, len(spec.Paths))
	for _, p := range spec.Paths {
		content, err := ReadFileIfExists(p)
		if err != nil {
			return err
		}
		existing[p] = content
		if content == "" {
			fmt.Fprintf(w, "  %s: (not present)\n", p)
		} else {
			fmt.Fprintf(w, "  %s: %d bytes\n", p, len(content))
		}
	}

	seed, err := spec.ReadExisting()
	if err != nil {
		return fmt.Errorf("read existing: %w", err)
	}

	p := &Prompter{In: in, Out: w}
	state, err := spec.RunInterview(p, seed)
	if err != nil {
		return fmt.Errorf("interview: %w", err)
	}

	rendered, err := spec.RenderAll(state)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}

	changes := make([]FileChange, 0, len(spec.Paths))
	for _, path := range spec.Paths {
		changes = append(changes, FileChange{
			Path:   path,
			OldTxt: existing[path],
			NewTxt: rendered[path],
		})
	}

	if !confirmApply(w, in, changes) {
		fmt.Fprintln(w, "\nAborted. No files changed.")
		return nil
	}

	if spec.LiveTargets != nil {
		if err := gateLiveServers(w, in, spec.LiveTargets(state), changes); err != nil {
			fmt.Fprintln(w, "\n"+err.Error())
			return nil
		}
	}

	if spec.GenerateMaterial != nil {
		if err := spec.GenerateMaterial(state); err != nil {
			return fmt.Errorf("generate material: %w", err)
		}
	}

	if _, err := applyChanges(w, changes); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	fmt.Fprintln(w, "\nDone.")
	return nil
}

func validateSpec(s Spec) error {
	if len(s.Paths) == 0 {
		return fmt.Errorf("configure.Run: Spec.Paths is empty")
	}
	if s.ReadExisting == nil {
		return fmt.Errorf("configure.Run: Spec.ReadExisting is nil")
	}
	if s.RunInterview == nil {
		return fmt.Errorf("configure.Run: Spec.RunInterview is nil")
	}
	if s.RenderAll == nil {
		return fmt.Errorf("configure.Run: Spec.RenderAll is nil")
	}
	return nil
}
