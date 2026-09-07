/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var genDocsDir string

// genDocsCmd generates the CLI reference -- one markdown page per command, with
// flags -- directly from the live cobra command tree, so the reference can
// never drift from the binary. It is a developer/build tool: hidden from normal
// help, takes no daemon connection and reads no tdns config (see the
// PersistentPreRun exemption in root.go). Regenerate after changing commands.
var genDocsCmd = &cobra.Command{
	Use:    "gen-docs",
	Short:  "Generate the CLI reference markdown from the live command tree",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Suppress cobra's "Auto generated ... on <date>" page footer so
		// regenerating yields stable diffs (no churn on the timestamp).
		disableAutoGenTag(rootCmd)
		if err := os.MkdirAll(genDocsDir, 0o755); err != nil {
			return fmt.Errorf("creating output dir %q: %w", genDocsDir, err)
		}
		if err := doc.GenMarkdownTree(rootCmd, genDocsDir); err != nil {
			return fmt.Errorf("generating CLI reference: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote CLI reference markdown to %s/\n", genDocsDir)
		return nil
	},
}

// disableAutoGenTag turns off cobra's auto-gen date footer for cmd and all of
// its descendants, so the generated pages don't churn on every run.
func disableAutoGenTag(cmd *cobra.Command) {
	cmd.DisableAutoGenTag = true
	for _, c := range cmd.Commands() {
		disableAutoGenTag(c)
	}
}

func init() {
	genDocsCmd.Flags().StringVar(&genDocsDir, "dir", "reference/cli",
		"output directory for the generated CLI reference markdown")
	rootCmd.AddCommand(genDocsCmd)
}
