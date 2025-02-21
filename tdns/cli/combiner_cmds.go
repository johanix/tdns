/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var CombinerCmd = &cobra.Command{
	Use:   "combiner",
	Short: "TDNS Combiner commands",
}

var combinerAddDataCmd = &cobra.Command{
	Use:   "add-data",
	Short: "Add local data to a zone passing through the combiner",
	Run: func(cmd *cobra.Command, args []string) {

		if _, err := os.Stat(tdnsDbFile); err == nil {
			fmt.Printf("Warning: TDNS DB file '%s' already exists.\n", tdnsDbFile)
		} else if os.IsNotExist(err) {
			// Validate parent directory
			parentDir := filepath.Dir(tdnsDbFile)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				log.Fatalf("Error: Parent directory '%s' does not exist", parentDir)
			}
			file, err := os.OpenFile(tdnsDbFile, os.O_CREATE|os.O_RDWR, 0644)
			if err != nil {
				log.Fatalf("Error creating TDNS DB file '%s': %v", tdnsDbFile, err)
			}
			defer file.Close()
			fmt.Printf("TDNS DB file '%s' created successfully.\n", tdnsDbFile)
		} else {
			log.Fatalf("Error checking TDNS DB file '%s': %v", tdnsDbFile, err)
		}
	},
}

func init() {
	CombinerCmd.AddCommand(combinerAddDataCmd)
}
