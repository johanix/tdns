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
	"github.com/spf13/viper"
)

// NewDbCmd returns a fresh 'db' subtree for attachment under a daemon
// parent (auth/agent). Each call returns independent cobra.Command
// instances so the same subtree can be wired under multiple parents
// without violating cobra's single-parent rule.
func NewDbCmd(parent string) *cobra.Command {
	var dbFile string

	dbCmd := &cobra.Command{
		Use:   "db",
		Short: fmt.Sprintf("Manage the %s daemon's SQLite database", parent),
	}

	dbInitCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s daemon's TDNS DB file", parent),
		Run: func(cmd *cobra.Command, args []string) {
			if dbFile == "" {
				dbFile = viper.GetString("db.file")
			}
			if dbFile == "" {
				log.Fatalf("Error: TDNS DB file not specified in config nor on command line")
			}

			parentDir := filepath.Dir(dbFile)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				log.Fatalf("Error: Parent directory '%s' does not exist", parentDir)
			}
			// O_EXCL makes creation atomic: if another process raced us,
			// open returns ErrExist and we report "already exists"
			// instead of silently treating a foreign file as ours.
			file, err := os.OpenFile(dbFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				if os.IsExist(err) {
					fmt.Printf("Warning: TDNS DB file '%s' already exists.\n", dbFile)
					return
				}
				log.Fatalf("Error creating TDNS DB file '%s': %v", dbFile, err)
			}
			defer file.Close()
			fmt.Printf("TDNS DB file '%s' created successfully.\n", dbFile)
		},
	}
	dbInitCmd.Flags().StringVarP(&dbFile, "file", "f", "", "TDNS DB file")

	dbCmd.AddCommand(dbInitCmd)
	return dbCmd
}
