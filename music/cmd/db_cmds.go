/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var musicDbFile string
var DbCmd = &cobra.Command{
	Use:   "db",
	Short: "MUSIC DB commands",
}

var dbInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize MUSIC DB",
	Run: func(cmd *cobra.Command, args []string) {
		if musicDbFile == "" {
			musicDbFile = viper.GetString("db.file")
		}
		if musicDbFile == "" {
			log.Fatalf("Error: MUSIC DB file not specified in config nor on command line")
		}

		if _, err := os.Stat(musicDbFile); err == nil {
			fmt.Printf("Warning: MUSIC DB file '%s' already exists.\n", musicDbFile)
		} else if os.IsNotExist(err) {
			// Validate parent directory
			parentDir := filepath.Dir(musicDbFile)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				log.Fatalf("Error: Parent directory '%s' does not exist", parentDir)
			}
			file, err := os.OpenFile(musicDbFile, os.O_CREATE|os.O_RDWR, 0644)
			if err != nil {
				log.Fatalf("Error creating MUSIC DB file '%s': %v", musicDbFile, err)
			}
			defer file.Close()
			fmt.Printf("MUSIC DB file '%s' created successfully.\n", musicDbFile)
		} else {
			log.Fatalf("Error checking MUSIC DB file '%s': %v", musicDbFile, err)
		}
	},
}

func init() {
	DbCmd.AddCommand(dbInitCmd)

	dbInitCmd.Flags().StringVarP(&musicDbFile, "file", "f", "", "MUSIC DB file")
}
