/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"fmt"
	"log"
	"os"

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
			file, err := os.Create(musicDbFile)
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