/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var tdnsDbFile string

var DbCmd = &cobra.Command{
	Use:   "db",
	Short: "TDNS DB commands",
}

var dbInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize TDNS DB",
	Run: func(cmd *cobra.Command, args []string) {
		if tdnsDbFile == "" {
			tdnsDbFile = viper.GetString("db.file")
		}
		if tdnsDbFile == "" {
			log.Fatalf("Error: TDNS DB file not specified in config nor on command line")
		}

		if _, err := os.Stat(tdnsDbFile); err == nil {
			fmt.Printf("Warning: TDNS DB file '%s' already exists.\n", tdnsDbFile)
		} else if os.IsNotExist(err) {
			file, err := os.Create(tdnsDbFile)
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
	DbCmd.AddCommand(dbInitCmd)

	dbInitCmd.Flags().StringVarP(&tdnsDbFile, "file", "f", "", "TDNS DB file")
}