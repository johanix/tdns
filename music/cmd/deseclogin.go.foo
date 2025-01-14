/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package mcmd

import (
	"fmt"

	"github.com/johanix/tdns/music"

	"github.com/spf13/cobra"
)

var DesecCmd = &cobra.Command{
	Use:   "desec",
	Short: "commands to talk directly to the deSEC API, without involving musicd",
	Long: `The 'desec' commands (login, logout, zone add, zone list, zone delete, etc)
communicate directly with the deSEC API and is therefore a method of verifying
what happens when musicd communicates with deSEC.

Furthermore, we don't intend to make musicd a complete zone management system, and
therefore the direct interaction with deSEC is a method of bootstrapping zones
and data in deSEC without further complicating musicd.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("desec called")
	},
}

var desecLoginCmd = &cobra.Command{
	Use:   "login",
	Short: fmt.Sprintf("Login to the deSEC API. Store the received token on disk, in %s", DefaultTokenFile),
	Run: func(cmd *cobra.Command, args []string) {
		api := music.GetUpdater("desec-api").GetApi()
		dlr, err := api.DesecLogin() // DesecLogin() will only return on success
		if err != nil {
			fmt.Printf("Error from DesecLogin: %v\n", err)
		}

		if dlr.Token != "" {
			endtime := dlr.Created.Add(dlr.MaxUnused)
			fmt.Printf("New token received and stored. It is valid until %v\n",
				endtime.Format("2006-01-02 15:04:05"))
		}
	},
}

var desecLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from the deSEC API and delete stored tokens",
	Run: func(cmd *cobra.Command, args []string) {

		tok := music.TokVip.GetString("token")
		fmt.Printf("About to log out with token %s\n", tok)

		err := music.DesecLogout(&music.CliConf, music.TokVip)
		if err != nil {
			fmt.Printf("Warning: error from desec logout: %v\n", err)
		}
	},
}

func init() {
	DesecCmd.AddCommand(desecLoginCmd, desecLogoutCmd)
}
