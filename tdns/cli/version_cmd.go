/*
 * Johan Stenstam
 */
package cli

import (
	"fmt"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of the app, more or less verbosely",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Verbose {
			fmt.Printf("This is %s, version %s, compiled on %v\n", tdns.Globals.App.Name, tdns.Globals.App.Version, tdns.Globals.App.Date)
		} else {
			fmt.Printf("This is %s, version %s, compiled on %v\n", tdns.Globals.App.Name, tdns.Globals.App.Version, tdns.Globals.App.Date)
		}
	},
}
