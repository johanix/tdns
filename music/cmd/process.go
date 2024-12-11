/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"encoding/json"
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns/music"
)

var processname string

// processCmd represents the process command
var ProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "list or visualize the defined processes",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var processListCmd = &cobra.Command{
	Use:   "list",
	Short: "list defined processes",
	Run: func(cmd *cobra.Command, args []string) {
		err := ListProcesses()
		if err != nil {
			fmt.Printf("Error from ListProcesses: %v\n", err)
		}
	},
}

// XXX: This really doesn't belong here, it would be more correct with
//      an "engine check" command than this "process check" command. But
//      this will have to do for now.

var processCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Kick the FSM engine to immediately run through all auto zones",
	Run: func(cmd *cobra.Command, args []string) {
		pr, err := SendProcess(music.ProcessPost{
			Command: "check",
		})
		if err != nil {
			fmt.Printf("Error from SendProcess: %v\n", err)
		}
		if pr.Error {
			fmt.Printf("%s\n", pr.ErrorMsg)
		}
		if pr.Msg != "" {
			fmt.Printf("%s\n", pr.Msg)
		}
	},
}

var processGraphCmd = &cobra.Command{
	Use:   "graph",
	Short: "generate a graph of the named process",
	Run: func(cmd *cobra.Command, args []string) {
		err := GraphProcess()
		if err != nil {
			fmt.Printf("Error from GraphProcess: %v\n", err)
		}
	},
}

func init() {
	//	rootCmd.AddCommand(processCmd)
	ProcessCmd.AddCommand(processListCmd, processCheckCmd, processGraphCmd)

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// processCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// processCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	processGraphCmd.Flags().StringVarP(&processname, "process", "p", "", "name of process")
	processGraphCmd.MarkFlagRequired("process")
}

func SendProcess(data music.ProcessPost) (music.ProcessResponse, error) {
	var pr music.ProcessResponse
	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/process", data, true)
	if err != nil {
		log.Println("Error from api.RequestNG:", err)
		return pr, err
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}
	return pr, nil
}

func PrintProcesses(pr music.ProcessResponse) {
	var out []string
	for _, p := range pr.Processes {
		// out = append(out, fmt.Sprintf("%s|%s", p.Name, p.Desc))
		if p.Desc == "" {
			out = append(out, fmt.Sprintf("%s|[no information]", p.Name))
		} else {
			fmt.Printf("%s\n%s\n\n", p.Name, p.Desc)
		}
	}
	if len(out) > 0 {
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}

func ListProcesses() error {
	data := music.ProcessPost{
		Command: "list",
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/process", data, true)
	if err != nil {
		log.Println("Error from Api Post:", err)
		return err
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var pr music.ProcessResponse
	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	var out []string
	//	if tdns.Globals.Verbose {
	//		out = append(out, "Process|Description")
	//	}
	for _, p := range pr.Processes {
		// out = append(out, fmt.Sprintf("%s|%s", p.Name, p.Desc))
		if p.Desc == "" {
			out = append(out, fmt.Sprintf("%s|[no information]", p.Name))
		} else {
			fmt.Printf("%s\n%s\n\n", p.Name, p.Desc)
		}
	}
	if len(out) > 0 {
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
	return nil
}

func GraphProcess() error {
	data := music.ProcessPost{
		Command: "graph",
		Process: processname,
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/process", data, true)
	if err != nil {
		log.Println("Error from Api Post:", err)
		return err
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var pr music.ProcessResponse
	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}
	fmt.Printf("%s", pr.Graph) // no newline needed
	return nil
}
