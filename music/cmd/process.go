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
	ProcessCmd.AddCommand(processListCmd, processCheckCmd, processGraphCmd)

	processGraphCmd.Flags().StringVarP(&processname, "process", "p", "", "name of process")
	processGraphCmd.MarkFlagRequired("process")
}

func SendProcess(data music.ProcessPost) (music.ProcessResponse, error) {
	var pr music.ProcessResponse

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/process", data, true)
	if err != nil {
		log.Println("Failed to send process request:", err)
		return pr, err
	}
	if status < 200 || status >= 300 {
		return pr, fmt.Errorf("process request returned unexpected status code %d", status)
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
	if tdns.Globals.Verbose {
		out = append(out, "Process|Description")
	}
	for _, p := range pr.Processes {
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
