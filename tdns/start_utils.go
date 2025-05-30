/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func xxxShellExec(cmdline string) (string, error) {
	args := strings.Fields(cmdline)
	if Globals.Verbose {
		fmt.Printf("ShellExec cmd: '%s'\n", cmdline)
	}

	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if len(out) > 1 {
		out = out[:len(out)-1] // chop of trailing newline
	}
	if err != nil {
		fmt.Printf("ShellExec of cmd '%s' failed. Error: %v\nOutput: %s\n", cmd, err, string(out))
		return fmt.Sprintf("shell exec of cmd '%s' failed. Error: %v", cmd, err), err
	}
	if Globals.Debug {
		fmt.Printf("ShellExec output: '%s'\n", string(out))
	}
	return string(out), nil
}

func (api *ApiClient) StopDaemon() {
	_, resp, err := api.UpdateDaemon(CommandPost{Command: "stop"}, false)
	if err != nil {
		fmt.Printf("Error from stop command: %v\n", err.Error())
		if err.Error() == "Connection refused" {
			fmt.Printf("Daemon seems to not be running.\n")
		} else {
			fmt.Printf("there is some other problem: %v\n", err)
		}
	} else { // we got a response, so deamon appears to be running
		if resp.Status == "stopping" {
			fmt.Printf("Daemon acknowledged stop command and is winding down.\n")
		} else {
			fmt.Printf("Daemon is running, but status is strange. Status: %v. Message: %v\n",
				resp.Status, resp.Msg)
		}
	}
}

// slurp means that we'll connect to stdout and stderr on the underlying
// daemon to check for possible error messages (if it dies somehow). The
// problem is that connecting to stdout doesn't work well, it kills the
// daemon after a while. So we only want to slurp when explicitly checking
// for errors.
func (api *ApiClient) StartDaemon(maxwait int, slurp bool) {
	if maxwait == 0 {
		maxwait = 5
	}

	_, resp, err := api.UpdateDaemon(CommandPost{Command: "status"}, false) // don't die
	if err != nil {
		if err.Error() == "Connection refused" {
			fmt.Printf("Daemon not responding. Starting new daemon (timeout: %d seconds)\n", maxwait)

			daemonbinary := viper.GetString("common.command")
			daemonname := viper.GetString("common.servername")
			if daemonname == "" {
				fmt.Printf("Name of server process not set. See common.servername.\n")
				daemonname = "undefined-server"
			}
			if fi, err := os.Stat(daemonbinary); err == nil {
				var stderr, stdout io.Reader
				age := time.Since(fi.ModTime()).Round(time.Second)
				fmt.Printf("Daemon binary \"%s\" found (%v old)\n",
					daemonbinary, age)
				cmd := exec.Command(daemonbinary)

				if slurp {
					stderr, err = cmd.StderrPipe()
					if err != nil {
						log.Fatalf("StartDaemon: Error from cmd.StderrPipe(): %v", err)
					}

					stdout, err = cmd.StdoutPipe()
					if err != nil {
						log.Fatalf("StartDaemon: Error from cmd.StdoutPipe(): %v", err)
					}
				}

				err2 := cmd.Start()
				if err2 != nil {
					log.Fatalf("StartDaemon: Error from cmd.Start(): %v", err2)
				} else {
					to_ticker := time.NewTicker(time.Duration(maxwait) * time.Second)
					check_ticker := time.NewTicker(time.Duration(1) * time.Second)
					for {
						select {
						case <-to_ticker.C:
							// timeout, give up
							fmt.Printf("Timeout (%d seconds) starting daemon. Giving up.\n",
								maxwait)

							if slurp {
								slurperr, _ := io.ReadAll(stderr)
								slurpout, _ := io.ReadAll(stdout)
								fmt.Printf("*** StartDaemon: Error from Daemon status update: %v\n", err)
								fmt.Printf("*** Here is stderr from %s:\n----------\n%s",
									daemonname, slurperr)
								fmt.Printf("---------\n")
								fmt.Printf("*** And here is stdout from %s:\n----------\n%s",
									daemonname, slurpout)
								fmt.Printf("---------\n*** Perhaps this provides some clue to why it isn't starting properly?\n")
							} else {
								fmt.Printf(
									`*** StartDaemon: daemon failed to start.
*** Note that starting the daemon takes a long time. Just wait a little and then ping it.
*** Otherwise, try slurping stderr and stdout with the '--slurp' flag.
`)
							}
							os.Exit(1)

						case <-check_ticker.C:
							// check status

							_, r, err := api.UpdateDaemon(CommandPost{Command: "status"},
								false)
							if err == nil {
								// All ok, daemon started, no error
								fmt.Printf("Daemon started. Status: %s. Message: %s\n",
									r.Status, r.Msg)
								os.Exit(0)
							} else {
								if err.Error() == "Connection refused" {
									if Globals.Verbose {
										fmt.Printf("Status: connection refused, but not yet giving up\n")
									}
									continue // with the for loop
								} else {
									fmt.Printf("*** StartDaemon: Error: %v\n", err)
								}

								if slurp {
									slurperr, _ := io.ReadAll(stderr)
									slurpout, _ := io.ReadAll(stdout)
									fmt.Printf("*** StartDaemon: Error from Daemon status update: %v\n", err)
									fmt.Printf("*** Here is stderr from %s:\n----------\n%s",
										daemonname, slurperr)
									fmt.Printf("---------\n")
									fmt.Printf("*** And here is stdout from %s:\n----------\n%s",
										daemonname, slurpout)
									fmt.Printf("---------\n*** Perhaps this provides some clue to why it isn't starting properly?\n")
								} else {
									fmt.Printf(
										`*** StartDaemon: Error from status command: %v.
*** Perhaps the daemon failed to start.
*** Try slurping stderr and stdout with the '--slurp' flag.
`, err)
								}
								os.Exit(1)
							}
						}
					}

					// XXX: unreachable
					// fmt.Printf("Daemon started. Status: %s. Message: %s\n", "foo", "bar") // r.Status, r.Msg)

				}
			} else {
				fmt.Printf("Daemon binary \"%s\" does not exist. Exit.\n",
					daemonbinary)
				os.Exit(1)
			}

		} else {
			// there is some error, but not "connection refused"
			fmt.Printf("StartDaemon: Error: there is some other problem: %v\n", err)
		}
	} else { // we got a response, so daemon appears to be running
		if resp.Status == "ok" {
			fmt.Printf("Daemon is already running. No change needed.\n")
		} else {
			fmt.Printf("Daemon already running, but status is strange. Status: %v. Message: %v\n",
				resp.Status, resp.Msg)
		}
	}
}

func (api *ApiClient) UpdateDaemon(data CommandPost, dieOnError bool) (int, CommandResponse, error) {
	var cr CommandResponse
	status, buf, err := api.RequestNG(http.MethodPost, "/command", data, dieOnError)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return 501, cr, errors.New("connection refused")
		} else {
			return 501, cr, err
		}
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		log.Printf("Error parsing JSON for CommandResponse: %s", string(buf))
		log.Fatalf("Error from unmarshal CommandResponse: %v\n", err)
	}
	return status, cr, err
}

func (api *ApiClient) SendPing(pingcount int, dieOnError bool) (PingResponse, error) {
	data := PingPost{
		Msg:   "One ping to rule them all and in the darkness bing them.",
		Pings: pingcount,
	}

	_, buf, err := api.RequestNG(http.MethodPost, "/ping", data, dieOnError)
	if err != nil {
		return PingResponse{}, err
	}

	var pr PingResponse
	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Printf("Error parsing JSON for PingResponse: %s", string(buf))
		log.Fatalf("Error from json.Unmarshal PingResponse: %v\n", err)
	}
	return pr, nil
}

func SendUnixPing(target string, dieOnError bool) (bool, error) {
	cmdline := []string{"/sbin/ping", "-o", "-q", "-Q", "-c", "2", target}

	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	out, err := cmd.CombinedOutput()
	if len(out) > 1 {
		out = out[:len(out)-1] // chop of trailing newline
	}

	if err != nil {
		return false, err
	}
	if Globals.Debug {
		fmt.Printf("ShellExec output: '%s'\n", string(out))
	}
	return true, nil
}

// func (api *ApiClient) SendCommand(data GroupCmdPost) (GroupCmdResponse, error) {

//	_, buf, err := api.RequestNG(http.MethodPost, "/command", data, false) // dieOnError=false

//	if err != nil {
//		return GroupCmdResponse{}, err
//	}

//	var cr GroupCmdResponse
//	err = json.Unmarshal(buf, &cr)
//	if err != nil {
//		log.Printf("Error parsing JSON for GroupCmdResponse: %s", string(buf))
//		log.Fatalf("Error from unmarshal of GroupCmdResponse: %v\n", err)
//	}

//	if cr.Error {
//		fmt.Printf("Error from remote end: %s\n", cr.ErrorMsg)
//	}
// fmt.Printf("%s\n", cr.Msg)
//	return cr, nil
//}

type ShowAPIresponse struct {
	Status int
	Msg    string
	Data   []string
}

func (api *ApiClient) ShowApi() {
	_, buf, _ := api.RequestNG(http.MethodGet, "/show/api", nil, true)

	var sar ShowAPIresponse
	err := json.Unmarshal(buf, &sar)
	if err != nil {
		log.Printf("Error parsing JSON for ShowAPIResponse: %s", string(buf))
		log.Fatalf("Error from unmarshal of ShowAPIresponse: %v\n", err)
	}
	for _, ep := range sar.Data[1:] {
		fmt.Printf("%s\n", ep)
	}
}

var ServerName string = "PLACEHOLDER"

func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	dstdir := filepath.Dir(dst)
	if err := os.MkdirAll(dstdir, os.ModePerm); err != nil {
		return 0, err
	}

	tmpdst, err := os.Create(dst + ".tmp")
	if err != nil {
		return 0, err
	}

	defer tmpdst.Close()
	nBytes, err := io.Copy(tmpdst, source)
	if err != nil {
		return 0, err
	}

	err = tmpdst.Close()
	if err != nil {
		return 0, err
	}

	err = os.Rename(dst+".tmp", dst)
	if err != nil {
		return 0, err
	}

	return nBytes, err
}
