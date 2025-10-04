/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile, cfgFileUsed string
var LocalConfig string


func initConfig() {
    cfgFile = Conf.Internal.CfgFile // this gets populated from MainInit()
    if cfgFile != "" {
        fmt.Printf("tdns-imr: config file is '%s'\n", cfgFile)
        // Use config file from the flag.
        viper.SetConfigFile(cfgFile)
    } else {
        viper.SetConfigFile(tdns.DefaultImrCfgFile)
    }

    viper.AutomaticEnv() // read in environment variables that match

    // If a config file is found, read it in.
    if err := viper.ReadInConfig(); err == nil {
        if tdns.Globals.Verbose {
            fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
        }
        cfgFileUsed = viper.ConfigFileUsed()
    } else {
        log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
    }

    LocalConfig = viper.GetString("imr.localconfig")
    if LocalConfig != "" {
        _, err := os.Stat(LocalConfig)
        if err != nil {
            if !os.IsNotExist(err) {
                log.Fatalf("Error stat(%s): %v", LocalConfig, err)
            }
        } else {
            viper.SetConfigFile(LocalConfig)
            if err := viper.MergeInConfig(); err != nil {
                log.Fatalf("Error merging in local config from '%s'", LocalConfig)
            } else {
                if tdns.Globals.Verbose {
                    fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
                }
            }
        }
        viper.SetConfigFile(LocalConfig)
    }

    ValidateConfig(nil, cfgFileUsed) // will terminate on error
    err := viper.Unmarshal(&Conf)
    if err != nil {
        log.Printf("Error from viper.UnMarshal(cfg): %v", err)
    }
}


var ReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Send a report",
	Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("%v\n", args)

        tdns.Globals.App.Type = tdns.AppTypeCli

        if tdns.Globals.Debug {
            fmt.Printf("initImr: Calling conf.MainInit(%q)\n", tdns.DefaultImrCfgFile)
        }

        err := Conf.MainInit(tdns.DefaultCliCfgFile)
        if err != nil {
            tdns.Shutdowner(&Conf, fmt.Sprintf("Error initializing tdns-cli: %v", err))
        }

        // Starting Imr
        log.Printf("Starting RecursorEngine")
        Conf.Internal.RecursorCh = make(chan tdns.ImrRequest, 10)
        stopCh := make(chan struct{}, 10)
        go Conf.RecursorEngine(stopCh)

        qname := dns.Fqdn(args[0])
        qtype := dns.StringToType[strings.ToUpper(args[1])]
        ede := args[2]

        resp := make(chan tdns.ImrResponse, 1)
        Conf.Internal.RecursorCh <- tdns.ImrRequest{
            Qname:      qname,
            Qclass:     dns.ClassINET,
            Qtype:      qtype,
            ResponseCh: resp,
        }

        select {
        case r := <-resp:
            if r.RRset != nil {
                // fmt.Printf("%v\n", r.RRset)
                for _, rr := range r.RRset.RRs {
                    switch rr.Header().Rrtype {
                    case qtype, dns.TypeCNAME:
                        fmt.Printf("%s\n", rr.String())
                    default:
                        fmt.Printf("Not printing: %q\n", rr.String())
                    }
                }
                for _, rr := range r.RRset.RRSIGs {
                    fmt.Printf("%s\n", rr.String())
                }
            } else if r.Error {
                fmt.Printf("Error: %s\n", r.ErrorMsg)
            } else {
                fmt.Printf("No records found: %s\n", r.Msg)
            }
        case <-time.After(3 * time.Second):
            fmt.Println("Timeout waiting for response")
            return
        }

        fmt.Printf("Sending %s report...\n", ede)
	},
}


var RawReportCmd = &cobra.Command{
	Use:   "rawreport",
	Short: "Send a rawreport",
	Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("Args: %v\n", args)
        fmt.Printf("Sending report...\n")
        m := new(dns.Msg)
        m.SetNotify("kau.se.")

        err := edns0.AddReporterOptionToMessage(m, &edns0.ReporterOption{
            ZoneName: "kau.se.",
            EDECode: edns0.EDEMPZoneXfrFailure,
            Severity: 17,
            Sender: "Jonathan",
            Message: "All fckd up",
        })
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("%s\n", m.String())
        c := tdns.NewDNSClient(tdns.TransportDo53, "9998", nil)
        resp, _, err := c.Exchange(m, "127.0.0.1")
        if err != nil {
            log.Fatal(err)
        }
        fmt.Printf("%s\n", resp.String())
	},
}

