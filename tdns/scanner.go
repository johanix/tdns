/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

type ScanRequest struct {
	Cmd              string
	ParentZone       string
	ScanZones        []string
	ScanType         string // "cds" | "csync" | "dnskey"	
	ChildZone        string
	CurrentChildData ChildDelegationData // Current parent-side delegation data for child
	ZoneData         *ZoneData
	RRtype           uint16
	Edns0Options     *edns0.MsgOptions
	Response         chan ScanResponse
}

type ScanResponse struct {
	Time    time.Time
	Zone    string
	RRtype  uint16
	RRset   core.RRset
	Msg     string
	Error   bool
	ErrorMsg string
}

//
// This will wait forever on an external signal, but even better would be
// if we could wait on an external signal OR an internal quit channel. TBD.

type Scanner struct {
	// Conf  *Config
	// LabDB *LabDB
	// RRtype  string
	AuthQueryQ  chan AuthQueryRequest
	IMR         string
	LogFile     string
	LogTemplate string
	Log         map[string]*log.Logger
	Verbose     bool
	Debug       bool
}

func NewScanner(authqueryq chan AuthQueryRequest, verbose, debug bool) Scanner {
	s := Scanner{
		AuthQueryQ: authqueryq,
		//		Conf:        conf,
		//		LabDB:       conf.Internal.LabDB,
		Log:         map[string]*log.Logger{},
		LogTemplate: "/var/log/axfr.net/scanner-%s.log",
		Verbose:     verbose,
		Debug:       debug,
	}

	return s
}

func (scanner *Scanner) AddLogger(rrtype string) error {
	lg := log.New(&lumberjack.Logger{
		Filename:   fmt.Sprintf(scanner.LogTemplate, rrtype),
		MaxSize:    20,
		MaxBackups: 3,
		MaxAge:     7,
	}, fmt.Sprintf("%s scanner: ", rrtype), log.Lshortfile)
	scanner.Log[rrtype] = lg
	scanner.Log[rrtype] = log.Default()
	return nil
}

func ScannerEngine(ctx context.Context, conf *Config) error {
	scannerq := conf.Internal.ScannerQ
	authqueryq := conf.Internal.AuthQueryQ
	interval := viper.GetInt("scanner.interval")
	if interval < 10 {
		interval = 10
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	//scanner := NewScanner(viper.GetBool("services.scanner.verbose"), viper.GetBool("services.scanner.debug"))
	scanner := NewScanner(authqueryq, true, true)
	scanner.AddLogger("CDS")
	scanner.AddLogger("CSYNC")
	scanner.AddLogger("DNSKEY")
	scanner.AddLogger("GENERIC")

	log.Printf("*** ScannerEngine: starting ***")
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("ScannerEngine: context cancelled")
			return nil
		case <-ticker.C:

		case sr, ok := <-scannerq:
			if !ok {
				log.Println("ScannerEngine: scannerq closed")
				return nil
			}
			switch sr.Cmd {
			case "SCAN":
				if sr.ChildZone == "" {
					log.Print("ScannerEngine: Zone unspecified. Ignoring.")
					continue
				}
				//					zd := FindZone(sr.Zone)
				//					if  {
				//						log.Printf("ScannerEngine: Zone containing %s not found. Ignoring.", sr.Zone)
				//						continue
				//					}
				log.Printf("ScannerEngine: Request for immediate scan of zone %s for RRtype %s",
					sr.ChildZone, dns.TypeToString[sr.RRtype])
				switch sr.RRtype {
				case dns.TypeCDS:
					log.Printf("go scanner.CheckCDS(sr)")
					err := conf.Internal.ImrEngine.SendRfc9567ErrorReport(ctx, sr.ChildZone, sr.RRtype, edns0.EDECDSScannerNotImplemented, sr.Edns0Options)
					if err != nil {
						log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
					}
					// go scanner.CheckCDS(sr, &sr.CurrentChildData)
				case dns.TypeCSYNC:
					err := conf.Internal.ImrEngine.SendRfc9567ErrorReport(ctx, sr.ChildZone, sr.RRtype, edns0.EDECSyncScannerNotImplemented, sr.Edns0Options)
					if err != nil {
						log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
					}
					go scanner.CheckCSYNC(sr, &sr.CurrentChildData)
				case dns.TypeDNSKEY:
					log.Printf("go scanner.CheckDNSKEY(sr)")
				}
			default:
				log.Printf("ScannerEngine: Unknown command: '%s'. Ignoring.", sr.Cmd)
			}
		}
	}
}
