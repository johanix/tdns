/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC initialization functions for tdns package
 */

package tdns

import (
	"context"
	"fmt"
	"log"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns/v0.x/tdns/kdc"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// StartKdc starts subsystems for tdns-kdc
func (conf *Config) StartKdc(ctx context.Context, apirouter *mux.Router) error {
	// Parse KDC configuration from stored YAML bytes
	var kdcConf kdc.KdcConf
	
	// conf.Internal.KdcConf is either []byte (YAML) or already *kdc.KdcConf
	switch v := conf.Internal.KdcConf.(type) {
	case []byte:
		// Unmarshal YAML bytes into kdc.KdcConf
		if err := yaml.Unmarshal(v, &kdcConf); err != nil {
			return fmt.Errorf("failed to unmarshal KDC config: %v", err)
		}
		conf.Internal.KdcConf = &kdcConf
	case *kdc.KdcConf:
		kdcConf = *v
	default:
		return fmt.Errorf("KDC configuration not found or invalid type (got %T)", conf.Internal.KdcConf)
	}

	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to initialize KDC database: %v", err)
	}
	conf.Internal.KdcDB = kdcDB

	// Setup KDC API routes
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
		"DnsEngine": map[string]interface{}{
			"Addresses": conf.DnsEngine.Addresses,
		},
		"KdcConf": &kdcConf,
	}
	kdc.SetupKdcAPIRoutes(apirouter, kdcDB, confMap, APIping(conf))

	// Start API dispatcher
	startEngine(&Globals.App, "APIdispatcher", func() error {
		return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
	})

	// Initialize DNS query channel for custom query handling
	conf.Internal.DnsQueryQ = make(chan DnsQueryRequest, 100)
	log.Printf("KDC: Initialized DnsQueryQ channel (capacity: %d)", cap(conf.Internal.DnsQueryQ))

	// Start DNS query handler for KDC (handles KMREQ, KMCTRL, etc.)
	startEngine(&Globals.App, "KdcQueryHandler", func() error {
		log.Printf("KDC: Starting QueryHandler engine")
		return QueryHandler(ctx, conf, func(ctx context.Context, dqr *DnsQueryRequest) error {
			if Globals.Debug {
				log.Printf("KDC: QueryHandler callback invoked (qname=%s, qtype=%s)", dqr.Qname, dns.TypeToString[dqr.Qtype])
			}
			// Convert DnsQueryRequest to kdc.KdcQueryRequest
			kdcReq := &kdc.KdcQueryRequest{
				ResponseWriter: dqr.ResponseWriter,
				Msg:            dqr.Msg,
				Qname:          dqr.Qname,
				Qtype:          dqr.Qtype,
				Options:        dqr.Options,
			}
			// Call KDC handler
			return kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
		})
	})

	// Initialize DNS NOTIFY channel for NOTIFY handling
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	log.Printf("KDC: Initialized DnsNotifyQ channel (capacity: %d)", cap(conf.Internal.DnsNotifyQ))

	// Start DNS NOTIFY handler for KDC (handles confirmation NOTIFYs from KRS)
	startEngine(&Globals.App, "KdcNotifyHandler", func() error {
		log.Printf("KDC: Starting NotifyHandler engine")
		return NotifyHandlerWithCallback(ctx, conf, func(ctx context.Context, dnr *DnsNotifyRequest) error {
			if Globals.Debug {
				log.Printf("KDC: NotifyHandler callback invoked (qname=%s)", dnr.Qname)
			}
			// Call KDC NOTIFY handler (pass individual fields to avoid import cycle)
			return kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)
		})
	})

	// Start DNS engine (listens on configured addresses and routes queries to DnsQueryQ channel)
	startEngine(&Globals.App, "DnsEngine", func() error {
		log.Printf("KDC: Starting DnsEngine")
		return DnsEngine(ctx, conf)
	})

	// Start key state worker for automatic transitions
	startEngine(&Globals.App, "KeyStateWorker", func() error {
		log.Printf("KDC: Starting KeyStateWorker")
		return kdc.KeyStateWorker(ctx, kdcDB, &kdcConf)
	})

	log.Printf("TDNS %s (%s): KDC started successfully", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

