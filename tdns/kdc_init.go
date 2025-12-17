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
	"github.com/johanix/tdns/tdns/kdc"
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
	kdc.SetupKdcAPIRoutes(apirouter, kdcDB)

	// Start API dispatcher
	startEngine(&Globals.App, "APIdispatcher", func() error {
		return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
	})

	// Start key distribution engine (future: handles NOTIFY and KMREQ queries)
	// For now, we'll just have the API endpoints

	log.Printf("TDNS %s (%s): KDC started successfully", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

