/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/spf13/viper"
)

func MainInit(tconf *tdns.Config, mconf *Config) error {
	mconf.Internal.EngineCheck = make(chan EngineCheck, 100)

	var err error
	mconf.Internal.MusicDB, err = NewDB(viper.GetString("db.file"), viper.GetString("db.mode"), false) // Don't drop status tables if they exist
	if err != nil {
		return fmt.Errorf("Error from NewDB(%s): %v", viper.GetString("db.file"), err)
	}

	mconf.Internal.TokViper = TokVip
	mconf.Internal.MusicDB.Tokvip = TokVip

	mconf.Internal.DesecFetch = make(chan SignerOp, 100)
	mconf.Internal.DesecUpdate = make(chan SignerOp, 100)
	mconf.Internal.DdnsFetch = make(chan SignerOp, 100)
	mconf.Internal.DdnsUpdate = make(chan SignerOp, 100)

	apistopper := make(chan struct{}) //
	tconf.Internal.APIStopCh = apistopper

	// go APIdispatcher(tconf, mconf, apistopper)          // sidecar mgmt API:
	go MusicSyncAPIdispatcher(tconf, mconf, apistopper) // sidecar-to-sidecar sync API:

	// XXX: Why don't we need this anymore?
	// rootcafile := viper.GetString("common.rootCA")

	// XXX: Let's put deSEC support on hold until we've sorted out the distributed multi-signer issues.
	//	desecapi, err := music.DesecSetupClient(rootcafile, music.CliConf.Verbose, music.CliConf.Debug)
	//	if err != nil {
	//		log.Fatalf("Error from DesecSetupClient: %v\n", err)
	//	}
	//	desecapi := music.GetUpdater("desec-api").GetApi()
	//	desecapi.TokViper = music.TokVip

	//	rldu := music.Updaters["rldesec-api"]
	//	rldu.SetChannels(mconf.Internal.DesecFetch, mconf.Internal.DesecUpdate)
	//	rldu.SetApi(*desecapi)
	//	du := music.Updaters["desec-api"]
	//	du.SetApi(*desecapi) // it is ok to reuse the same object here

	rlddu := Updaters["rlddns"]
	rlddu.SetChannels(mconf.Internal.DdnsFetch, mconf.Internal.DdnsUpdate)

	var done = make(chan struct{}, 1)

	go DbUpdater(mconf)
	// 	go music.DeSECmgr(&mconf, done)
	go DdnsMgr(mconf, done)
	go FSMEngine(mconf, done)

	return nil
}
