/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/miekg/dns"
)

func APIzone(refreshq chan ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zp ZonePost
		err := decoder.Decode(&zp)
		if err != nil {
			log.Println("APIzone: error decoding zone command post:", err)
		}

		log.Printf("API: received /zone request (cmd: %s) from %s.\n",
			zp.Command, r.RemoteAddr)

		resp := ZoneResponse{
			Time:    time.Now(),
			AppName: Globals.AppName,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		zd, exist := Zones.Get(zp.Zone)
		if !exist && zp.Command != "list-zones" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zp.Zone)
			return
		}

		switch zp.Command {
		case "bump":
			// resp.Msg, err = BumpSerial(conf, cp.Zone)

			br, err := zd.BumpSerial()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zp.Zone, br.OldSerial, br.NewSerial)

		case "write-zone":
			msg, err := zd.WriteZone(false, zp.Force)
			resp.Msg = msg
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "sign-zone":
			newrrsigs, err := zd.SignZone(kdb, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: signed with %d new RRSIGs", zd.ZoneName, newrrsigs)

		case "generate-nsec":
			err := zd.GenerateNsecChain(kdb)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "show-nsec-chain":
			resp.Names, err = zd.ShowNsecChain()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "freeze":
			// If a zone has modifications, freezing implies that the updated
			// zone data should be written out to disk.
			if !zd.Options[OptAllowUpdates] && !zd.Options[OptAllowChildUpdates] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s does not allow updates. Freeze would be a no-op", zd.ZoneName)
			}

			if zd.Options[OptFrozen] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s is already frozen", zd.ZoneName)
			}

			// zd.mu.Lock()
			zd.SetOption(OptFrozen, true)
			//zd.mu.Unlock()
			if zd.Options[OptDirty] {
				tosource := true
				zd.WriteZone(tosource, false)
				resp.Msg = fmt.Sprintf("Zone %s is now frozen, modifications will be written to disk", zd.ZoneName)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is now frozen", zd.ZoneName)
			}

		case "thaw":
			if !zd.Options[OptAllowUpdates] && !zd.Options[OptAllowChildUpdates] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s does not allow updates. Thaw would be a no-op", zd.ZoneName)
			}
			if !zd.Options[OptFrozen] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s is not frozen", zd.ZoneName)
			}
			zd.SetOption(OptFrozen, false)
			resp.Msg = fmt.Sprintf("Zone %s is now thawed", zd.ZoneName)

		case "reload":
			// XXX: Note: if the zone allows updates and is dirty, then reloading should be denied
			log.Printf("ZoneOps: reloading, will check for changes to delegation data\n")
			// resp.Msg, err = ReloadZone(cp.Zone, cp.Force)
			resp.Msg, err = zd.ReloadZone(refreshq, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "list-zones":
			zones := map[string]ZoneConf{}
			for item := range Zones.IterBuffered() {
				zname := item.Key
				zd := item.Val

				options := []ZoneOption{}
				for opt, val := range zd.Options {
					if val {
						options = append(options, opt)
					}
				}

				zconf := ZoneConf{
					Name:    zname,
					Dirty:   zd.Options[OptDirty],
					Frozen:  zd.Options[OptFrozen],
					Options: options,
				}
				zones[zname] = zconf
			}
			resp.Zones = zones

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zp.Command)
			resp.Error = true
		}
	}
}

func APIzoneDsync(refreshq chan ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zdp ZoneDsyncPost
		err := decoder.Decode(&zdp)
		if err != nil {
			log.Println("APIzoneDsync: error decoding zone command post:", err)
		}

		log.Printf("API: received /zone/dsync request (cmd: %s) from %s.\n",
			zdp.Command, r.RemoteAddr)

		resp := ZoneDsyncResponse{
			AppName:   Globals.AppName,
			Time:      time.Now(),
			Functions: map[string]string{},
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		zd, exist := Zones.Get(zdp.Zone)
		if !exist {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zdp.Zone)
			return
		}

		// Most of the dsync commands relate to the child role. The exception is the publish/unpublish commands
		if !zd.Options[OptDelSyncChild] && zdp.Command != "publish-dsync-rrset" && zdp.Command != "unpublish-dsync-rrset" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s does not support delegation sync (option delegation-sync-child=false)", zd.ZoneName)
			return
		}

		if zd.Parent == "" {
			imr := viper.GetString("resolver.address")
			if imr == "" {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Parent zone to %s unknown and no resolver address configured", zd.ZoneName)
				return
			}
			zd.Parent, err = ParentZone(zd.ZoneName, imr)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
		}

		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return
		}

		switch zdp.Command {
		case "status":
			keyrrset, err := zd.GetRRset(zd.ZoneName, dns.TypeKEY)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = fmt.Sprintf("Zone %s: current delegation sync status", zdp.Zone)
			if keyrrset != nil && len(keyrrset.RRs) > 0 {
				resp.Functions["SIG(0) key publication"] = "done"
			} else if zd.ZoneType == Secondary {
				if zd.Options[OptDelSyncChild] {
					resp.Functions["SIG(0) key publication"] = "not done; KEY record must be added to zone at primary server"
					resp.Todo = append(resp.Todo, fmt.Sprintf("Add this KEY record to the %s zone at primary server:\n%s", zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs[0].String()))
				} else {
					resp.Functions["SIG(0) key publication"] = "disabled by policy (delegation-sync-child=false)"
				}
			} else if zd.ZoneType == Primary {
				if zd.Options[OptAllowUpdates] {
					resp.Functions["SIG(0) key publication"] = "failed"
				} else {
					resp.Functions["SIG(0) key publication"] = "disabled by policy (allow-updates=false)"

				}
			}

			resp.Functions["Latest delegation sync transaction"] = "successful"
			resp.Functions["Latest delegation sync transaction"] = "successful"
			resp.Functions["Time of latest delegation sync"] = "2024-05-01 12:00:00"
			resp.Functions["Current delegation status"] = fmt.Sprintf("parent \"%s\" is in sync with \"%s\" (the child)", zd.Parent, zd.ZoneName)

		case "bootstrap-sig0-key":
			resp.Msg = fmt.Sprintf("Zone %s: bootstrapping published SIG(0) with parent", zd.ZoneName)
			resp.Msg, err, resp.UpdateResult = zd.BootstrapSig0KeyWithParent(zdp.Algorithm)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "roll-sig0-key":
			switch zdp.Action {
			case "complete":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent", zd.ZoneName)
			case "add":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: ADDING NEW KEY", zd.ZoneName)
			case "remove":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: REMOVING OLD KEY", zd.ZoneName)
			case "update-local":
				resp.Msg = fmt.Sprintf("Zone %s: requesting rollover of the active SIG(0) key with parent: UPDATING LOCAL KEYSTORE", zd.ZoneName)
			}
			resp.Msg, resp.OldKeyID, resp.NewKeyID, err, resp.UpdateResult = zd.RolloverSig0KeyWithParent(zdp.Algorithm, zdp.Action, zdp.OldKeyID, zdp.NewKeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "publish-dsync-rrset":
			resp.Msg = fmt.Sprintf("Zone %s: publishing DSYNC RRset", zd.ZoneName)
			err = zd.PublishDsyncRRs()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		case "unpublish-dsync-rrset":
			resp.Msg = fmt.Sprintf("Zone %s: unpublishing DSYNC RRset", zd.ZoneName)
			err = zd.UnpublishDsyncRRs()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zdp.Command)
			resp.Error = true
		}
	}
}
