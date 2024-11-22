/*
 * apiserver.go
 *
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

func HomeLink(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome home!")
}

func API_NYI(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "NYI")

		status := 101
		resp := "NYI"

		apistatus := APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(apistatus)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIGoAway(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		status := 404
		resp := "These are not the droids you're looking for"

		apistatus := APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(apistatus)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

var pongs int = 0

func APItest(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		var resp = TestResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		tx, err := mdb.StartTransactionNG()
		if err != nil {
			log.Printf("APItest: Error from mdb.StartTransactionNG(): %v\n", err)
			resp.Msg = "Error from mdb.StartTransactionNG()"
			resp.Error = true
			resp.ErrorMsg = err.Error()
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
			return
		}
		defer func() {
			mdb.CloseTransactionNG(tx, err)
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var tp TestPost
		err = decoder.Decode(&tp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APItest: received /test request (command: %s) from %s.\n",
			tp.Command, r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")

		switch tp.Command {
		case "dnsquery":
			signer, err := mdb.GetSigner(tx, &Signer{Name: tp.Signer}, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			updater := GetUpdater(signer.Method)
			if updater == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error: Unknown updater: '%s'.", tp.Updater)

			}
			rrtype := dns.StringToType[tp.RRtype]
			if !resp.Error {
				i := 0
				queuedepth := 0
				switch signer.Method {
				case "ddns", "desec-api":
					queuedepth = 0
				case "rlddns":
					queuedepth = len(conf.Internal.DdnsFetch)
				case "rldesec":
					queuedepth = len(conf.Internal.DesecFetch)
				}

				fmt.Printf("Test DNS Query: currently %d fetch requests in the '%s' fetch queue.\n",
					queuedepth, signer.Method)
				fmt.Printf("Test DNS Query: will send %d queries for '%s %s'\n",
					tp.Count, tp.Qname, tp.RRtype)
				for i = 0; i < tp.Count; i++ {
					// err, _ = updater.FetchRRset(signer, tp.Zone, tp.Qname, rrtype)
					go updater.FetchRRset(signer, tp.Zone, tp.Qname, rrtype)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
						break
					}
					fmt.Printf("Test DNS Query: query %d (of %d) done.\n", i, tp.Count)
				}
				resp.Msg = fmt.Sprintf("All %d fetch requests done\n", i)
			}

		default:
		}

		//		err = json.NewEncoder(w).Encode(resp)
		//		if err != nil {
		//			log.Printf("Error from Encoder: %v\n", err)
		//		}
	}
}

func APIzone(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	enginecheck := conf.Internal.EngineCheck // need to be able to send this to Zone{Add,...}

	return func(w http.ResponseWriter, r *http.Request) {

		var resp = ZoneResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		tx, err := mdb.StartTransactionNG()
		if err != nil {
			log.Printf("APIzone: Error from mdb.StartTransactionNG(): %v\n", err)
			resp.Msg = "Error from mdb.StartTransactionNG()"
			resp.Error = true
			resp.ErrorMsg = err.Error()
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
			return
		}
		defer func() {
			mdb.CloseTransactionNG(tx, err)
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var zp ZonePost
		err = decoder.Decode(&zp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APIzone: received /zone request (command: %s) from %s.\n",
			zp.Command, r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")

		dbzone, _, err := mdb.GetZone(tx, zp.Zone.Name) // Get a more complete Zone structure
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			switch zp.Command {
			case "list":
				zs, err := mdb.ListZones(tx)
				if err != nil {
					log.Printf("Error from ListZones: %v", err)
				}
				resp.Zones = zs
			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
			case "status":
				var zl = make(map[string]Zone, 1)
				if dbzone.Exists {
					sg, err := mdb.GetSignerGroup(tx, dbzone.SGname, true)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {

						zl[dbzone.Name] = Zone{
							Name:       dbzone.Name,
							State:      dbzone.State,
							Statestamp: dbzone.Statestamp,
							NextState:  dbzone.NextState,
							FSM:        dbzone.FSM,
							SGroup:     sg,
							SGname:     sg.Name,
						}
						resp.Zones = zl
					}

				} else {
					message := fmt.Sprintf("Zone %s: not in DB", zp.Zone.Name)
					log.Println(message)
					resp.Msg = message
				}

			case "add":
				fmt.Printf("apiserver:/zone: zone: %v group: '%s'", zp.Zone, zp.SignerGroup)
				resp.Msg, err = mdb.AddZone(tx, &zp.Zone, zp.SignerGroup, enginecheck)
				if err != nil {
					// log.Printf("Error from AddZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "update":
				resp.Msg, err = mdb.UpdateZone(tx, dbzone, &zp.Zone, enginecheck)
				if err != nil {
					// log.Printf("Error from UpdateZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "delete":
				resp.Msg, err = mdb.DeleteZone(tx, dbzone) // XXX: shouldn't there be a tx here?
				if err != nil {
					// log.Printf("Error from DeleteZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "join":
				resp.Msg, err = mdb.ZoneJoinGroup(tx, dbzone, zp.SignerGroup, enginecheck)
				if err != nil {
					// log.Printf("Error from ZoneJoinGroup: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "leave":
				resp.Msg, err = mdb.ZoneLeaveGroup(tx, dbzone, zp.SignerGroup)
				if err != nil {
					// log.Printf("Error from ZoneLeaveGroup: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			// XXX: A single zone cannot "choose" to join an FSM, it's the Group that does that.
			//      This endpoint is only here for development and debugging reasons.
			case "fsm":
				resp.Msg, err = mdb.ZoneAttachFsm(tx, dbzone, zp.FSM, zp.FSMSigner, false)
				if err != nil {
					// log.Printf("Error from ZoneAttachFsm: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "step-fsm":
				// var zones map[string]music.Zone
				// var success bool
				// err, resp.Msg, zones = mdb.ZoneStepFsm(nil, dbzone, zp.FsmNextState)
				// log.Printf("APISERVER: STEP-FSM: Calling ZoneStepFsm for zone %s and %v\n", dbzone.Name, zp.FsmNextState)
				var success bool
				log.Printf("$$$ ROG-> calling mdb.ZoneStepFsm with %v as tx", tx)
				success, resp.Msg, err = mdb.ZoneStepFsm(tx, dbzone, zp.FsmNextState)
				if err != nil {
					log.Printf("APISERVER: Error from ZoneStepFsm: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
					// resp.Zones = zones
					// resp.Zones = map[string]Zone{ dbzone.Name: *dbzone }
					// w.Header().Set("Content-Type", "application/json")
				}
				log.Printf("APISERVER: STEP-FSM: pre GetZone\n")
				dbzone, _, err = mdb.ApiGetZone(tx, dbzone.Name) // apisafe
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if !success {
						dbzone.StopReason, _, err = mdb.GetStopReason(tx, dbzone)
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						}
					}
					resp.Zones = map[string]Zone{dbzone.Name: *dbzone}
				}
				// err = json.NewEncoder(w).Encode(resp)
				//if err != nil {
				//	log.Printf("Error from Encoder: %v\n", err)
				//}
				return

			case "get-rrsets":
				// var rrsets map[string][]dns.RR
				err, msg, _ := mdb.ZoneGetRRsets(dbzone, zp.Owner, zp.RRtype)
				resp.Msg = msg
				if err != nil {
					// log.Printf("Error from ZoneGetRRset: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// dbzone, _ := mdb.GetZone(tx, zp.Zone.Name)
					sg := dbzone.SignerGroup()
					// fmt.Printf("APIzone: get-rrsets: zone: %v sg: %v\n", zp.Zone, sg)

					var result = map[string][]string{}
					var rrset []string
					for k, _ := range sg.Signers() {
						err, resp.Msg, rrset = mdb.ListRRset(tx, dbzone, k, zp.Owner,
							zp.RRtype)
						if err != nil {
							log.Fatalf("APIzone: get-rrsets: Error from ListRRset: %v\n", err)
						} else {
							result[k] = rrset
						}
					}
					resp.RRsets = result
					// fmt.Printf("get:rrsets: len: %d\n", len(rrsets))
				}
				//err = json.NewEncoder(w).Encode(resp)
				//if err != nil {
				//	log.Printf("Error from Encoder: %v\n", err)
				//}
				return

			case "copy-rrset":
				fmt.Printf("APIzone: copy-rrset: %s %s %s\n", dbzone.Name,
					zp.Owner, zp.RRtype)
				// var rrset []dns.RR
				err, resp.Msg = mdb.ZoneCopyRRset(tx, dbzone, zp.Owner, zp.RRtype,
					zp.FromSigner, zp.ToSigner)
				if err != nil {
					log.Printf("Error from ZoneCopyRRset: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// resp.RRset = rrset
					// fmt.Printf("copy:rrset: len: %d\n", len(rrset))
				}
				//err = json.NewEncoder(w).Encode(resp)
				//if err != nil {
				//	log.Printf("Error from Encoder: %v\n", err)
				//}
				return

			case "list-rrset":
				var rrset []string
				err, resp.Msg, rrset = mdb.ListRRset(tx, dbzone, zp.Signer,
					zp.Owner, zp.RRtype)
				if err != nil {
					log.Printf("Error from ListRRset: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.RRset = rrset
				}
				//err = json.NewEncoder(w).Encode(resp)
				//if err != nil {
				//	log.Printf("Error from Encoder: %v\n", err)
				//}
				return

			case "meta":
				dbzone.ZoneType = zp.Zone.ZoneType
				resp.Msg, err = mdb.ZoneSetMeta(tx, dbzone, zp.Metakey, zp.Metavalue)
				if err != nil {
					// log.Printf("Error from ZoneSetMeta: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			default:
			}
		}
		/*
			zs, err := mdb.ListZones()
			if err != nil {
				log.Printf("Error from ListZones: %v", err)
			}
			resp.Zones = zs
			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
		*/
		// err = json.NewEncoder(w).Encode(resp)
		//if err != nil {
		//   log.Printf("Error from Encoder: %v\n", err)
		//}
	}
}

func APIsigner(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		var resp = SignerResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		tx, err := mdb.StartTransactionNG()
		if err != nil {
			log.Printf("APIsigner: Error from mdb.StartTransactionNG(): %v\n", err)
			resp.Msg = "Error from mdb.StartTransactionNG()"
			resp.Error = true
			resp.ErrorMsg = err.Error()
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
			return
		}
		defer func() {
			mdb.CloseTransactionNG(tx, err)
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var sp SignerPost
		err = decoder.Decode(&sp)
		if err != nil {
			log.Println("APIsigner: error decoding signer post:",
				err)
		}

		log.Printf("APIsigner: received /signer request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		dbsigner, _ := mdb.GetSigner(tx, &sp.Signer, false) // not apisafe

		switch sp.Command {
		case "list":
			ss, err := mdb.ListSigners(tx)
			if err != nil {
				log.Printf("Error from ListSigners: %v", err)
			}
			resp.Signers = ss

		case "add":
			resp.Msg, err = mdb.AddSigner(tx, dbsigner, sp.SignerGroup)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "update":
			resp.Msg, err = mdb.UpdateSigner(tx, dbsigner, sp.Signer)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "delete":
			resp.Msg, err = mdb.DeleteSigner(tx, dbsigner)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "join":
			resp.Msg, err = mdb.SignerJoinGroup(tx, dbsigner, sp.Signer.SignerGroup)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "leave":
			resp.Msg, err = mdb.SignerLeaveGroup(tx, dbsigner, sp.Signer.SignerGroup)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "login":
			err, resp.Msg = mdb.SignerLogin(dbsigner, &CliConf, TokVip)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "logout":
			err, resp.Msg = mdb.SignerLogout(dbsigner, &CliConf, TokVip)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		default:
		}

		ss, err := mdb.ListSigners(tx)
		if err != nil {
			log.Printf("Error from ListSigners: %v", err)
		}
		resp.Signers = ss

		w.Header().Set("Content-Type", "application/json")
		//		err = json.NewEncoder(w).Encode(resp)
		//		if err != nil {
		//			log.Printf("Error from Encoder: %v\n", err)
		//		}
	}
}

func APIsignergroup(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		var resp = SignerGroupResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		tx, err := mdb.StartTransactionNG()
		if err != nil {
			log.Printf("APIsignergroup: Error from mdb.StartTransactionNG(): %v\n", err)
			resp.Msg = "Error from mdb.StartTransactionNG()"
			resp.Error = true
			resp.ErrorMsg = err.Error()
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
			return
		}
		defer func() {
			mdb.CloseTransactionNG(tx, err)
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
		}()

		log.Printf("APIsignergroup: received /signergroup request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var sgp SignerGroupPost
		err = decoder.Decode(&sgp)
		if err != nil {
			log.Println("APIsignergroup: error decoding signergroup post:",
				err)
		}

		fmt.Printf("apiserver: /signergroup %v\n", sgp)

		switch sgp.Command {
		case "list":

		case "add":
			fmt.Printf("apiserver: AddSignerGroup\n")
			msg, err := mdb.AddSignerGroup(tx, sgp.Name)
			if err != nil {
				log.Printf("Error from AddSignerGroup: %v", err)
			}
			resp.Msg = msg

		case "delete":
			msg, err := mdb.DeleteSignerGroup(tx, sgp.Name)
			if err != nil {
				log.Printf("Error from DeleteSignerGroup: %v", err)
			}
			resp.Msg = msg
		default:

		}

		ss, err := mdb.ListSignerGroups(tx)
		if err != nil {
			log.Printf("Error from ListSignerGroups: %v", err)
		}
		resp.SignerGroups = ss

		w.Header().Set("Content-Type", "application/json")
		//		err = json.NewEncoder(w).Encode(resp)
		//		if err != nil {
		//			log.Printf("Error from Encoder: %v\n", err)
		//		}
	}
}

func APIprocess(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	var check EngineCheck
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIprocess: received /process request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp ProcessPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIprocess: error decoding process post:", err)
		}

		var resp = ProcessResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		fmt.Printf("apiserver: /process %v\n", pp)

		switch pp.Command {
		case "list":
			sp, err, msg := mdb.ListProcesses()
			if err != nil {
				log.Printf("Error from ListProcesses: %v", err)
				resp.Error = true
				resp.ErrorMsg = msg
			}
			resp.Processes = sp

		case "check":
			conf.Internal.EngineCheck <- check
			resp.Msg = "FSM Engine will make a run through all non-blocked zones immediately."

		case "graph":
			graph, err := mdb.GraphProcess(pp.Process)
			if err != nil {
				log.Printf("Error from GraphProcess: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Graph = graph

		default:

		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIbeat(mconf *Config) func(w http.ResponseWriter, r *http.Request) {
	if mconf.Internal.HeartbeatQ == nil {
		log.Println("APIbeat: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := BeatResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		log.Printf("APIbeat: received /beat request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var bp BeatPost
		err := decoder.Decode(&bp)
		if err != nil {
			log.Println("APIbeat: error decoding beat post:", err)
		}

		switch bp.Type {
		case "BEAT", "FULLBEAT":
			resp.Msg = "OK"
			mconf.Internal.HeartbeatQ <- Heartbeat{
				Name:  bp.Name,
				Type:  bp.Type,
				Time:  time.Now(),
				Zones: bp.Zones,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %s", bp.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from json.NewEncoder: %v\n", err)
		}
	}
}

func APIhello(mconf *Config) func(w http.ResponseWriter, r *http.Request) {
	if mconf.Internal.HeartbeatQ == nil {
		log.Println("APIhello: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := HelloResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var hp HelloPost
		err := decoder.Decode(&hp)
		if err != nil {
			log.Println("APIhello: error decoding hello post:", err)
		}

		switch hp.Type {
		case "HELLO":
			mconf.Internal.HeartbeatQ <- Heartbeat{
				Name:  hp.Name,
				Type:  "HELLO",
				Time:  time.Now(),
				Zones: hp.Zones,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %s", hp.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from json.NewEncoder: %v\n", err)
		}
	}
}

func APIshow(conf *Config, router *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	address := viper.GetString("services.apiserver.api")
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var sp ShowPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIshow: error decoding show post:", err)
		}

		log.Printf("APIshow: received /show request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		var resp = ShowResponse{
			Status: 101,
		}

		switch sp.Command {
		case "api":
			message := "All ok, here are all defined API endpoints"

			data := []string{fmt.Sprintf("API provided by MUSICD listening on: %s",
				address)}

			walker := func(route *mux.Route, router *mux.Router,
				ancestors []*mux.Route) error {
				path, _ := route.GetPathTemplate()
				methods, _ := route.GetMethods()
				for m := range methods {
					data = append(data, fmt.Sprintf("%-6s %s", methods[m], path))
				}
				return nil
			}
			if err := router.Walk(walker); err != nil {
				log.Panicf("Logging err: %s\n", err.Error())
			}
			resp.Message = message
			resp.ApiData = data

		case "updaters":
			resp.Message = "Defined updaters"
			resp.Updaters = ListUpdaters()
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}
