/*
 * apiserver.go
 *
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns/tdns"
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

		log.Printf("APIzone: received /zone request (command: %s) from %s.\n", zp.Command, r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")

		switch zp.Command {
		case "list":
			zs, err := mdb.ListZones(tx)
			if err != nil {
				log.Printf("Error from ListZones: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Zones = zs
			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
			return
		}

		dbzone, _, err := mdb.GetZone(tx, zp.Zone.Name) // Get a more complete Zone structure
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			switch zp.Command {
			//			case "list":
			//				zs, err := mdb.ListZones(tx)
			//				if err != nil {
			//					log.Printf("Error from ListZones: %v", err)
			//				}
			//				resp.Zones = zs
			//			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
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
		resp := SidecarBeatResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		log.Printf("APIbeat: received /beat request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var bp SidecarBeatPost
		err := decoder.Decode(&bp)
		if err != nil {
			log.Println("APIbeat: error decoding beat post:", err)
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APIbeat: error encoding response: %v\n", err)
			}
		}()

		switch bp.MessageType {
		case "BEAT", "FULLBEAT":
			resp.Msg = "OK"
			mconf.Internal.HeartbeatQ <- SidecarBeatReport{
				Time: time.Now(),
				Beat: bp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %s", bp.MessageType)
		}
	}
}

func APIhello(mconf *Config) func(w http.ResponseWriter, r *http.Request) {
	if mconf.Internal.HeartbeatQ == nil {
		log.Println("APIhello: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := SidecarHelloResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var hp SidecarHelloPost
		err := decoder.Decode(&hp)
		if err != nil {
			log.Println("APIhello: error decoding hello post:", err)
		}

		switch hp.MessageType {
		case "HELLO":
			mconf.Internal.HeartbeatQ <- SidecarBeatReport{
				Time: time.Now(),
				Beat: SidecarBeatPost{
					Identity:    hp.Identity,
					MessageType: "HELLO",
					Time:        time.Now(),
					SharedZones: hp.Zones,
				},
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %s", hp.MessageType)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from json.NewEncoder: %v\n", err)
		}
	}
}

func APIshow(conf *Config, router *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	address := viper.GetString("apiserver.address")
	name := viper.GetString("service.name")
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

			data := []string{fmt.Sprintf("API provided by %s listening on: %v", name, address)}

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

func APIsidecar(mconf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var sp SidecarPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIsidecar: error decoding sidecar post:", err)
		}

		log.Printf("APIsidecar: received /sidecar request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		var resp = SidecarResponse{
			Status: 101,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			// Note: the resp.Sidecars field has already been cleaned from non serializable fields in the MusicSyncEngine.
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error encoding response: %v\n", err)
				dump.P(resp)
			}
		}()

		switch strings.ToLower(sp.Command) {
		case "status":
			responseCh := make(chan MusicSyncStatus)
			log.Printf("APIsidecar: STATUS request received")
			mconf.Internal.MusicSyncStatusQ <- MusicSyncStatus{
				Command:  "STATUS",
				Response: responseCh,
			}
			log.Printf("APIsidecar: STATUS request sent to MusicSyncStatusQ")
			select {
			case tmp := <-responseCh:
				log.Printf("APIsidecar: STATUS response received")
				if tmp.Error {
					http.Error(w, tmp.ErrorMsg, http.StatusInternalServerError)
					return
				}
				resp.Sidecars = tmp.Sidecars

			case <-time.After(5 * time.Second):
				log.Printf("APIsidecar: STATUS request timed out")
				http.Error(w, "Request timed out", http.StatusGatewayTimeout)
				return
			}
		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", sp.Command)
		}

	}
}

// This is the sidecar mgmt API router.
func SetupAPIRouter(tconf *tdns.Config, mconf *Config) (*mux.Router, error) {
	kdb := tconf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)
	apikey := mconf.ApiServer.ApiKey
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()

	// TDNS stuff
	sr.HandleFunc("/ping", tdns.APIping(tconf)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone", tdns.APIzone(&tconf.App, tconf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(tconf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", tdns.APIdebug()).Methods("POST")

	sr.HandleFunc("/command", tdns.APIcommand(tconf)).Methods("POST")
	sr.HandleFunc("/config", tdns.APIconfig(tconf)).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	// MUSIC stuff
	sr.HandleFunc("/signer", APIsigner(mconf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(mconf)).Methods("POST")
	sr.HandleFunc("/signergroup", APIsignergroup(mconf)).Methods("POST")
	sr.HandleFunc("/test", APItest(mconf)).Methods("POST")
	sr.HandleFunc("/process", APIprocess(mconf)).Methods("POST")
	sr.HandleFunc("/show", APIshow(mconf, r)).Methods("POST")

	sr.HandleFunc("/sidecar", APIsidecar(mconf)).Methods("POST")

	return r, nil
}

// This is the sidecar-to-sidecar sync API router.
func SetupMusicSyncRouter(tconf *tdns.Config, mconf *Config) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", HomeLink)

	// Create base subrouter without auth header requirement
	sr := r.PathPrefix("/api/v1").Subrouter()

	// Special case for /hello endpoint which validates against TLSA in payload
	sr.HandleFunc("/hello", APIhello(mconf)).Methods("POST")

	// All other endpoints require valid client cert matching TLSA record
	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("secureRouter: %s", r.URL.Path)
			// Skip validation for /hello endpoint
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}

			// Get peer certificate from TLS connection
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]

			// Get TLSA record for the client's identity and verify
			clientId := clientCert.Subject.CommonName
			sidecar, ok := Globals.Sidecars.S.Get(clientId)
			if !ok {
				log.Printf("secureRouter: Unknown client identity: %s", clientId)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			tlsaRR := sidecar.Details[tdns.MsignerMethodAPI].TlsaRR
			if tlsaRR == nil {
				log.Printf("secureRouter: No TLSA record available for client: %s", clientId)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			err := tdns.VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw)
			if err != nil {
				log.Printf("secureRouter: Certificate verification for client id '%s' failed: %v", clientId, err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	secureRouter.HandleFunc("/ping", tdns.APIping(tconf)).Methods("POST")
	secureRouter.HandleFunc("/beat", APIbeat(mconf)).Methods("POST")

	return r, nil
}

// This is the sidecar-to-sidecar sync API dispatcher.
func MusicSyncAPIdispatcher(tconf *tdns.Config, mconf *Config, done <-chan struct{}) error {
	log.Printf("MusicSyncAPIdispatcher: starting with sidecar ID '%s'", mconf.Sidecar.Identity)

	router, err := SetupMusicSyncRouter(tconf, mconf)
	if err != nil {
		return err
	}
	addresses := mconf.Sidecar.Api.Addresses.Listen
	port := mconf.Sidecar.Api.Port
	certFile := mconf.Sidecar.Api.Cert
	keyFile := mconf.Sidecar.Api.Key
	if len(addresses) == 0 {
		log.Println("MusicSyncAPIdispatcher: no addresses to listen on. Not starting.")
		return nil
	}
	if certFile == "" || keyFile == "" {
		log.Println("MusicSyncAPIdispatcher: certFile or keyFile not set. Not starting.")
		return nil
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequestClientCert, // Request but don't require - we'll handle verification in middleware
		MinVersion: tls.VersionTLS12,
		// Remove VerifyPeerCertificate as we now handle this in middleware per-endpoint
	}

	for idx, address := range addresses {
		idxCopy := idx
		go func(address string, idx int) {
			server := &http.Server{
				Handler:   router,
				TLSConfig: tlsConfig,
				Addr:      net.JoinHostPort(address, fmt.Sprintf("%d", port)),
			}

			log.Printf("Starting MusicSyncAPI dispatcher #%d. Listening on '%s'\n", idx, server.Addr)
			log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
		}(string(address), idxCopy)

		log.Println("MusicSyncAPIdispatcher: unclear how to stop the http server nicely.")
	}
	return nil
}
