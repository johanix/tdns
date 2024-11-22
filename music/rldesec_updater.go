/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type RLDesecUpdater struct {
	FetchCh  chan SignerOp
	UpdateCh chan SignerOp
	Api      Api
}

func init() {
	Updaters["rldesec-api"] = &RLDesecUpdater{
		Api: Api{},
	}
}

func (u *RLDesecUpdater) SetChannels(fetch, update chan SignerOp) {
	u.FetchCh = fetch
	u.UpdateCh = update
}

func (u *RLDesecUpdater) SetApi(api Api) {
	u.Api = api
}

func (u *RLDesecUpdater) GetApi() Api {
	return u.Api
}

func (u *RLDesecUpdater) FetchRRset(s *Signer, zone, owner string,
	rrtype uint16) (error, []dns.RR) {

	// what we want:
	op := SignerOp{
		Signer:   s,
		Zone:     zone,
		Owner:    owner,
		RRtype:   rrtype,
		Response: make(chan SignerOpResult),
	}
	u.FetchCh <- op
	time.Sleep(1 * time.Second)
	resp := <-op.Response
	return resp.Error, resp.RRs
}

// Returns: rrl=true if reate-limited, int=seconds penalty (now testing with status),
//          error (if any), []dns.RR data
func RLDesecFetchRRset(fdop SignerOp) (bool, int, error) {
	signer := fdop.Signer
	zone := fdop.Zone
	owner := fdop.Owner
	rrtype := fdop.RRtype
	mdb := signer.MusicDB()
	verbose := viper.GetBool("common.verbose")
	// log.Printf("FetchRRset: looking up '%s IN %s' from %s\n", owner,
	//    dns.TypeToString[rrtype], s.Address)

	zone = StripDot(zone)
	owner = StripDot(owner)

	endpoint := fmt.Sprintf("/domains/%s/rrsets/%s/%s/",
		zone, DesecSubname(zone, owner, true),
		dns.TypeToString[rrtype])

	// temporary kludge
	api := GetUpdater("rldesec-api").GetApi()
	api.DesecTokenRefresh()

	fmt.Printf("FetchRRset: deSEC API endpoint: %s. token: %s\n", endpoint, api.apiKey)
	status, buf, err := api.Get(endpoint)

	if err != nil {
		log.Printf("Error from api.Get (desec): %v\n", err)
		// not rate-limited, no hold, but error from API transaction
		return false, 0, fmt.Errorf("Error from deSEC API for %s: %v",
			endpoint, err)
	}

	if status == 429 { // we have been rate-limited
		fmt.Printf("desec.FetchRRset: rate-limit. This is what we got: '%v'. Retry in %d seconds.\n", string(buf), 10)
		// return true, status, nil, []dns.RR{}
		hold := ExtractHoldPeriod(buf)
		// rate-limited, hold period, no error
		return false, hold, nil // API should be (RL success, hold period, error)
	}

	fmt.Printf("FetchRRset: got a response from deSEC:\n%v\n", string(buf))
	if verbose {
		fmt.Printf("FetchRRset: status: %d\n", status)
	}

	var dr DesecResponseRRset
	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("FetchRRset: Error from unmarshal: %v\n", err)
	}

	var rrs []dns.RR

	for _, r := range dr.RData {
		rrstr := fmt.Sprintf("%s %d IN %s %s", dr.Name, dr.TTL, dr.RRtype, r)
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			// not rate-limited, no hold, but error return for parse error
			return true, 0,
				fmt.Errorf("FetchRRset: Error parsing RR into dns.RR: %v\n",
					err)
		}
		rrs = append(rrs, rr)
	}

	mdb.WriteRRs(signer, dns.Fqdn(owner), zone, rrtype, rrs)
	// return false, status, nil, DNSFilterRRsetOnType(rrs, rrtype)
	fdop.Response <- SignerOpResult{
		Status:   status,
		RRs:      DNSFilterRRsetOnType(rrs, rrtype),
		Error:    err,
		Response: "Obladi, oblada!",
	}
	return true, 0, nil // all is good, we're done with this request
}

func (u *RLDesecUpdater) Update(signer *Signer, zone, owner string,
	inserts, removes *[][]dns.RR) error {
	op := SignerOp{
		Signer:   signer,
		Zone:     zone,
		Owner:    owner,
		Inserts:  inserts,
		Removes:  removes,
		Response: make(chan SignerOpResult, 2),
	}
	u.UpdateCh <- op
	time.Sleep(1 * time.Second)
	resp := <-op.Response
	return resp.Error
}

func RLDesecUpdate(udop SignerOp) (bool, int, error) {
	// signer := udop.Signer
	zone := StripDot(udop.Zone)
	owner := udop.Owner
	inserts := udop.Inserts
	removes := udop.Removes

	verbose := viper.GetBool("common.verbose")

	fmt.Printf("DesecUpdater: inserts: %v removes: %v\n", inserts, removes)

	endpoint := fmt.Sprintf("/domains/%s/rrsets/", zone)
	//endpoint := fmt.Sprintf("/domains/%s/rrsets/%s/%s/",
	//	      		  zone, DesecSubname(zone, owner, true),
	//			  dns.TypeToString[rrtype])

	desecRRsets := []DesecRRset{}

	if inserts != nil {
		for _, rrset := range *inserts {
			if len(rrset) == 0 {
				continue
			}

			desecRRset, err := CreateDesecRRset(zone, owner, rrset, false)
			if err != nil {
				log.Printf("Error from DesecCreateRRset: %v\n", err)
			} else {
				desecRRsets = append(desecRRsets, desecRRset)
			}
		}
	}

	if removes != nil {
		for _, rrset := range *removes {
			if len(rrset) == 0 {
				continue
			}

			desecRRset, err := CreateDesecRRset(zone, owner, rrset, true)
			if err != nil {
				log.Printf("Error from DesecCreateRRset: %v\n", err)
			} else {
				desecRRsets = append(desecRRsets, desecRRset)
			}
		}
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(desecRRsets)

	api := GetUpdater("rldesec-api").GetApi()
	api.DesecTokenRefresh()
	fmt.Printf("RLdeSECUpdater: deSEC API endpoint: %s. Data: %v\n",
		endpoint, desecRRsets)

	status, buf, err := api.Put(endpoint, bytebuf.Bytes())
	if err != nil {
		log.Printf("Error from api.Post (desec): %v\n", err)
		udop.Response <- SignerOpResult{
			Error: fmt.Errorf("Error from deSEC API for %s: %v",
				endpoint, err),
		}
		return false, 0, nil
	}

	if verbose {
		fmt.Printf("DesecUpdateRRset: status: %d\n", status)
	}

	udop.Response <- SignerOpResult{
		Error: nil, // + send back some sort of desec status code?
	}
	fmt.Printf("DesecUpdateRRset: buf: %v\n", string(buf))
	return false, 0, nil
}

func (u *RLDesecUpdater) RemoveRRset(signer *Signer, zone, owner string, rrsets [][]dns.RR) error {

	fmt.Printf("Desec RemoveRRset: rrsets: %v\n", rrsets)
	return u.Update(signer, zone, owner, &[][]dns.RR{}, &rrsets)
}
