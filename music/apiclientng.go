/*
 * Johan Stenstam, johani@johani.org
 */
package music

// Client side API client calls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	tdns "github.com/johanix/tdns/tdns"
)

func ExtractHoldPeriod(buf []byte) (int, error) {
	var de DesecError
	err := json.Unmarshal(buf, &de)
	if err != nil {
		return 0, fmt.Errorf("error unmarshalling DesecError: %v", err)
	}
	// "Request was throttled. Expected available in 1 second."
	// log.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Detail = strings.TrimPrefix(de.Detail, "Request was throttled. Expected available in ")
	// log.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Detail = strings.TrimSuffix(de.Detail, " second.")
	// log.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Hold, err = strconv.Atoi(de.Detail)
	if err != nil {
		return 0, fmt.Errorf("error converting hold period to int: %v", err)
	}
	log.Printf("Rate-limited. Hold period: %d\n", de.Hold)
	return de.Hold, nil
}

type DesecError struct {
	Detail string
	Hold   int
}

// The MUSIC API client has extrasupport for verification of a server cert against a TLSA, login parameters for deSEC, etc.
func (sc *Sidecar) NewMusicSyncApiClient(name, baseurl, apikey, authmethod, rootcafile string) error {
	if sc == nil {
		return fmt.Errorf("sidecar is nil")
	}
	if !sc.Methods["API"] || sc.Details[tdns.MsignerMethodAPI].TlsaRR == nil {
		return fmt.Errorf("sidecar %s does not support the MUSIC API Method", sc.Identity)
	}

	api := MusicApi{
		ApiClient: tdns.NewClient(name, baseurl, apikey, authmethod, rootcafile, tdns.Globals.Verbose, tdns.Globals.Debug),
	}

	tlsconfig := &tls.Config{}

	if rootcafile == "insecure" {
		tlsconfig.InsecureSkipVerify = true
	} else if rootcafile == "tlsa" {
		// use TLSA RR for verification; InsecureSkipVerify must still be true
		tlsconfig.InsecureSkipVerify = true
		// use TLSA RR for verification
		tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			log.Printf("NewMusicSyncApiClient: VerifyPeerCertificate called for %s (have TLSA: %s)", sc.Identity,
				sc.Details[tdns.MsignerMethodAPI].TlsaRR.String())
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %v", err)
				}
				if cert.Subject.CommonName != "api."+sc.Identity {
					return fmt.Errorf("unexpected certificate common name (should have been %s)", sc.Identity)
				}

				err = tdns.VerifyCertAgainstTlsaRR(sc.Details[tdns.MsignerMethodAPI].TlsaRR, rawCert)
				if err != nil {
					return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
				}
			}
			// log.Printf("NewMusicSyncApiClient: VerifyPeerCertificate returning nil (all good)")
			return nil
		}
	} else {
		rootCAPool := x509.NewCertPool()
		// rootCA, err := ioutil.ReadFile(viper.GetString("musicd.rootCApem"))
		rootCA, err := os.ReadFile(rootcafile)
		if err != nil {
			log.Fatalf("reading cert failed : %v", err)
		}
		if tdns.Globals.Debug {
			fmt.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n",
				name, rootcafile)
		}

		rootCAPool.AppendCertsFromPEM(rootCA)
		tlsconfig.RootCAs = rootCAPool
	}

	// api.Client = &http.Client{}
	api.ApiClient.Client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig},
	}

	api.ApiClient.Debug = tdns.Globals.Debug
	api.ApiClient.Verbose = tdns.Globals.Verbose
	// log.Printf("client is a: %T\n", api.Client)

	// dump.P(tlsconfig)

	if tdns.Globals.Debug {
		fmt.Printf("Setting up MUSIC Sync API client: %s\n", name)
		fmt.Printf("* baseurl is: %s \n* authmethod is: %s \n",
			api.ApiClient.BaseUrl, api.ApiClient.AuthMethod)
	}
	sc.Api = &api

	return nil
}

func (api *MusicApi) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		return 501, nil, fmt.Errorf("MusicApi client is nil")
	}
	if api.ApiClient == nil || api.ApiClient.Client == nil {
		return 501, nil, fmt.Errorf("TDNS API client is nil")
	}
	return api.ApiClient.RequestNG(method, endpoint, data, dieOnError)
}
