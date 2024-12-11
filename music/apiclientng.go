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

func ExtractHoldPeriod(buf []byte) int {
	var de DesecError
	err := json.Unmarshal(buf, &de)
	if err != nil {
		log.Fatalf("Error from unmarshal DesecError: %v\n", err)
	}
	// "Request was throttled. Expected available in 1 second."
	fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Detail = strings.TrimLeft(de.Detail, "Request was throttled. Expected available in ")
	fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Detail = strings.TrimRight(de.Detail, " second.")
	fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
	de.Hold, err = strconv.Atoi(de.Detail)
	if err != nil {
		log.Printf("Error from Atoi: %v\n", err)
	}
	fmt.Printf("Rate-limited. Hold period: %d\n", de.Hold)
	return de.Hold
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
	if sc.Methods["API"] == false || sc.Details[tdns.MsignerMethodAPI].TlsaRR == nil {
		return fmt.Errorf("sidecar %s does not support the MUSIC API Method", sc.Identity)
	}

	api := MusicApi{
		ApiClient: tdns.NewClient(name, baseurl, apikey, authmethod, rootcafile, tdns.Globals.Verbose, tdns.Globals.Debug),
	}

	tlsconfig := &tls.Config{}

	if rootcafile == "insecure" {
		tlsconfig.InsecureSkipVerify = true
	} else if rootcafile == "tlsa" {
		// use TLSA RR for verification
		tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %v", err)
				}
				if cert.Subject.CommonName != sc.Identity {
					return fmt.Errorf("unexpected certificate common name (should have been %s)", sc.Identity)
				}

				err = tdns.VerifyCertAgainstTlsaRR(sc.Details[tdns.MsignerMethodDNS].TlsaRR, rawCert)
				if err != nil {
					return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
				}
			}
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

	if tdns.Globals.Debug {
		fmt.Printf("Setting up MUSIC Sync API client: %s\n", name)
		fmt.Printf("* baseurl is: %s \n* authmethod is: %s \n",
			api.ApiClient.BaseUrl, api.ApiClient.AuthMethod)
	}
	sc.Api = &api

	return nil
}

// I think that this API client is only used for deSEC login.
// XXX: This should die in favour of the tdns.ApiClient
// func xxxNewClient(name, baseurl, apikey, authmethod, rootcafile string, verbose, debug bool) *tdns.ApiClient {
// 	api := tdns.ApiClient{
// 		Name:       name,
// 		BaseUrl:    baseurl,
// 		apiKey:     apikey,
// 		AuthMethod: authmethod,
// 	}

// 	if rootcafile == "insecure" {
// 		api.Client = &http.Client{
// 			Transport: &http.Transport{
// 				TLSClientConfig: &tls.Config{
// 					InsecureSkipVerify: true,
// 				},
// 			},
// 		}
// 	} else if rootcafile == "tlsa" {
// 		// use TLSA RR for verification

// 	} else {
// 		rootCAPool := x509.NewCertPool()
// rootCA, err := ioutil.ReadFile(viper.GetString("musicd.rootCApem"))
// 		rootCA, err := os.ReadFile(rootcafile)
// 		if err != nil {
// 			log.Fatalf("reading cert failed : %v", err)
// 		}
// 		if debug {
// 			fmt.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n",
// 				name, rootcafile)
// 		}

// 		rootCAPool.AppendCertsFromPEM(rootCA)

// 		api.Client = &http.Client{
// 			Transport: &http.Transport{
// 				TLSClientConfig: &tls.Config{
// 					RootCAs: rootCAPool,
// 				},
// 			},
// 		}
// 	}
// 	// api.Client = &http.Client{}
// 	api.Debug = debug
// 	api.Verbose = verbose
// 	// log.Printf("client is a: %T\n", api.Client)

// 	if debug {
// 		fmt.Printf("Setting up %s API client:\n", name)
// 		fmt.Printf("* baseurl is: %s \n* apikey is: %s \n* authmethod is: %s \n",
// 			api.BaseUrl, api.apiKey, api.AuthMethod)
// 	}

// 	return &api
// }

// request helper function
// func (api *Api) requestHelper(req *http.Request) (int, []byte, error) {

// 	req.Header.Add("Content-Type", "application/json")

// 	if api.AuthMethod == "" {
// 		// do not add any authentication header at all
// 	} else if api.AuthMethod == "X-API-Key" {
// 		req.Header.Add("X-API-Key", api.apiKey)
// 	} else if api.AuthMethod == "Authorization" {
// 		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
// 	} else {
// 		log.Printf("Error: Client API Post: unknown auth method: %s. Aborting.\n",
// 			api.AuthMethod)
// 		return 501, []byte{}, fmt.Errorf("unknown auth method: %s", api.AuthMethod)
// 	}

// 	if api.Debug {
// 		fmt.Println()
// 		fmt.Printf("requestHelper: about to send request using auth method '%s' and key '%s'\n",
// 			api.AuthMethod, api.apiKey)
// 	}

// 	if api.apiKey == "" {
// 		log.Fatalf("api.requestHelper: Error: apikey not set.\n")
// 	}

// 	resp, err := api.Client.Do(req)

// 	if err != nil {
// 		return 501, nil, err
// 	}

// 	defer resp.Body.Close()
// 	buf, err := ioutil.ReadAll(resp.Body)
// 	if api.Debug {
// 		var prettyJSON bytes.Buffer
// 		error := json.Indent(&prettyJSON, buf, "", "  ")
// 		if error != nil {
// 			log.Println("JSON parse error: ", error)
// 		}
// 		fmt.Printf("requestHelper: received %d bytes of response data: %s\n", len(buf), prettyJSON.String())
// 		//fmt.Printf("requestHelper: received %d bytes of response data: %v\n",
// 		//len(buf), string(buf))
// 	}

// 	//not bothering to copy buf, this is a one-off
// 	return resp.StatusCode, buf, err
// }

// api NoAuthPost
// func (api *Api) NoAuthPost(endpoint string, data []byte) (int, []byte, error) {

// 	req, err := http.NewRequest(http.MethodPost, api.BaseUrl+endpoint,
// 		bytes.NewBuffer(data))
// 	if err != nil {
// 		log.Fatalf("Error from http.NewRequest: Error: %v", err)
// 	}

// 	req.Header.Add("Content-Type", "application/json")

// 	if api.Debug {
// 		fmt.Printf("api.NoAuthPost: posting to URL '%s' %d bytes of data: %v\n",
// 			api.BaseUrl+endpoint, len(data), string(data))
// 	}

// 	resp, err := api.Client.Do(req)
// 	if err != nil {
// 		return 501, nil, err
// 	}

// 	defer resp.Body.Close()
// 	buf, err := ioutil.ReadAll(resp.Body)

// 	if api.Debug {
// 		fmt.Printf("api.NoAuthPost: received %d bytes of response data: %v\n",
// 			len(buf), string(buf))
// 	}

// 	//not bothering to copy buf, this is a one-off
// 	return resp.StatusCode, buf, err
// }

func (api *MusicApi) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		return 501, nil, fmt.Errorf("api client is nil")
	}
	if api.ApiClient == nil || api.ApiClient.Client == nil {
		return 501, nil, fmt.Errorf("api client is nil")
	}
	return api.ApiClient.RequestNG(method, endpoint, data, dieOnError)
}
