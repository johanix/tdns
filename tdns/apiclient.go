/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

// Client side API client calls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func NewClient(name, baseurl, apikey, authmethod, rootcafile string, verbose, debug bool) *Api {
	api := Api{
		Name:       name,
		BaseUrl:    baseurl,
		apiKey:     apikey,
		Authmethod: authmethod,
	}

	if rootcafile == "insecure" {
		api.Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	} else {
		rootCAPool := x509.NewCertPool()
		// rootCA, err := ioutil.ReadFile(viper.GetString("musicd.rootCApem"))
		rootCA, err := ioutil.ReadFile(rootcafile)
		if err != nil {
			log.Fatalf("reading cert failed : %v", err)
		}
		if debug {
			fmt.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n",
				name, rootcafile)
		}

		rootCAPool.AppendCertsFromPEM(rootCA)

		api.Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAPool,
				},
			},
		}
	}
	// api.Client = &http.Client{}
	api.Debug = debug
	api.Verbose = verbose
	// log.Printf("client is a: %T\n", api.Client)

	if debug {
		fmt.Printf("Setting up %s API client:\n", name)
		fmt.Printf("* baseurl is: %s \n* apikey is: %s \n* authmethod is: %s \n",
			api.BaseUrl, api.apiKey, api.Authmethod)
	}

	return &api
}

// request helper function
func (api *Api) requestHelper(req *http.Request) (int, []byte, error) {

	req.Header.Add("Content-Type", "application/json")

	if api.Authmethod == "" {
		// do not add any authentication header at all
	} else if api.Authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.apiKey)
	} else if api.Authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
	} else {
		log.Printf("Error: Client API Post: unknown auth method: %s. Aborting.\n",
			api.Authmethod)
		return 501, []byte{}, fmt.Errorf("unknown auth method: %s", api.Authmethod)
	}

	if api.Debug {
		fmt.Println()
		fmt.Printf("requestHelper: about to send request using auth method '%s' and key '%s'\n",
			api.Authmethod, api.apiKey)
	}

	if api.apiKey == "" {
		log.Fatalf("api.requestHelper: Error: apikey not set.\n")
	}

	resp, err := api.Client.Do(req)

	if err != nil {
		return 501, nil, err
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if api.Debug {
		var prettyJSON bytes.Buffer
		error := json.Indent(&prettyJSON, buf, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("requestHelper: received %d bytes of response data:\n%s\n", len(buf),
					   prettyJSON.String())
	}

	return resp.StatusCode, buf, err
}

func (api *Api) Post(endpoint string, data []byte) (int, []byte, error) {

	if api.Debug {
		var prettyJSON bytes.Buffer
		error := json.Indent(&prettyJSON, data, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("api.Post: posting to URL '%s' %d bytes of data:\n%s\n",
				      api.BaseUrl+endpoint, len(data), prettyJSON.String())
	}

	req, err := http.NewRequest(http.MethodPost, api.BaseUrl+endpoint,
		bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Delete (not tested)
func (api *Api) Delete(endpoint string) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Delete: posting to URL '%s'\n",
			api.BaseUrl+endpoint)
	}

	req, err := http.NewRequest(http.MethodDelete, api.BaseUrl+endpoint, nil)
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Get (not tested)
func (api *Api) Get(endpoint string) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Get: GET URL '%s'\n", api.BaseUrl+endpoint)
	}

	req, err := http.NewRequest(http.MethodGet, api.BaseUrl+endpoint, nil)
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Put
func (api *Api) Put(endpoint string, data []byte) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Put: posting to URL '%s' %d bytes of data: %v\n",
			api.BaseUrl+endpoint, len(data), string(data))
	}

	req, err := http.NewRequest(http.MethodPut, api.BaseUrl+endpoint,
		bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}
