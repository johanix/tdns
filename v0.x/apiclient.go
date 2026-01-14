/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

// Client side API client calls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"strings"

	"fmt"
	"log"
	"net/http"
	"net/url"
)

func NewClient(name, baseurl, apikey, authmethod, rootcafile string) *ApiClient {
	api := ApiClient{
		Name:       name,
		BaseUrl:    baseurl,
		apiKey:     apikey,
		AuthMethod: authmethod,
	}

	tlsconfig := &tls.Config{}

	if rootcafile == "insecure" {
		tlsconfig.InsecureSkipVerify = true
	} else if rootcafile == "tlsa" {

		// In the TLSA case, do nothing here, the TLSConfig will be filled in from the Agent side afterwards.

		// use TLSA RR for verification
		//		tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		//			for _, rawCert := range rawCerts {
		//				cert, err := x509.ParseCertificate(rawCert)
		//				if err != nil {
		//					return fmt.Errorf("failed to parse certificate: %v", err)
		//				}
		//				if cert.Subject.CommonName != sc.Identity {
		//					return fmt.Errorf("unexpected certificate common name (should have been %s)", sc.Identity)
		//				}
		//
		//				err = tdns.VerifyCertAgainstTlsaRR(sc.Details[tdns.MsignerMethodDNS].TlsaRR, rawCert)
		//				if err != nil {
		//					return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
		//				}
		//			}
		//			return nil
		//		}
	} else {
		rootCAPool := x509.NewCertPool()
		// rootCA, err := os.ReadFile(viper.GetString("musicd.rootCApem"))
		rootCA, err := os.ReadFile(rootcafile)
		if err != nil {
			log.Fatalf("reading cert failed : %v", err)
		}
		if Globals.Debug {
			fmt.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n", name, rootcafile)
		}

		rootCAPool.AppendCertsFromPEM(rootCA)
		tlsconfig.RootCAs = rootCAPool
	}

	//	} else {
	//		rootCAPool := x509.NewCertPool()
	//		// rootCA, err := os.ReadFile(viper.GetString("musicd.rootCApem"))
	//		rootCA, err := os.ReadFile(rootcafile)
	//		if err != nil {
	//			log.Fatalf("reading cert failed : %v", err)
	//		}
	//		if debug {
	//			log.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n", name, rootcafile)
	//		}
	//
	//		rootCAPool.AppendCertsFromPEM(rootCA)

	//		api.Client = &http.Client{
	//			Transport: &http.Transport{
	//				TLSClientConfig: &tls.Config{
	//					RootCAs: rootCAPool,
	//				},
	//			},
	//		}
	//	}
	api.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig,
		},
	}
	// api.Debug = Globals.Debug
	//api.Verbose = Globals.Verbose
	// log.Printf("client is a: %T\n", api.Client)

	//	if Globals.Debug {
	//		log.Printf("Setting up %s API client:\n", name)
	//		log.Printf("* baseurl is: %s \n* apikey is: %s \n* authmethod is: %s \n",
	//			api.BaseUrl, api.apiKey, api.AuthMethod)
	//	}

	return &api
}

// request helper function
func (api *ApiClient) requestHelper(req *http.Request) (int, []byte, error) {

	req.Header.Add("Content-Type", "application/json")

	if api.AuthMethod == "" {
		// do not add any authentication header at all
	} else if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.apiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
	} else {
		log.Printf("Error: Client API Post: unknown auth method: %s. Aborting.\n",
			api.AuthMethod)
		return 501, []byte{}, fmt.Errorf("unknown auth method: %s", api.AuthMethod)
	}

	if api.Debug {
		log.Printf("\nrequestHelper: about to send request using auth method '%s' and key '%s'\n",
			api.AuthMethod, api.apiKey)
	}

	if api.apiKey == "" {
		log.Fatalf("api.requestHelper: Error: apikey not set.\n")
	}

	resp, err := api.Client.Do(req)

	if err != nil {
		return 501, nil, err
	}

	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
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

func (api *ApiClient) Post(endpoint string, data []byte) (int, []byte, error) {
	if api == nil {
		return 501, nil, fmt.Errorf("api client is nil")
	}

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
func (api *ApiClient) Delete(endpoint string) (int, []byte, error) {

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
func (api *ApiClient) Get(endpoint string) (int, []byte, error) {

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
func (api *ApiClient) Put(endpoint string, data []byte) (int, []byte, error) {

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

func (api *ApiClient) UrlReport(method, endpoint string, data []byte) {
	if !api.Debug {
		return
	}

	if api.UseTLS {
		fmt.Printf("API%s: apiurl: %s (using TLS)\n", method, api.BaseUrl+endpoint)
	} else {
		fmt.Printf("API%s: apiurl: %s (not using TLS)\n", method, api.BaseUrl+endpoint)
	}

	if (method == http.MethodPost) || (method == http.MethodPut) {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, data, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("API%s: posting %d bytes of data: %s\n", method, len(data), prettyJSON.String())
	}
}

func (api *ApiClient) UrlReportNG(method, fullurl string, data []byte) {
	if !api.Debug {
		return
	}

	if api.UseTLS {
		fmt.Printf("API%s: apiurl: %s (using TLS)\n", method, fullurl)
	} else {
		fmt.Printf("API%s: apiurl: %s (not using TLS)\n", method, fullurl)
	}

	if (method == http.MethodPost) || (method == http.MethodPut) {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, data, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("API%s: posting %d bytes of data: %s\n", method, len(data), prettyJSON.String())
	}
}

func (api *ApiClient) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		log.Printf("api.RequestNG: api client is nil. Returning.")
		return 501, nil, fmt.Errorf("api client is nil")
	}
	bytebuf := new(bytes.Buffer)
	err := json.NewEncoder(bytebuf).Encode(data)
	if err != nil {
		fmt.Printf("api.RequestNG: Error from json.NewEncoder: %v\n", err)
		if dieOnError {
			os.Exit(1)
		}
	}

	if api.Debug {
		log.Printf("api.RequestNG: %s %s data: %+v", method, endpoint, data)
		log.Printf("api.RequestNG: %s %s %d bytes of data: %s", method, endpoint, bytebuf.Len(), bytebuf.String())
	}

	api.UrlReport(method, endpoint, bytebuf.Bytes())

	if api.Debug {
		fmt.Printf("api.RequestNG: %s %s dieOnError: %v\n", method, endpoint, dieOnError)
	}

	baseURL, err := url.Parse(api.BaseUrl)
	if err != nil {
		if dieOnError {
			log.Fatalf("Failed to parse base URL: %v", err)
		}
		return 0, nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// Determine which addresses to try
	addressesToTry := api.Addresses
	if len(addressesToTry) == 0 {
		// If no explicit addresses, use the hostname from BaseUrl
		addressesToTry = []string{baseURL.Host}
	}

	if api.Debug {
		log.Printf("api.RequestNG: trying addresses: %v\n", addressesToTry)
	}

	var resp *http.Response

	// Try each address
	var lastErr error
	for _, addr := range addressesToTry {
		// Create the full URL with the current address
		urlCopy := *baseURL // Create a copy of the parsed URL
		urlCopy.Host = addr // addr must be in addr:port format
		fullURL := fmt.Sprintf("%s%s", urlCopy.String(), endpoint)

		if api.Debug {
			log.Printf("api.RequestNG: trying URL: %s\n", fullURL)
		}
		api.UrlReportNG(method, fullURL, bytebuf.Bytes())

		// Create the request
		req, err := http.NewRequest(method, fullURL, bytebuf)
		//	req, err := http.NewRequest(method, api.BaseUrl+endpoint, bytebuf)
		if err != nil {
			// return 501, nil, fmt.Errorf("Error from http.NewRequest: Error: %v", err)
			lastErr = err
			continue // Try next address
		}
		req.Header.Add("Content-Type", "application/json")
		if api.AuthMethod == "X-API-Key" {
			req.Header.Add("X-API-Key", api.apiKey)
		} else if api.AuthMethod == "Authorization" {
			req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
		} else if api.AuthMethod == "none" {
			// do not add any authentication header at all
		}
		resp, err = api.Client.Do(req)

		if err != nil {
			lastErr = err
			continue // Try next address
		}

		if api.Debug {
			fmt.Printf("api.RequestNG: %s %s dieOnError: %v err: %v\n", method, endpoint, dieOnError, err)
		}

		lastErr = nil // success finally
		break
	}

	if lastErr != nil {
		var msg string
		if strings.Contains(lastErr.Error(), "connection refused") {
			msg = "Connection refused. Server process probably not running."
		} else {
			msg = fmt.Sprintf("Error from API request %s: %v", method, lastErr)
		}
		if dieOnError {
			fmt.Printf("%s\n", msg)
			os.Exit(1)
		} else {
			return 501, nil, lastErr
		}
	}

	status := resp.StatusCode
	defer resp.Body.Close()
	if api.Debug {
		fmt.Printf("Status from %s: %d\n", method, status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("api.RequestNG: Error from io.ReadAll: %v", err)
		if dieOnError {
			os.Exit(1)
		}
		return 501, nil, fmt.Errorf("error from io.ReadAll: %v", err)
	}

	if api.Debug {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, buf, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		log.Printf("API%s: received %d bytes of response data: %s\n%s\n", method, len(buf), string(buf), prettyJSON.String())
		log.Printf("API%s: end of response\n", method)
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}

func (api *ApiClient) RequestNGWithContext(ctx context.Context, method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		log.Printf("api.RequestNG: api client is nil. Returning.")
		return 501, nil, fmt.Errorf("api client is nil")
	}
	bytebuf := new(bytes.Buffer)
	err := json.NewEncoder(bytebuf).Encode(data)
	if err != nil {
		fmt.Printf("api.RequestNG: Error from json.NewEncoder: %v\n", err)
		if dieOnError {
			os.Exit(1)
		}
	}

	// alternative to this:
	// Set the request body if data is provided
	//var reqBody []byte
	// if data != nil {
	// 	reqBody, err = json.Marshal(data)
	// 	if err != nil {
	// 		log.Printf("api.RequestNGWithContext: failed to marshal data: %v", err)
	// 	}
	// }
	// if dieOnError {
	// 	os.Exit(1)
	// }
	// This would be the correct way to do it, but it's not working:
	// reqBytes := bytebuf.Bytes()
	// reqBody = io.NopCloser(bytes.NewReader(reqBytes))
	// }

	api.UrlReport(method, endpoint, bytebuf.Bytes())

	if api.Debug {
		fmt.Printf("api.RequestNG: %s %s dieOnError: %v\n", method, endpoint, dieOnError)
	}

	baseURL, err := url.Parse(api.BaseUrl)
	if err != nil {
		if dieOnError {
			log.Fatalf("Failed to parse base URL: %v", err)
		}
		return 0, nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// Determine which addresses to try
	addressesToTry := api.Addresses
	if len(addressesToTry) == 0 {
		// If no explicit addresses, use the hostname from BaseUrl
		addressesToTry = []string{baseURL.Host}
	}

	if api.Debug {
		log.Printf("api.RequestNG: trying addresses: %v\n", addressesToTry)
	}

	var resp *http.Response

	// Try each address
	var lastErr error
	for _, addr := range addressesToTry {
		// Create the full URL with the current address
		urlCopy := *baseURL // Create a copy of the parsed URL
		urlCopy.Host = addr // addr must be in addr:port format
		fullURL := fmt.Sprintf("%s%s", urlCopy.String(), endpoint)

		if api.Debug {
			log.Printf("api.RequestNG: trying URL: %s\n", fullURL)
		}
		api.UrlReportNG(method, fullURL, bytebuf.Bytes())

		// Create the request with context
		// req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(bytebuf.Bytes()))
		if err != nil {
			// return 501, nil, fmt.Errorf("Error from http.NewRequest: Error: %v", err)
			lastErr = err
			continue // Try next address
		}

		// if data != nil {
		// 	req.Body = io.NopCloser(bytes.NewReader(reqBody))
		// }

		req.Header.Add("Content-Type", "application/json")
		if api.AuthMethod == "X-API-Key" {
			req.Header.Add("X-API-Key", api.apiKey)
		} else if api.AuthMethod == "Authorization" {
			req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
		} else if api.AuthMethod == "none" {
			// do not add any authentication header at all
		}
		resp, err = api.Client.Do(req)

		if err != nil {
			lastErr = err
			continue // Try next address
		}

		if api.Debug {
			fmt.Printf("api.RequestNG: %s %s dieOnError: %v err: %v\n", method, endpoint, dieOnError, err)
		}

		lastErr = nil // success finally
		break
	}

	if lastErr != nil {
		var msg string
		if strings.Contains(lastErr.Error(), "connection refused") {
			msg = "Connection refused. Server process probably not running."
		} else {
			msg = fmt.Sprintf("Error from API request %s: %v", method, lastErr)
		}
		if dieOnError {
			fmt.Printf("%s\n", msg)
			os.Exit(1)
		} else {
			return 501, nil, lastErr
		}
	}

	status := resp.StatusCode
	defer resp.Body.Close()
	if api.Debug {
		fmt.Printf("Status from %s: %d\n", method, status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return 500, nil, fmt.Errorf("error reading response body: %v", err)
	}

	if api.Debug {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, buf, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		log.Printf("API%s: received %d bytes of response data: %s\n%s\n", method, len(buf), string(buf), prettyJSON.String())
		log.Printf("API%s: end of response\n", method)
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}
