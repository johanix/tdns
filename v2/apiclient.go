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
			lgApi.Error("reading cert failed", "err", err)
			os.Exit(1)
		}
		lgApi.Debug("creating API client with root CAs", "name", name, "rootcafile", rootcafile)

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

	if api.AuthMethod == "" || api.AuthMethod == "none" {
		// no auth needed
	} else if api.AuthMethod == "X-API-Key" {
		if api.apiKey == "" {
			return 0, nil, fmt.Errorf("X-API-Key auth method requires apiKey to be set")
		}
		req.Header.Add("X-API-Key", api.apiKey)
	} else if api.AuthMethod == "Authorization" {
		if api.apiKey == "" {
			return 0, nil, fmt.Errorf("authorization auth method requires apiKey to be set")
		}
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
	} else {
		lgApi.Error("unknown auth method", "method", api.AuthMethod)
		return 501, []byte{}, fmt.Errorf("unknown auth method: %s", api.AuthMethod)
	}

	lgApi.Debug("sending request", "authMethod", api.AuthMethod)

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
			lgApi.Debug("JSON parse error", "err", error)
		}
		lgApi.Debug("received response data", "bytes", len(buf), "data", prettyJSON.String())
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
			lgApi.Debug("JSON parse error", "err", error)
		}
		lgApi.Debug("posting data", "url", api.BaseUrl+endpoint, "bytes", len(data), "data", prettyJSON.String())
	}

	req, err := http.NewRequest(http.MethodPost, api.BaseUrl+endpoint,
		bytes.NewBuffer(data))
	if err != nil {
		lgApi.Error("http.NewRequest failed", "err", err)
		os.Exit(1)
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
		lgApi.Error("http.NewRequest failed", "err", err)
		os.Exit(1)
	}
	return api.requestHelper(req)
}

// api Get (not tested)
func (api *ApiClient) Get(endpoint string) (int, []byte, error) {

	if api.Debug {
		lgApi.Debug("GET request", "url", api.BaseUrl+endpoint)
	}

	req, err := http.NewRequest(http.MethodGet, api.BaseUrl+endpoint, nil)
	if err != nil {
		lgApi.Error("http.NewRequest failed", "err", err)
		os.Exit(1)
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
		lgApi.Error("http.NewRequest failed", "err", err)
		os.Exit(1)
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
			lgApi.Debug("JSON parse error", "err", error)
		}
		lgApi.Debug("posting data", "method", method, "bytes", len(data), "data", prettyJSON.String())
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
			lgApi.Debug("JSON parse error", "err", error)
		}
		lgApi.Debug("posting data", "method", method, "bytes", len(data), "data", prettyJSON.String())
	}
}

func (api *ApiClient) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		lgApi.Warn("api client is nil")
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

	lgApi.Debug("RequestNG preparing request", "method", method, "endpoint", endpoint, "bytes", bytebuf.Len())

	api.UrlReport(method, endpoint, bytebuf.Bytes())

	if api.Debug {
		fmt.Printf("api.RequestNG: %s %s dieOnError: %v\n", method, endpoint, dieOnError)
	}

	baseURL, err := url.Parse(api.BaseUrl)
	if err != nil {
		if dieOnError {
			lgApi.Error("failed to parse base URL", "err", err)
			os.Exit(1)
		}
		return 0, nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// Determine which addresses to try
	addressesToTry := api.Addresses
	if len(addressesToTry) == 0 {
		// If no explicit addresses, use the hostname from BaseUrl
		addressesToTry = []string{baseURL.Host}
	}

	lgApi.Debug("RequestNG trying addresses", "addresses", addressesToTry)

	bodyBytes := bytebuf.Bytes()

	var resp *http.Response

	// Try each address
	var lastErr error
	for _, addr := range addressesToTry {
		// Create the full URL with the current address
		urlCopy := *baseURL // Create a copy of the parsed URL
		urlCopy.Host = addr // addr must be in addr:port format
		fullURL := fmt.Sprintf("%s%s", urlCopy.String(), endpoint)

		lgApi.Debug("RequestNG trying URL", "url", fullURL)
		api.UrlReportNG(method, fullURL, bodyBytes)

		// Create the request with a fresh reader for each attempt
		req, err := http.NewRequest(method, fullURL, bytes.NewReader(bodyBytes))
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
			// Show which URLs were tried for better debugging
			msg = fmt.Sprintf("Connection refused. Server process probably not running.\nTried addresses: %v\nBase URL: %s%s", addressesToTry, api.BaseUrl, endpoint)
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
		if err := json.Indent(&prettyJSON, buf, "", "  "); err != nil {
			lgApi.Debug("response (not JSON)", "method", method, "endpoint", endpoint, "bytes", len(buf), "data", string(buf))
		} else {
			lgApi.Debug("response", "method", method, "endpoint", endpoint, "bytes", len(buf), "data", prettyJSON.String())
		}
	}

	// Report non-2xx status codes clearly
	if status < 200 || status >= 300 {
		body := strings.TrimSpace(string(buf))
		msg := fmt.Sprintf("API %s %s%s returned HTTP %d: %s", method, api.BaseUrl, endpoint, status, body)
		if dieOnError {
			fmt.Println(msg)
			os.Exit(1)
		}
		return status, buf, fmt.Errorf("%s", msg)
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}

func (api *ApiClient) RequestNGWithContext(ctx context.Context, method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	if api == nil {
		lgApi.Warn("api client is nil")
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
			lgApi.Error("failed to parse base URL", "err", err)
			os.Exit(1)
		}
		return 0, nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// Determine which addresses to try
	addressesToTry := api.Addresses
	if len(addressesToTry) == 0 {
		// If no explicit addresses, use the hostname from BaseUrl
		addressesToTry = []string{baseURL.Host}
	}

	lgApi.Debug("RequestNG trying addresses", "addresses", addressesToTry)

	var resp *http.Response

	// Try each address
	var lastErr error
	for _, addr := range addressesToTry {
		// Create the full URL with the current address
		urlCopy := *baseURL // Create a copy of the parsed URL
		urlCopy.Host = addr // addr must be in addr:port format
		fullURL := fmt.Sprintf("%s%s", urlCopy.String(), endpoint)

		lgApi.Debug("RequestNG trying URL", "url", fullURL)
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
			// Show which URLs were tried for better debugging
			msg = fmt.Sprintf("Connection refused. Server process probably not running.\nTried addresses: %v\nBase URL: %s%s", addressesToTry, api.BaseUrl, endpoint)
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
		fmt.Printf("api.RequestNGWithContext: Error from io.ReadAll: %v", err)
		if dieOnError {
			os.Exit(1)
		}
		return 501, nil, fmt.Errorf("error from io.ReadAll: %v", err)
	}

	if api.Debug {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, buf, "", "  "); err != nil {
			lgApi.Debug("response (not JSON)", "method", method, "endpoint", endpoint, "bytes", len(buf), "data", string(buf))
		} else {
			lgApi.Debug("response", "method", method, "endpoint", endpoint, "bytes", len(buf), "data", prettyJSON.String())
		}
	}

	// Report non-2xx status codes clearly
	if status < 200 || status >= 300 {
		body := strings.TrimSpace(string(buf))
		msg := fmt.Sprintf("API %s %s%s returned HTTP %d: %s", method, api.BaseUrl, endpoint, status, body)
		if dieOnError {
			fmt.Println(msg)
			os.Exit(1)
		}
		return status, buf, fmt.Errorf("%s", msg)
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}
