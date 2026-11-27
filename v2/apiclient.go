/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

// Client side API client calls

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"

	"fmt"
	"net/http"
	"net/url"
)

// ClientOptions is how a management API client verifies the daemon and
// authenticates itself. Over TCP that is TLS with the daemon's certificate
// pins (Pins) and the operator's client certificate (ClientCert); on the
// daemon's local admin socket (a unix:///path base URL) it is nothing: the
// socket's file permissions are the authentication. There is no API key.
type ClientOptions struct {
	// Pins are the daemon's SPKI SHA-256 pins: its leaf certificate's must
	// be one of these (no name, no expiry check; the pin is the trust
	// anchor). An https client without pins refuses every connection.
	Pins []string
	// PinFix, when set, is added to the refusal of a daemon whose pin is
	// not one of Pins: how the caller's user takes the daemon's new pins.
	PinFix string
	// ClientCert is presented on the TLS connection.
	ClientCert *tls.Certificate
	// ExpectConfigFile, for a local socket client, is the config file the
	// daemon must run. Every request carries it (ExpectConfigFileHeader), and
	// a daemon that runs another config refuses the request before acting
	// on it: the check is part of the very request that does the work, so a
	// daemon that took the socket after an earlier check cannot run it.
	ExpectConfigFile string
}

// ExpectConfigFileHeader carries ClientOptions.ExpectConfigFile. A daemon
// refuses a request whose header names another config file than its own
// (412), whatever the request.
const ExpectConfigFileHeader = "X-Tdns-Config-File"

// expectConfigTransport adds the ExpectConfigFileHeader to every request.
type expectConfigTransport struct {
	base http.RoundTripper
	file string
}

func (t expectConfigTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(ExpectConfigFileHeader, t.file)
	return t.base.RoundTrip(r)
}

// NewClientWithOptions builds a management API client for baseurl.
func NewClientWithOptions(name, baseurl string, o ClientOptions) *ApiClient {
	api := ApiClient{
		Name:    name,
		BaseUrl: baseurl,
	}

	// unix:///path is the daemon's local admin socket. Every request is
	// dialled to that socket whatever the URL's host says, so the URL the rest
	// of this client builds is plain http on a fixed host. No TLS, and no
	// credential: the daemon authenticates the socket by file permissions.
	// A unix:// URL whose path is not absolute is still a socket URL: it must
	// not fall through to the TCP client, so every request fails, saying why.
	if strings.HasPrefix(baseurl, "unix://") {
		path, ok := unixSocketPath(baseurl)
		api.Socket = path
		api.BaseUrl = "http://localhost/api/v1"
		var tr http.RoundTripper = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if !ok {
					return nil, fmt.Errorf("baseurl %s: a local socket is unix:///absolute/path", baseurl)
				}
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}
		if o.ExpectConfigFile != "" {
			// Absolute, from this process's working directory: the daemon
			// has another one, and compares with its own absolute path.
			tr = expectConfigTransport{base: tr, file: absConfigFile(o.ExpectConfigFile)}
		}
		api.Client = &http.Client{Transport: tr}
		return &api
	}

	// TLS 1.3, as the daemon serves it. Pinning replaces chain building:
	// InsecureSkipVerify turns off the default verification and
	// VerifyConnection, which still runs (on resumed connections too), is
	// the gate. With no pins it refuses every daemon.
	pins, fix := append([]string(nil), o.Pins...), o.PinFix
	tlsconfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(pins) == 0 {
				return fmt.Errorf("no certificate pin for the daemon, so it cannot be verified")
			}
			err := verifyServerPin(cs, pins)
			if err != nil && fix != "" {
				err = fmt.Errorf("%w; fix: %s", err, fix)
			}
			return err
		},
	}
	if o.ClientCert != nil {
		tlsconfig.Certificates = []tls.Certificate{*o.ClientCert}
	}
	api.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig,
		},
	}
	return &api
}

// unixSocketPath returns the socket path of a unix:///path base URL.
func unixSocketPath(baseurl string) (string, bool) {
	const prefix = "unix://"
	if !strings.HasPrefix(baseurl, prefix) {
		return "", false
	}
	p := strings.TrimPrefix(baseurl, prefix)
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}

// verifyServerPin is the VerifyConnection gate for a pinned daemon: the leaf
// certificate's SPKI SHA-256 must match one of pins.
func verifyServerPin(cs tls.ConnectionState, pins []string) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("the daemon presented no certificate")
	}
	got := SPKISHA256(cs.PeerCertificates[0])
	for _, want := range pins {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("the daemon's certificate has pin %s, which is not one of the %d pinned for this entry (the daemon's certificate changed, or this is not the daemon you meant)", got, len(pins))
}

// requestURLs are the URLs a request to endpoint is sent to, in order, as
// RequestNG tries them: api.BaseUrl with each of api.Addresses as its host,
// or api.BaseUrl alone when there are none.
func (api *ApiClient) requestURLs(endpoint string) ([]string, error) {
	if len(api.Addresses) == 0 {
		return []string{api.BaseUrl + endpoint}, nil
	}
	base, err := url.Parse(api.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}
	urls := make([]string, 0, len(api.Addresses))
	for _, addr := range api.Addresses {
		u := *base
		u.Host = addr // addr:port, as for RequestNG
		urls = append(urls, u.String()+endpoint)
	}
	return urls, nil
}

// send is the request method endpoint with body (nil for none), sent to each
// of requestURLs in turn until one answers, as RequestNG does: an address
// that cannot be reached is skipped, and the first reply, whatever its
// status, is the answer (requestHelper). When no address answers, the error
// is the last one's, naming every address tried when there were several.
func (api *ApiClient) send(method, endpoint string, body []byte) (int, []byte, error) {
	if api == nil {
		return 501, nil, fmt.Errorf("api client is nil")
	}
	urls, err := api.requestURLs(endpoint)
	if err != nil {
		return 0, nil, err
	}
	var lastErr error
	for _, u := range urls {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, u, rd)
		if err != nil {
			lgApi.Error("http.NewRequest failed", "url", u, "err", err)
			lastErr = err
			continue
		}
		status, buf, unreached, err := api.requestHelper(req)
		if !unreached {
			return status, buf, err
		}
		lgApi.Debug("no answer, trying the next address", "url", u, "err", err)
		lastErr = err
	}
	if len(urls) > 1 {
		return 501, nil, fmt.Errorf("%w (tried %s)", lastErr, strings.Join(api.Addresses, ", "))
	}
	return 501, nil, lastErr
}

// requestHelper sends req and reads the reply. unreached is set when the
// request got no reply (Client.Do failed), so that send tries the next
// address; an error with unreached false is the daemon's answer, or a
// setting of this client that no address would change.
func (api *ApiClient) requestHelper(req *http.Request) (status int, body []byte, unreached bool, err error) {

	req.Header.Add("Content-Type", "application/json")

	resp, err := api.Client.Do(req)

	if err != nil {
		return 501, nil, true, err
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

	// A refusal made before any handler runs (the access check's 401, 403,
	// 413 or 503) has a plain-text body, not the JSON the callers decode.
	// Return it as an error, so that the operator sees the daemon's own
	// words instead of a JSON parse error. A non-2xx reply with a JSON body
	// is a handler's own and goes back as before.
	if err == nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) && !json.Valid(buf) {
		return resp.StatusCode, buf, false, plainHTTPError(resp.StatusCode, buf)
	}

	return resp.StatusCode, buf, false, err
}

// ApiRefusal is a non-2xx reply whose body is plain text: a refusal made
// before any handler ran (the access check), or a handler's own plain-text
// error. A client can tell it from a failed exchange and print the daemon's
// words as they are.
type ApiRefusal struct {
	Status int
	Msg    string
}

func (e *ApiRefusal) Error() string {
	return fmt.Sprintf("HTTP %d from the daemon: %s", e.Status, e.Msg)
}

// Report is the refusal worded for a caller that prints it after its own
// "Error from <daemon>: " prefix: "refused (HTTP 403):", then the daemon's
// words (ErrorReport). A CLI that names the daemon itself uses ReportFrom.
func (e *ApiRefusal) Report() string {
	verdict := fmt.Sprintf("refused (HTTP %d):", e.Status)
	if e.Status != http.StatusForbidden {
		verdict = fmt.Sprintf("HTTP %d from the daemon:", e.Status)
	}
	return ErrorReport(verdict, e.msg())
}

// ReportFrom is the refusal as a CLI prints it, from the daemon called
// daemon: one verdict that names it, "Refused by tdns-auth (HTTP 403):"
// ("Error from tdns-auth (HTTP 500):" for another status), then the
// daemon's words (ErrorReport).
func (e *ApiRefusal) ReportFrom(daemon string) string {
	if daemon == "" {
		daemon = "the daemon"
	}
	verdict := fmt.Sprintf("Refused by %s (HTTP %d):", daemon, e.Status)
	if e.Status != http.StatusForbidden {
		verdict = fmt.Sprintf("Error from %s (HTTP %d):", daemon, e.Status)
	}
	return ErrorReport(verdict, e.msg())
}

func (e *ApiRefusal) msg() string {
	if strings.TrimSpace(e.Msg) == "" {
		return http.StatusText(e.Status)
	}
	return e.Msg
}

// ErrorReportWidth is the widest line ErrorReport wraps to.
const ErrorReportWidth = 72

// ErrorReport is a daemon's error as a CLI prints it, verdict first: the
// verdict on a line of its own, then msg, indented two spaces and wrapped
// within ErrorReportWidth. Each of msg's own lines stays a line, with its
// own indent on top of the two, so that a hint the daemon puts on an
// indented line of its own (appRefusal) stays one; a wrapped line goes on
// at its own indent. A word wider than its line (a long zone name) is left
// whole.
func ErrorReport(verdict, msg string) string {
	lines := []string{verdict}
	for _, para := range strings.Split(msg, "\n") {
		text := strings.TrimLeft(para, " ")
		indent := "  " + para[:len(para)-len(text)]
		line := ""
		for _, w := range strings.Fields(text) {
			switch {
			case line == "":
				line = w
			case len(indent)+len(line)+1+len(w) > ErrorReportWidth:
				lines = append(lines, indent+line)
				line = w
			default:
				line += " " + w
			}
		}
		if line != "" {
			lines = append(lines, indent+line)
		}
	}
	return strings.Join(lines, "\n")
}

// plainHTTPError is the error for a non-2xx reply whose body is plain text.
func plainHTTPError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(status)
	}
	return &ApiRefusal{Status: status, Msg: msg}
}

// Post sends data to endpoint and returns the reply's status and body, a
// non-2xx one included; a plain-text non-2xx reply is also an ApiRefusal.
// Like RequestNG it tries each of api.Addresses in turn (send).
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

	return api.send(http.MethodPost, endpoint, data)
}

// api Delete (not tested)
func (api *ApiClient) Delete(endpoint string) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Delete: posting to URL '%s'\n",
			api.BaseUrl+endpoint)
	}

	return api.send(http.MethodDelete, endpoint, nil)
}

// api Get (not tested)
func (api *ApiClient) Get(endpoint string) (int, []byte, error) {

	if api.Debug {
		lgApi.Debug("GET request", "url", api.BaseUrl+endpoint)
	}

	return api.send(http.MethodGet, endpoint, nil)
}

// api Put
func (api *ApiClient) Put(endpoint string, data []byte) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Put: posting to URL '%s' %d bytes of data: %v\n",
			api.BaseUrl+endpoint, len(data), string(data))
	}

	return api.send(http.MethodPut, endpoint, data)
}

func (api *ApiClient) UrlReport(method, endpoint string, data []byte) {
	if !api.Debug {
		return
	}

	fmt.Printf("API%s: apiurl: %s\n", method, api.BaseUrl+endpoint)

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

	fmt.Printf("API%s: apiurl: %s\n", method, fullurl)

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
			if api.Socket != "" {
				msg = fmt.Sprintf("Cannot reach the local admin socket %s: %v\n(daemon not running, or the socket is not yours to open)", api.Socket, lastErr)
			}
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
		// A plain-text reply is the daemon's own sentence (a refusal by
		// the access check, or a handler's error): printed once, as such,
		// not after the URL.
		if dieOnError && !json.Valid(buf) {
			fmt.Println((&ApiRefusal{Status: status, Msg: body}).ReportFrom(api.Name))
			os.Exit(1)
		}
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
			if api.Socket != "" {
				msg = fmt.Sprintf("Cannot reach the local admin socket %s: %v\n(daemon not running, or the socket is not yours to open)", api.Socket, lastErr)
			}
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
		// A plain-text reply is the daemon's own sentence (a refusal by
		// the access check, or a handler's error): printed once, as such,
		// not after the URL.
		if dieOnError && !json.Valid(buf) {
			fmt.Println((&ApiRefusal{Status: status, Msg: body}).ReportFrom(api.Name))
			os.Exit(1)
		}
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
