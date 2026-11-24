/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The callers: an application's client, as a provisioning daemon builds it
 * (tdns.NewClientWithOptions, its own certificate, the daemon's pin), the
 * operator's certificate, the API key, the local socket for read-only audits,
 * and tdns-ncli for the operator's steps.
 */
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// client is one caller of the management API.
type client struct {
	who string
	api *tdns.ApiClient
	tr  *transcript
}

// newCertClient is the client an application builds: TCP, TLS with its own
// certificate, and the daemon verified by its pin. No API key.
func newCertClient(who, baseURL, certFile, keyFile, pin string, tr *transcript) (*client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", who, err)
	}
	api := tdns.NewClientWithOptions(who, baseURL, tdns.ClientOptions{
		AuthMethod: "certificate",
		ClientCert: &cert,
		Pins:       []string{pin},
	})
	api.Client.Timeout = 30 * time.Second
	return &client{who: who, api: api, tr: tr}, nil
}

// newKeyClient is a caller on the API key, over the same pinned TLS.
func newKeyClient(baseURL, apikey, pin string, tr *transcript) *client {
	api := tdns.NewClientWithOptions("apikey", baseURL, tdns.ClientOptions{
		AuthMethod: "X-API-Key",
		ApiKey:     apikey,
		Pins:       []string{pin},
	})
	api.Client.Timeout = 30 * time.Second
	return &client{who: "apikey", api: api, tr: tr}
}

// newSocketClient is the daemon's local admin socket. The checks use it only
// to read state, as an independent view of what a request did; the
// operator's steps go through tdns-ncli.
func newSocketClient(socket, daemonConfig string, tr *transcript) *client {
	api := tdns.NewClientWithOptions("audit", "unix://"+socket, tdns.ClientOptions{
		AuthMethod:       "none",
		ExpectConfigFile: daemonConfig,
	})
	api.Client.Timeout = 30 * time.Second
	return &client{who: "audit", api: api, tr: tr}
}

// reply is what the daemon answered.
type reply struct {
	HTTP int
	Body []byte
	Err  error // a failed exchange, or a plain-text refusal (*tdns.ApiRefusal)
}

// outcome is a reply as a check reads it.
type outcome struct {
	OK   bool
	HTTP int
	Msg  string // the daemon's error when not OK, else its message
	Raw  []byte
}

func (c *client) post(endpoint string, req, resp any) reply {
	body, err := json.Marshal(req)
	if err != nil {
		return reply{Err: err}
	}
	status, buf, err := c.api.Post(endpoint, body)
	r := reply{HTTP: status, Body: buf, Err: err}
	if err == nil && resp != nil && len(bytes.TrimSpace(buf)) > 0 {
		if derr := json.Unmarshal(buf, resp); derr != nil {
			r.Err = fmt.Errorf("the reply does not decode: %v: %s", derr, oneLine(string(buf), 200))
		}
	}
	c.tr.request(c.who, endpoint, body, r)
	return r
}

// get is a GET route (the rollover reads): no body, the zone in the query.
func (c *client) get(endpoint string) outcome {
	status, buf, err := c.api.Get(endpoint)
	r := reply{HTTP: status, Body: buf, Err: err}
	c.tr.request(c.who, "GET "+endpoint, nil, r)
	return judge(r, false, "", oneLine(string(buf), 120))
}

// postRaw is a POST whose refusal is plain text (the rollover writes).
func (c *client) postRaw(endpoint string, req any) outcome {
	r := c.post(endpoint, req, nil)
	return judge(r, false, "", oneLine(string(r.Body), 120))
}

// judge makes an outcome of a reply and the JSON verdict the handler gave.
func judge(r reply, isErr bool, errMsg, msg string) outcome {
	if r.Err != nil {
		var ref *tdns.ApiRefusal
		if errors.As(r.Err, &ref) {
			return outcome{HTTP: ref.Status, Msg: ref.Msg, Raw: r.Body}
		}
		return outcome{HTTP: r.HTTP, Msg: r.Err.Error(), Raw: r.Body}
	}
	if r.HTTP < 200 || r.HTTP >= 300 || isErr {
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d, no error text: %s", r.HTTP, oneLine(string(r.Body), 200))
		}
		return outcome{HTTP: r.HTTP, Msg: errMsg, Raw: r.Body}
	}
	return outcome{OK: true, HTTP: r.HTTP, Msg: msg, Raw: r.Body}
}

func (c *client) ping() (tdns.PingResponse, outcome) {
	var resp tdns.PingResponse
	r := c.post("/ping", tdns.PingPost{Msg: "appowner", Pings: 1}, &resp)
	return resp, judge(r, false, "", resp.Auth)
}

func (c *client) zone(zp tdns.ZonePost) (tdns.ZoneResponse, outcome) {
	var resp tdns.ZoneResponse
	r := c.post("/zone", zp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) keystore(kp tdns.KeystorePost) (tdns.KeystoreResponse, outcome) {
	var resp tdns.KeystoreResponse
	r := c.post("/keystore", kp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) truststore(tp tdns.TruststorePost) (tdns.TruststoreResponse, outcome) {
	var resp tdns.TruststoreResponse
	r := c.post("/truststore", tp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) catalog(cp tdns.CatalogPost) (tdns.CatalogResponse, outcome) {
	var resp tdns.CatalogResponse
	r := c.post("/catalog", cp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) config(cp tdns.ConfigPost) (tdns.ConfigResponse, outcome) {
	var resp tdns.ConfigResponse
	r := c.post("/config", cp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) delegation(dp tdns.DelegationPost) (tdns.DelegationResponse, outcome) {
	var resp tdns.DelegationResponse
	r := c.post("/delegation", dp, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

func (c *client) scannerPoll(cmd string) (tdns.ScannerPollResponse, outcome) {
	var resp tdns.ScannerPollResponse
	r := c.post("/scanner/poll", tdns.ScannerPollPost{Command: cmd}, &resp)
	return resp, judge(r, false, "", resp.Msg)
}

func (c *client) imr(cmd string) (tdns.ImrMgmtResponse, outcome) {
	var resp tdns.ImrMgmtResponse
	r := c.post("/imr", tdns.ImrMgmtPost{Command: cmd}, &resp)
	return resp, judge(r, resp.Error, resp.ErrorMsg, resp.Msg)
}

// ncli runs tdns-ncli against the daemon's entry in its CLI config, which
// reaches the daemon over its local admin socket: the operator's steps.
type ncli struct {
	bin, cfg string
	tr       *transcript
}

// run runs `tdns-ncli --config CFG args...` and returns its combined output.
func (n ncli) run(args ...string) (string, error) {
	full := append([]string{"--config", n.cfg}, args...)
	cmd := exec.Command(n.bin, full...)
	out, err := cmd.CombinedOutput()
	n.tr.command(filepath.Base(n.bin), full, string(out), err)
	return string(out), err
}

// transcript keeps every request, reply and command, for a FAIL to be read
// in full.
type transcript struct {
	mu sync.Mutex
	f  *os.File
}

func openTranscript(path string) (*transcript, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &transcript{f: f}, nil
}

func (t *transcript) close() {
	if t != nil && t.f != nil {
		t.f.Close()
	}
}

func (t *transcript) printf(format string, args ...any) {
	if t == nil || t.f == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.f, format, args...)
}

func (t *transcript) request(who, endpoint string, body []byte, r reply) {
	errs := ""
	if r.Err != nil {
		errs = " err=" + r.Err.Error()
	}
	t.printf("--> %s POST %s %s\n<-- HTTP %d%s %s\n", who, endpoint, body, r.HTTP, errs, bytes.TrimSpace(r.Body))
}

func (t *transcript) command(bin string, args []string, out string, err error) {
	t.printf("$ %s %s\n%s(exit: %v)\n", bin, strings.Join(args, " "), out, err)
}

func (t *transcript) note(format string, args ...any) {
	t.printf("## "+format+"\n", args...)
}

// oneLine is s on one line, cut at n bytes.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
