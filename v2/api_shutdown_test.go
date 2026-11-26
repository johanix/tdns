package tdns

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// At shutdown, a TCP API server that stopped by itself, and so is no longer
// listed as listening (apiTCPServeFailed), is not shut down again: only the
// servers still listed are.
func TestApiShutdownSkipsAServerThatStopped(t *testing.T) {
	var mu sync.Mutex
	var shut []string
	server := func(addr string) apiTCPServer {
		srv := &http.Server{Addr: addr}
		srv.RegisterOnShutdown(func() {
			mu.Lock()
			shut = append(shut, addr)
			mu.Unlock()
		})
		return apiTCPServer{srv: srv}
	}
	stopped, live := server("127.0.0.1:1"), server("127.0.0.1:2")
	apiTCPServers.Lock()
	savedSrvs, savedFailed := apiTCPServers.srvs, apiTCPServers.failed
	apiTCPServers.srvs = []apiTCPServer{stopped, live}
	apiTCPServers.Unlock()
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs, apiTCPServers.failed = savedSrvs, savedFailed
		apiTCPServers.Unlock()
	})

	apiTCPServeFailed(stopped, errors.New("tls: failed to find any PEM data"))
	shutdownApiTCPServers([]apiTCPServer{stopped, live})
	// The shutdown hooks run in goroutines of their own.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(shut)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(shut) != 1 || shut[0] != "127.0.0.1:2" {
		t.Errorf("shut down %v, want only the server still listed (127.0.0.1:2)", shut)
	}
}
