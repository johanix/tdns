package tdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// The access check is on the root router, so it covers routes added after the
// builder returns: tdns-mp adds routes on a second "/api/v1" subrouter
// (SetupMPAgentRoutes and friends), and RegisterAPIRoute callbacks get the
// root router. With the check on the builder's own subrouter, both kinds
// answered unchecked.
func TestAccessCheckCoversRoutesAddedLater(t *testing.T) {
	builders := map[string]func(*Config, context.Context) (*mux.Router, error){
		"SetupAPIRouter":       (*Config).SetupAPIRouter,
		"SetupSimpleAPIRouter": (*Config).SetupSimpleAPIRouter,
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			conf := &Config{}
			conf.Internal.ServerErrors = NewServerErrorRegistry()
			rtr, err := build(conf, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			reached := map[string]bool{}
			handler := func(path string) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) { reached[path] = true }
			}
			// As tdns-mp does it: another /api/v1 subrouter on the same root.
			rtr.PathPrefix("/api/v1").Subrouter().HandleFunc("/later-subrouter", handler("/api/v1/later-subrouter")).Methods("POST")
			// As a RegisterAPIRoute callback can: straight on the root router.
			rtr.HandleFunc("/api/v1/later-root", handler("/api/v1/later-root")).Methods("POST")

			for _, path := range []string{"/api/v1/later-subrouter", "/api/v1/later-root", "/api/v1/ping"} {
				// Over TCP, with no client certificate (and an API key
				// header, which means nothing now): refused, unreached.
				req := httptest.NewRequest(http.MethodPost, path, nil)
				req.Header.Set("X-API-Key", "a-key")
				rec := httptest.NewRecorder()
				rtr.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden || reached[path] {
					t.Errorf("%s over TCP without a certificate: status %d, reached %v; want 403, unreached", path, rec.Code, reached[path])
				}
				// On the local socket: admin, reached.
				req = httptest.NewRequest(http.MethodPost, path, nil)
				req = req.WithContext(context.WithValue(req.Context(), localSocketKey{}, true))
				rec = httptest.NewRecorder()
				rtr.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK || (path != "/api/v1/ping" && !reached[path]) {
					t.Errorf("%s on the socket: status %d, reached %v; want 200", path, rec.Code, reached[path])
				}
			}
		})
	}
}
