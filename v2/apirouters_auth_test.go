package tdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// Routes that callers add to the router after the builder returns must be
// behind the same key check as the builder's own. tdns-mp adds its management
// routes on a second "/api/v1" subrouter (SetupMPAgentRoutes and friends), and
// RegisterAPIRoute callbacks get the root router. With the check on the
// builder's own subrouter, both kinds answered without a key.
func TestApiKeyCoversRoutesAddedLater(t *testing.T) {
	const key = "the-api-key"
	builders := map[string]func(*Config, context.Context) (*mux.Router, error){
		"SetupAPIRouter":       (*Config).SetupAPIRouter,
		"SetupSimpleAPIRouter": (*Config).SetupSimpleAPIRouter,
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			conf := &Config{}
			conf.ApiServer.ApiKey = key
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

			for _, path := range []string{"/api/v1/later-subrouter", "/api/v1/later-root"} {
				for _, tc := range []struct {
					sendKey string
					want    int
				}{
					{sendKey: "", want: http.StatusForbidden},
					{sendKey: "wrong", want: http.StatusForbidden},
					{sendKey: key, want: http.StatusOK},
				} {
					reached[path] = false
					req := httptest.NewRequest(http.MethodPost, path, nil)
					if tc.sendKey != "" {
						req.Header.Set("X-API-Key", tc.sendKey)
					}
					rec := httptest.NewRecorder()
					rtr.ServeHTTP(rec, req)
					if rec.Code != tc.want {
						t.Errorf("%s with key %q: status %d, want %d", path, tc.sendKey, rec.Code, tc.want)
					}
					if reached[path] != (tc.want == http.StatusOK) {
						t.Errorf("%s with key %q: handler reached = %v", path, tc.sendKey, reached[path])
					}
				}
			}

			// The builder's own routes are still checked as before.
			rec := httptest.NewRecorder()
			rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("/api/v1/ping without a key: status %d, want 403", rec.Code)
			}
		})
	}
}
