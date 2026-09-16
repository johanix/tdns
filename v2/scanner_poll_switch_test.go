package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The runtime switch for polling (POST /scanner/poll): it overrides
// scanner.poll.enabled until follow-config, and switching off stops a round
// from starting more children.

func TestPollSwitchOverridesTheConfigUntilFollowConfig(t *testing.T) {
	withLiveConfig(t, &RuntimeConfig{ScannerPollEnabled: false})
	sc := NewScanner(nil, false, false)

	if sc.pollConf().Enabled {
		t.Fatal("polling is on with the config off and the switch unset")
	}
	sc.setPollSwitch(pollSwitchOn)
	if !sc.pollConf().Enabled {
		t.Fatal("switched on, but polling is off")
	}

	liveConfig.Store(&RuntimeConfig{ScannerPollEnabled: true})
	sc.setPollSwitch(pollSwitchOff)
	if sc.pollConf().Enabled {
		t.Fatal("switched off, but polling is on with the config on")
	}

	sc.setPollSwitch(pollSwitchConfig)
	if !sc.pollConf().Enabled {
		t.Fatal("after follow-config, polling does not follow the config")
	}
}

// Switching polling on where the config already polls changes no setting, but
// the switch is part of what the settings line reports, so it is logged again.
func TestPollSettingsAreLoggedAgainWhenOnlyTheSwitchChanges(t *testing.T) {
	withLiveConfig(t, &RuntimeConfig{ScannerPollEnabled: true})
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	sc := NewScanner(nil, false, false)
	settingsLines := func() int { return strings.Count(buf.String(), "ScannerEngine: poll settings") }

	sc.notePollConf(sc.pollConf())
	sc.notePollConf(sc.pollConf())
	if got := settingsLines(); got != 1 {
		t.Fatalf("%d settings line(s) before any change, want 1", got)
	}

	sc.setPollSwitch(pollSwitchOn)
	sc.notePollConf(sc.pollConf())
	if got := settingsLines(); got != 2 {
		t.Fatalf("%d settings line(s) after switching on; want the switch logged", got)
	}
	if !strings.Contains(buf.String(), "switch=on") {
		t.Errorf("the settings line does not say switch=on:\n%s", buf.String())
	}
}

func postScannerPoll(t *testing.T, conf *Config, body string) (int, ScannerPollResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	APIscannerPoll(conf)(rec, httptest.NewRequest(http.MethodPost, "/scanner/poll", bytes.NewBufferString(body)))
	var resp ScannerPollResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding the response: %v", err)
		}
	}
	return rec.Code, resp
}

func TestAPIscannerPoll(t *testing.T) {
	withLiveConfig(t, &RuntimeConfig{ScannerPollEnabled: false})
	conf := &Config{}
	if code, _ := postScannerPoll(t, conf, `{"command":"status"}`); code != http.StatusServiceUnavailable {
		t.Errorf("no scanner: status %d, want 503", code)
	}

	sc := NewScanner(nil, false, false)
	conf.Internal.PublishScanner(sc)

	if code, resp := postScannerPoll(t, conf, `{"command":"on"}`); code != http.StatusOK || !resp.Enabled || resp.Msg == "" {
		t.Errorf("on: status %d, %+v", code, resp)
	}
	if !sc.pollConf().Enabled {
		t.Error("the API switched polling on, but the scanner does not poll")
	}
	for _, body := range []string{`{"command":"status"}`, ``} {
		if code, resp := postScannerPoll(t, conf, body); code != http.StatusOK || !resp.Enabled || resp.Msg != "" {
			t.Errorf("status (body %q): status %d, %+v", body, code, resp)
		}
	}
	if code, resp := postScannerPoll(t, conf, `{"command":"off"}`); code != http.StatusOK || resp.Enabled {
		t.Errorf("off: status %d, %+v", code, resp)
	}
	// The config says off, so following it again leaves polling off.
	if code, resp := postScannerPoll(t, conf, `{"command":"follow-config"}`); code != http.StatusOK || resp.Enabled || sc.pollSwitch() != pollSwitchConfig {
		t.Errorf("follow-config: status %d, %+v, switch %s", code, resp, sc.pollSwitch())
	}
	for _, body := range []string{`{"command":"pause"}`, `{"command":"reset"}`, `{`} {
		if code, _ := postScannerPoll(t, conf, body); code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, code)
		}
	}
}

func TestPollSwitchedOffStartsNoMoreChildren(t *testing.T) {
	const child = "switched.example."
	zd, _ := pollParent(t, child, true)
	n := pollNet(t, child)
	sc, _ := pollScanner(n)
	sc.setPollSwitch(pollSwitchOff)

	sc.pollRound(context.Background(), []*ZoneData{zd}, scannerPollConf{Enabled: true, Concurrency: 1})

	if len(n.queried) != 0 {
		t.Fatalf("queried %v after polling was switched off", n.queried)
	}
}
