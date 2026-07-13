/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigDir is the base directory for all tdns-debug on-disk state:
// the state file (<configdir>/state.yaml) and each test's artifacts
// (<configdir>/<id>/). Overridable with --configdir. Chosen as a short,
// predictable path rather than burying artifacts under a deep temp path.
const DefaultConfigDir = "/tmp/tdns-debug"

// The state file is deliberately NOT a database (design doc §6.2): one small,
// human-readable, hand-editable YAML document. Losing it loses bookkeeping
// convenience, not correctness — everything it names is also discoverable by
// its "<id>." prefix on the server.

type StageEvent struct {
	Stage string    `yaml:"stage"` // provisioned | ran | cleaned | ...
	Time  time.Time `yaml:"time"`
	Note  string    `yaml:"note,omitempty"`
}

// TestRecord is everything later stages need to correlate with an earlier
// --generate-config: run resolves zone/keys from here, cleanup undoes here.
type TestRecord struct {
	Id            string       `yaml:"id"`
	Kind          string       `yaml:"kind"` // churn | ddns | ...
	CreatedAt     time.Time    `yaml:"created_at"`
	BaseZone      string       `yaml:"base_zone"`
	Zone          string       `yaml:"zone"`
	Target        string       `yaml:"target,omitempty"`     // apiservers entry name
	DnsServer     string       `yaml:"dns_server,omitempty"` // addr:port
	Sig0KeyName   string       `yaml:"sig0_key_name"`
	Sig0KeyFile   string       `yaml:"sig0_key_file,omitempty"` // KEY RR (public)
	Sig0PrivFile  string       `yaml:"sig0_priv_file,omitempty"`
	ArtifactDir   string       `yaml:"artifact_dir"`
	AutoInstalled []string     `yaml:"auto_installed,omitempty"` // undone via API by cleanup (M3)
	OperatorSteps []string     `yaml:"operator_steps,omitempty"` // manual install; cleanup prints the mirror
	History       []StageEvent `yaml:"history"`
	Cleaned       bool         `yaml:"cleaned"`
}

type State struct {
	NextId int                    `yaml:"next_id"`
	Tests  map[string]*TestRecord `yaml:"tests"`
}

// LoadState reads the state file; a missing file is an empty state, not an
// error (first use).
func LoadState(path string) (*State, error) {
	st := &State{NextId: 1, Tests: map[string]*TestRecord{}}
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(buf, st); err != nil {
		return nil, fmt.Errorf("state file %s is not valid YAML: %v", path, err)
	}
	if st.Tests == nil {
		st.Tests = map[string]*TestRecord{}
	}
	if st.NextId < 1 {
		st.NextId = 1
	}
	return st, nil
}

// Save writes atomically (tmp + rename). Best-effort single-user semantics;
// concurrent tdns-debug invocations are not a supported mode.
func (st *State) Save(path string) error {
	buf, err := yaml.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Allocate reserves the next sequential test ID (test001, test002, …) and
// registers a skeleton record for it.
func (st *State) Allocate(kind string) *TestRecord {
	id := fmt.Sprintf("test%03d", st.NextId)
	st.NextId++
	rec := &TestRecord{
		Id:        id,
		Kind:      kind,
		CreatedAt: time.Now(),
		History:   []StageEvent{},
	}
	st.Tests[id] = rec
	return rec
}

func (st *State) Get(id string) (*TestRecord, error) {
	rec, ok := st.Tests[id]
	if !ok {
		return nil, fmt.Errorf("unknown test %q (see tdns-debug list-tests)", id)
	}
	return rec, nil
}

func (rec *TestRecord) AddStage(stage, note string) {
	rec.History = append(rec.History, StageEvent{Stage: stage, Time: time.Now(), Note: note})
}
