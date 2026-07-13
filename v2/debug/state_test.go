package debug

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateAllocateAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")

	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on missing file: %v", err)
	}

	r1 := st.Allocate("churn")
	r2 := st.Allocate("ddns")
	if r1.Id != "test001" || r2.Id != "test002" {
		t.Fatalf("sequential ids: got %q, %q", r1.Id, r2.Id)
	}
	r1.Zone = "test001.test.example."
	r1.AddStage("provisioned", "unit test")

	if err := st.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	st2, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState round-trip: %v", err)
	}
	if st2.NextId != 3 {
		t.Errorf("NextId: got %d, want 3", st2.NextId)
	}
	got, err := st2.Get("test001")
	if err != nil {
		t.Fatalf("Get(test001): %v", err)
	}
	if got.Zone != "test001.test.example." || got.Kind != "churn" {
		t.Errorf("record round-trip: %+v", got)
	}
	if len(got.History) != 1 || got.History[0].Stage != "provisioned" {
		t.Errorf("history round-trip: %+v", got.History)
	}
	if _, err := st2.Get("test999"); err == nil {
		t.Errorf("Get(test999) should fail")
	}
}

func TestStateSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	st, _ := LoadState(path)
	st.Allocate("churn")
	if err := st.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file left behind")
	}
}

func TestStateRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	if err := os.WriteFile(path, []byte(":\tnot yaml ["), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Errorf("LoadState should reject invalid YAML")
	}
}
