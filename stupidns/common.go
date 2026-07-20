package stupidns

import (
	"os"
)

/* Directory containing the testdata */
const TESTDATA_DIR = "./testdata/"

/* Signature for result fetcher functions */
type ResultFetcher func(obj ...interface{}) []string

/* Map for registering and accessing fetcher functions */
var FetcherDispatchTable = map[string]ResultFetcher{}

/* Signature for result checker functions */
type ResultChecker func(got, want []string) bool

/* Map for registering and accessing checker functions */
var CheckerDispatchTable = map[string]ResultChecker{}

/* A struct representing a test case */
type Case struct {
	Mqueue   [][]string        `yaml:"mqueue"`
	Expected []string          `yaml:"expected"`
	Fetcher  string            `yaml:fetcher`
	Checker  string            `yaml:checker`
	Runs     uint              `yaml:runs`
	Config   map[string]string `yaml:config`
}

/* Cache for storing strings that will be fetched by "getFromBucket" */
type Bucket struct {
	contents []string
}

func (b *Bucket) Store(s string) {
	if b.contents == nil {
		b.contents = make([]string, 0)
	}

	b.contents = append(b.contents, s)
}

func (b *Bucket) Get() []string {
	return b.contents
}

/* Populate the tables with some basic utilities */
func init() {
	CheckerDispatchTable["orderedSliceCompare"] = orderedSliceCompare
	CheckerDispatchTable["unorderedSliceCompare"] = unorderedSliceCompare
	CheckerDispatchTable["orderedSliceWithoutWhitespaceCompare"] = orderedSliceWithoutWhitespaceCompare
	CheckerDispatchTable["unorderedSliceWithoutWhitespaceCompare"] = unorderedSliceWithoutWhitespaceCompare

	FetcherDispatchTable["getEmptySlice"] = getEmptySlice
	FetcherDispatchTable["getEmptyString"] = getEmptyString
	FetcherDispatchTable["getFoo"] = getFoo
	FetcherDispatchTable["getBar"] = getBar
	FetcherDispatchTable["getFooBar"] = getFooBar
	FetcherDispatchTable["getBarFoo"] = getBarFoo
	FetcherDispatchTable["getFromBucket"] = getFromBucket
}

/* A temporary directory that test can use as a scratchpad */
var TEST_RUNDIR string

/* Setup function for creating the test directory */
func Setup() {
	var err error
	TEST_RUNDIR, err = os.MkdirTemp("", "tdns_integration_test_*")
	TEST_RUNDIR += "/"

	if err != nil {
		panic("Error setting up integration tests")
	}
}

/* Teardown function for remove the test directory */
func Teardown() {
	err := os.RemoveAll(TEST_RUNDIR)

	if err != nil {
		panic("Error tearing down integration tests")
	}
}
