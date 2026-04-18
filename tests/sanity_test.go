//go:build integration
// +build integration

package tests

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/zluudg/tdns/stupidns"
)

func TestIntegrationSanity(t *testing.T) {
    stupidns.Setup()

	files, err := os.ReadDir(stupidns.TESTDATA_DIR)
	if err != nil {
		panic(fmt.Sprintf("Error reading testdata files: %s", err))
	}

	for _, f := range files {
		/*
		 * Any files in the testdata folder not beginning with this string will be
		 * ignored by this test.
		 */
		if !strings.HasPrefix(f.Name(), "sanity") {
			continue
		}

		file, err := os.ReadFile(stupidns.TESTDATA_DIR + f.Name())
		if err != nil {
			panic(fmt.Sprintf("Error reading testdata file: %s", err))
		}

		var c stupidns.Case

		yaml.Unmarshal(file, &c)
		if err != nil {
			panic(fmt.Sprintf("Error unmarshaling testdata file: %s", err))
		}

		t.Run(f.Name(), func(t *testing.T) {
			/* Get the result fetcher function that will be used for this test */
			fetcher, ok := stupidns.FetcherDispatchTable[c.Fetcher]
			if !ok {
				panic("Error getting fetcher function")
			}

			/* Get the result checker function that will be used for this test */
			checker, ok := stupidns.CheckerDispatchTable[c.Checker]
			if !ok {
				panic("Error getting checker function")
			}

			stupiDNS := stupidns.Create(net.JoinHostPort(c.Config["address"], c.Config["port"]))
			/* Queue up the messages that StupiDNS will respond with */
			for _, m := range c.Mqueue {
				stupiDNS.AddToQueue(m...)
			}

			/* Start the StupiDNS server */
			stupiDNS.Serve()

			for _ = range c.Runs {
				/* Test logic for a single run goes here */
			}

			/* Fetch the result */
			result := fetcher()

			/* Check the result */
			if !checker(result, c.Expected) {
				t.Fatalf("Failed, got: %+v, expected: %+v", result, c.Expected)
			}
		})
	}

    stupidns.Teardown()
}
