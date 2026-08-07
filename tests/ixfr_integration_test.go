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
	"github.com/miekg/dns"

	"github.com/zluudg/tdns/stupidns"
)

func TestIntegrationIxfr(t *testing.T) {
	files, err := os.ReadDir(stupidns.TESTDATA_DIR)
	if err != nil {
		panic(fmt.Sprintf("Error reading testdata files: %s", err))
	}

	for _, f := range files {
		/*
		 * Any files in the testdata folder not beginning with this string will be
		 * ignored by this test.
		 */
		if !strings.HasPrefix(f.Name(), "ixfr_integration") {
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
            /* Create the bucket that will be used by the fetcher */
            var bucket stupidns.Bucket

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

            /* The StupiDNS server address */
			addr := net.JoinHostPort(c.Config["address"], c.Config["port"])

            /* Create the StupiDNS server */
            stupiDNS := stupidns.Create(addr)

			/* Queue up the messages that StupiDNS will respond with */
			for _, m := range c.Mqueue {
				stupiDNS.AddToQueue(m...)
			}

			/* Start the StupiDNS server */
			stupiDNS.Serve()

			/* Run the actual code to be tested here "c.Runs" times */
			for _ = range c.Runs {
				/* Create the client */
				client := new(dns.Client)
				client.Net = "tcp"
				var conn *dns.Conn

				/* Retry 10 times in case StupiDNS is not up yet */
				for range 10 {
					conn, err = client.Dial(addr)

					if err == nil {
						break
					}
				}

				/* Assemble the query... */
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.RecursionDesired = true

				/* ...aaand send it */
				r, _, err := client.ExchangeWithConn(m, conn)

				/* Make sure response was ok */
				if r == nil {
					panic(fmt.Sprintf("*** error: %s\n", err))
				}
				if r.Rcode != dns.RcodeSuccess {
					panic("Bad response code!")
				}

				/* For each RR in the answer section, exctract IP address and
				 * store in bucket.
				 */
				for _, answer := range r.Answer {
					fields := strings.Fields(answer.String())
					bucket.Store(fields[4])
				}
			}

			/* Fetch the result, pass bucket since "getFromBucket" is being used */
			result := fetcher(bucket)

			/* Check the result */
			if !checker(result, c.Expected) {
				t.Fatalf("Failed, got: %+v, expected: %+v", result, c.Expected)
			}
		})
	}
}
