/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
        "log"
        "strings"

        "github.com/miekg/dns"
)

type UpdatePolicy struct {
        Type    string // only "selfsub" known at the moment
        RRtypes map[uint16]bool
        Verbose bool
        Debug   bool
}
func (policy *UpdatePolicy) ApproveUpdate(zone, signername string, r *dns.Msg) (bool, error) {
        log.Printf("Analysing update using policy type %s with allowed RR types %v",
                policy.Type, policy.RRtypes)

        for i := 0; i <= len(r.Ns)-1; i++ {
                rr := r.Ns[i]

                if !policy.RRtypes[rr.Header().Rrtype] {
                        log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
                                dns.TypeToString[rr.Header().Rrtype])
                        return false, nil
                }

                switch policy.Type {
                case "selfsub":
                        if !strings.HasSuffix(rr.Header().Name, signername) {
                                log.Printf("ApproveUpdate: update rejected (owner name %s outside selfsub %s tree)",
                                        rr.Header().Name, signername)
                                return false, nil
                        }

                case "self":
                        if rr.Header().Name != signername {
                                log.Printf("ApproveUpdate: update rejected (owner name %s different from signer name %s in violation of \"self\" policy)",
                                        rr.Header().Name, signername)
                                return false, nil
                        }
                default:
                        log.Printf("ApproveUpdate: unknown policy type: \"%s\"", policy.Type)
                        return false, nil
                }

                if rr.Header().Class == dns.ClassNONE {
                        log.Printf("ApproveUpdate: Remove RR: %s", rr.String())
                } else if rr.Header().Class == dns.ClassANY {
                        log.Printf("ApproveUpdate: Remove RRset: %s", rr.String())
                } else {
                        log.Printf("ApproveUpdate: Add RR: %s", rr.String())
                }
        }
        return true, nil
}
