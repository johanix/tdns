/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"fmt"
	"log"

	edns0 "github.com/johanix/tdns/v0.x/edns0"
	"github.com/miekg/dns"
)

func (imr *Imr) SendRfc9567ErrorReport(ctx context.Context, qname string, qtype uint16, ede_code uint16, msgoptions *edns0.MsgOptions) error {
	if msgoptions == nil || !msgoptions.HasEROption || msgoptions.ErAgentDomain == "" {
		log.Printf("SendRfc9567ErrorReport: No ER option or agent domain. Cannot send error report.")
		return nil
	}
	if imr != nil {
		go func() {
			select {
			case <-ctx.Done():
				log.Printf("SendRfc9567ErrorReport: Context cancelled before sending report")
				return
			default:
			}
			report_qname := fmt.Sprintf("_er.%d.%s%d._er.%s", qtype, qname, ede_code, msgoptions.ErAgentDomain)
			log.Printf("SendRfc9567ErrorReport: Sending report query %q", report_qname)
			ir, err := imr.ImrQuery(ctx, report_qname, dns.TypeTXT, dns.ClassINET, nil)
			if err != nil {
				log.Printf("SendRfc9567ErrorReport: Error from ImrQuery: %v", err)
			} else {
				log.Printf("SendRfc9567ErrorReport: Received response from ImrQuery: %v", ir)
			}
		}()
		return nil
	}
	log.Printf("SendRfc9567ErrorReport: ImrEngine not active. Cannot send error report.")
	return fmt.Errorf("ImrEngine not active. Cannot send error report.")
}
