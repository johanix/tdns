package ixfr

import (
	"fmt"

	"github.com/miekg/dns"
)

var logger = fmt.Printf

type Ixfr struct {
	InitialSOASerial uint32
	FinalSOASerial   uint32
	IsAxfr           bool
	DiffSequences    []DiffSequence
	AxfrRRs          []dns.RR
}

func SetLoggerHandle(fptr func(string, ...any) (int, error)) {
	logger = fptr
}

func (self *Ixfr) AddDiffSequence(ds DiffSequence) {
	self.DiffSequences = append(self.DiffSequences, ds)
}

func (self *Ixfr) Equals(other Ixfr) bool {
	if self.InitialSOASerial != other.InitialSOASerial {
		return false
	}

	if self.FinalSOASerial != other.FinalSOASerial {
		return false
	}

	if len(self.DiffSequences) != len(other.DiffSequences) {
		return false
	}

	for i, s := range self.DiffSequences {
		if !s.Equals(other.DiffSequences[i]) {
			return false
		}
	}

	return true
}

func IxfrFromResponse(rsp *dns.Msg) Ixfr {
	ixfr := Ixfr{}
	ixfr.DiffSequences = []DiffSequence{}
	isAdding := true
	var tmpSeq DiffSequence

	switch rsp.Answer[1].(type) {
	case *dns.SOA:
		/* Response was ixfr, proceed as normal */
	default:
		/* Response was axfr, handle accordingly */
		ixfr.IsAxfr = true
		ixfr.AxfrRRs = rsp.Answer

		switch u := rsp.Answer[0].(type) {
		case *dns.SOA:
			ixfr.FinalSOASerial = u.Serial
		default:
			panic("Bad first RR (SOA) in AXFR")
		}
	}

	if ixfr.IsAxfr {
		/* Response was in axfr form skip the handling of diff sequences*/
		return ixfr
	}

	for i, rr := range rsp.Answer {
		switch u := rr.(type) {
		case *dns.SOA:
			if i == 0 {
				/* First SOA record is not the start of a diff sequence */
				ixfr.FinalSOASerial = u.Serial
				continue
			} else if i == len(rsp.Answer) {
				/* We are done */
				continue
			}

			if isAdding {
				/* If we find a SOA and are in the adding state, it means its time
				 * to push the current diff sequence to the main ixfr object
				 * and then start preparing the next diff sequence. An exception
				 * is made for the first SOA in the diff sequence list where we
				 * don't push anything.
				 */

				if i == 1 {
					/* Start of first diff sequence, nothing to push */
					ixfr.InitialSOASerial = u.Serial
				} else {
					ixfr.DiffSequences = append(ixfr.DiffSequences, tmpSeq)
				}

				tmpSeq = CreateDiffSequence(u.Serial, 0)
				tmpSeq.AddedRecords = make([]dns.RR, 0)
				tmpSeq.DeletedRecords = make([]dns.RR, 0)
			} else {
				tmpSeq.EndSOASerial = u.Serial
			}

			/* Toggle between reading added/deleted records */
			isAdding = !isAdding
		default:
			if isAdding {
				tmpSeq.AddedRecords = append(tmpSeq.AddedRecords, rr)
			} else {
				tmpSeq.DeletedRecords = append(tmpSeq.DeletedRecords, rr)
			}
		}
	}

	return ixfr
}

func (self *Ixfr) GetCompressed() DiffSequence {
	tmp := CreateDiffSequence(0, 1)

	for _, ds := range self.DiffSequences {
		tmp.AddedRecords = append(tmp.AddedRecords, ds.AddedRecords...)
		tmp.DeletedRecords = append(tmp.DeletedRecords, ds.DeletedRecords...)
	}

	return DiffSequence{
		StartSOASerial: self.InitialSOASerial,
		EndSOASerial:   self.FinalSOASerial,
		AddedRecords:   tmp.GetAdded(),
		DeletedRecords: tmp.GetDeleted(),
	}
}

func (self *Ixfr) GetAdded() []dns.RR {
	ds := self.GetCompressed()
	return ds.GetAdded()
}

func (self *Ixfr) GetDeleted() []dns.RR {
	ds := self.GetCompressed()
	return ds.GetDeleted()
}
