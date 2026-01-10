package ixfr

import (
	"fmt"

	"github.com/miekg/dns"
)

type DiffSequence struct {
	StartSOASerial uint32
	EndSOASerial   uint32
	AddedRecords   []dns.RR
	DeletedRecords []dns.RR
}

func CreateDiffSequence(soaStart, soaEnd uint32) DiffSequence {
	return DiffSequence{
		StartSOASerial: soaStart,
		EndSOASerial:   soaEnd,
		AddedRecords:   []dns.RR{},
		DeletedRecords: []dns.RR{},
	}
}

func (self *DiffSequence) Equals(other DiffSequence) bool {
	if self.StartSOASerial != other.StartSOASerial {
		return false
	}

	if self.EndSOASerial != other.EndSOASerial {
		return false
	}

	if !rrEquals(self.AddedRecords, other.AddedRecords) {
		return false
	}

	if !rrEquals(self.DeletedRecords, other.DeletedRecords) {
		return false
	}

	return true
}

func (self *DiffSequence) GetAdded() []dns.RR {
	return self.getDifference(true)
}

func (self *DiffSequence) AddAdded(rrStr string) {
	rr, err := dns.NewRR(rrStr)

	if err != nil {
		panic("Error adding RR to 'added' slice")
	}

	self.AddedRecords = append(self.AddedRecords, rr)
}

func (self *DiffSequence) GetDeleted() []dns.RR {
	return self.getDifference(false)
}

func (self *DiffSequence) AddDeleted(rrStr string) {
	rr, err := dns.NewRR(rrStr)

	if err != nil {
		panic("Error adding RR to 'deleted' slice")
	}

	self.DeletedRecords = append(self.DeletedRecords, rr)
}

/* TODO Handle differing number of added and deleted rrs.
 * What happens for instance if we delete 2 NS records
 * and add 3 NS records for a given domain? Which one
 * was "added" and which ones where "just changed"
 */
func (self *DiffSequence) getDifference(getAdded bool) []dns.RR {
	/* Calc set difference as "a\b" */
	var a, b *[]dns.RR
	diff := make(map[string][]string, 0)

	if getAdded {
		a = &self.AddedRecords
		b = &self.DeletedRecords
	} else {
		a = &self.DeletedRecords
		b = &self.AddedRecords
	}

	/* keys are of the format "DOMAIN+RType", an A record for example.com
	 * would be "example.com+1", for instance
	 */
	for _, _a := range *a {
		key := fmt.Sprintf("%s+%d", _a.Header().Name, _a.Header().Rrtype)
		_, ok := diff[key]
		if !ok {
			diff[key] = make([]string, 1)
			diff[key][0] = _a.String()
		} else {
			diff[key] = append(diff[key], _a.String())
		}
	}

	for _, _b := range *b {
		key := fmt.Sprintf("%s+%d", _b.Header().Name, _b.Header().Rrtype)
		slice, ok := diff[key]
		if ok {
			diff[key] = slice[1:len(slice)]
		} else {
			continue
		}

		if len(diff[key]) == 0 {
			delete(diff, key)
		}
	}

	rrs := make([]dns.RR, 0)
	for _, v := range diff {
		for _, s := range v {
			rr, err := dns.NewRR(s)
			if err != nil {
				panic("Error calculating diff between RR slices")
			}
			rrs = append(rrs, rr)
		}
	}

	return rrs
}
