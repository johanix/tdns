package tdns

import (
	cmap "github.com/orcaman/concurrent-map/v2"
)

type RRTypeStore interface {
	Get(key uint16) (RRset, bool)
	Set(key uint16, value RRset)
	Delete(key uint16)
	GetOnlyRRSet(key uint16) RRset
	Count() int
	Keys() []uint16
}

type ConcurrentRRTypeStore struct {
	data cmap.ConcurrentMap[uint16, RRset]
}

func NewConcurrentRRTypeStore() *ConcurrentRRTypeStore {
	return &ConcurrentRRTypeStore{
		data: cmap.NewWithCustomShardingFunction[uint16, RRset](func(key uint16) uint32 {
			return uint32(key)
		}),
	}
}

func (s *ConcurrentRRTypeStore) Get(key uint16) (RRset, bool) {
	return s.data.Get(key)
}

func (s *ConcurrentRRTypeStore) GetOnlyRRSet(key uint16) RRset {
	rrset, _ := s.data.Get(key)
	return rrset
}

func (s *ConcurrentRRTypeStore) Set(key uint16, value RRset) {
	s.data.Set(key, value)
}

func (s *ConcurrentRRTypeStore) Delete(key uint16) {
	s.data.Remove(key)
}

func (s *ConcurrentRRTypeStore) Count() int {
	return s.data.Count()
}

func (s *ConcurrentRRTypeStore) Keys() []uint16 {
	return s.data.Keys()
}

func NewOwnerData(name string) *OwnerData {
	return &OwnerData{
		Name:    name,
		RRtypes: NewConcurrentRRTypeStore(),
	}
}
