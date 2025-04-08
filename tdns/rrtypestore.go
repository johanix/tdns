package tdns

type RRTypeStore struct {
	data ConcurrentMap[uint16, RRset]
}

func NewRRTypeStore() *RRTypeStore {
	return &RRTypeStore{
		data: NewWithCustomShardingFunction[uint16, RRset](func(key uint16) uint32 {
			return uint32(key)
		}),
	}
}

func (s *RRTypeStore) Get(key uint16) (RRset, bool) {
	return s.data.Get(key)
}

func (s *RRTypeStore) GetOnlyRRSet(key uint16) RRset {
	// dump.P(s)
	// dump.P(key)
	rrset, _ := s.data.Get(key)
	return rrset
}

func (s *RRTypeStore) Set(key uint16, value RRset) {
	s.data.Set(key, value)
}

func (s *RRTypeStore) Delete(key uint16) {
	s.data.Remove(key)
}

func (s *RRTypeStore) Count() int {
	return s.data.Count()
}

func (s *RRTypeStore) Keys() []uint16 {
	return s.data.Keys()
}

func NewOwnerData(name string) *OwnerData {
	return &OwnerData{
		Name:    name,
		RRtypes: NewRRTypeStore(),
	}
}
