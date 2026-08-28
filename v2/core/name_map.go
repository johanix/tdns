/*
 * A concurrent map keyed by DNS name.
 *
 * The point of the type is that the canonicalisation cannot be forgotten. A
 * plain ConcurrentMap keyed by a name is correct only if every one of its call
 * sites remembers to fold the key first -- and tdns had sixty-odd such sites,
 * of which the ones that remembered were the minority. Here the invariant is
 * structural: there is no way to reach the underlying map with a raw key.
 */

package core

// NameMap is a concurrent map whose keys are DNS names, compared
// case-insensitively as DNS requires.
//
// Every method that takes a name canonicalises it (CanonicalizeName), so
// Get("NS1.Example.COM.") and Get("ns1.example.com.") reach the same entry
// however the entry was spelled when it was stored.
//
// KEYS ARE CANONICAL, VALUES ARE NOT. Iterating yields folded keys. Where the
// name as it arrived matters -- serving it back, writing a zone file, reporting
// it over the API -- read it from the value, which is where the arrived
// spelling is kept (OwnerData.Name, an RR header). Callers that used the map
// key as the display name will show a lowercase name after this change; that
// is the intended trade, since the key can no longer be both a reliable index
// and a faithful record of what was typed.
//
// Names are canonicalised, not absolutised: a relative name and its FQDN are
// still different keys. Pass names through dns.Fqdn before they get here, as
// the rest of tdns already does.
type NameMap[V any] struct {
	m *ConcurrentMap[string, V]
}

// NewNameMap returns an empty NameMap.
func NewNameMap[V any]() *NameMap[V] {
	return &NameMap[V]{m: NewCmap[V]()}
}

// Get returns the value stored under name, and whether it was there.
func (nm *NameMap[V]) Get(name string) (V, bool) {
	return nm.m.Get(CanonicalizeName(name))
}

// Set stores value under name.
func (nm *NameMap[V]) Set(name string, value V) {
	nm.m.Set(CanonicalizeName(name), value)
}

// Has reports whether name is present.
func (nm *NameMap[V]) Has(name string) bool {
	return nm.m.Has(CanonicalizeName(name))
}

// SetIfAbsent stores value under name only if the name is not already present,
// reporting whether it stored.
func (nm *NameMap[V]) SetIfAbsent(name string, value V) bool {
	return nm.m.SetIfAbsent(CanonicalizeName(name), value)
}

// Remove deletes name, if present.
func (nm *NameMap[V]) Remove(name string) {
	nm.m.Remove(CanonicalizeName(name))
}

// Count returns the number of entries.
func (nm *NameMap[V]) Count() int { return nm.m.Count() }

// IsEmpty reports whether the map holds nothing.
func (nm *NameMap[V]) IsEmpty() bool { return nm.m.IsEmpty() }

// Keys returns every key, canonical.
func (nm *NameMap[V]) Keys() []string { return nm.m.Keys() }

// Items returns a snapshot of the map as a plain map, keyed canonically.
func (nm *NameMap[V]) Items() map[string]V { return nm.m.Items() }

// Iter returns a channel of every entry.
func (nm *NameMap[V]) Iter() <-chan Tuple[string, V] { return nm.m.Iter() }

// IterBuffered returns a buffered channel of every entry.
func (nm *NameMap[V]) IterBuffered() <-chan Tuple[string, V] { return nm.m.IterBuffered() }
