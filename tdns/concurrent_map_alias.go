package tdns

import corepkg "github.com/johanix/tdns/tdns/core"

type ConcurrentMap[K comparable, V any] = corepkg.ConcurrentMap[K, V]
type ConcurrentMapShared[K comparable, V any] = corepkg.ConcurrentMapShared[K, V]
type Tuple[K comparable, V any] = corepkg.Tuple[K, V]
type UpsertCb[V any] = corepkg.UpsertCb[V]
type RemoveCb[K any, V any] = corepkg.RemoveCb[K, V]
type IterCb[K comparable, V any] = corepkg.IterCb[K, V]

func NewCmap[V any]() *corepkg.ConcurrentMap[string, V] {
	return corepkg.NewCmap[V]()
}

func NewStringer[K corepkg.Stringer, V any]() corepkg.ConcurrentMap[K, V] {
	return corepkg.NewStringer[K, V]()
}

func NewWithCustomShardingFunction[K comparable, V any](sharding func(key K) uint32) corepkg.ConcurrentMap[K, V] {
	return corepkg.NewWithCustomShardingFunction[K, V](sharding)
}
