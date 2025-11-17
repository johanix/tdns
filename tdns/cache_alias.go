package tdns

import cachepkg "github.com/johanix/tdns/tdns/cache"

type DnskeyCacheT = cachepkg.DnskeyCacheT
type TrustAnchor = cachepkg.TrustAnchor
type CachedRRset = cachepkg.CachedRRset
type AuthServer = cachepkg.AuthServer

var NewDnskeyCache = cachepkg.NewDnskeyCache
