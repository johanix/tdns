/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// DelegationBackend is where a parent's approved child delegation data ends
// up. It is what ZoneData.DelegationBackend holds, and what the CHILD-UPDATE
// path, the scanner and the operator surface call.
//
// Behind it are two independent questions (docs/2026-09-08-childsync-proxy.md
// D-7): WHERE the intended delegation state is kept -- the DelegationStore --
// and HOW it reaches the parent zone -- the ParentZoneWriter.
// LookupDelegationBackend composes one of each. The historical one-word type
// names are sugar for particular pairs:
//
//	type: db          = store: sqlite,      writer: none
//	type: direct      = store: direct,      writer: none
//	type: zonefile    = store: sqlite,      writer: zonefile
//	type: upstream    = store: sqlite,      writer: ddns
//	type: external-db = store: external-db, writer: none
type DelegationBackend interface {
	// ApplyChildUpdate processes an approved child UPDATE.
	// Actions are ClassINET (add), ClassNONE (delete-RR), ClassANY (delete-RRset).
	ApplyChildUpdate(parentZone string, ur UpdateRequest) error

	// GetDelegationData returns current delegation RRs for a child zone,
	// grouped by owner name and RR type.
	//
	// A child with nothing stored yields an EMPTY map and a nil error. An
	// error means the store could not be read, and no caller may read it as
	// "nothing there": a store behind a network fails for reasons that have
	// nothing to do with the child, and the two answers lead to opposite
	// actions -- an empty delegation is something to reconcile against, an
	// unreadable one is something to leave alone.
	GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error)

	// ListChildren returns all child zones with stored delegation data.
	ListChildren(parentZone string) ([]string, error)

	// Name returns the backend name for logging.
	Name() string
}

// DelegationStore persists intended delegation state: the store axis. It
// answers the same four questions a DelegationBackend does, because a backend
// IS a store with a writer beside it.
//
// ApplyChildUpdate is ATOMIC over ur.Actions: a child update is one intent
// and must not be observable half-applied, by tdns's own reconciler or by an
// external consumer reading the store.
type DelegationStore interface {
	ApplyChildUpdate(parentZone string, ur UpdateRequest) error
	GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error)
	ListChildren(parentZone string) ([]string, error)
	Name() string
}

// ParentZoneWriter delivers approved delegation data to wherever the parent
// zone is authored: the writer axis. Actions use the RFC 2136 classes the
// rest of the tree uses: ClassINET add, ClassNONE delete-RR, ClassANY
// delete-RRset.
//
// A writer is called AFTER the store has recorded the change, so it may read
// the store for the child's whole current state rather than replay the
// actions; the zonefile writer does exactly that.
type ParentZoneWriter interface {
	Write(ctx context.Context, parentZone string, actions []dns.RR, desc string) error
	Name() string
}

// Store and writer names as written in the config.
const (
	DelegationStoreSqlite     = "sqlite"
	DelegationStoreDirect     = "direct"
	DelegationStoreExternalDB = "external-db"

	DelegationWriterNone     = "none"
	DelegationWriterZonefile = "zonefile"
	DelegationWriterDDNS     = "ddns"
)

// DelegationBackendConf is a named backend definition from the config file.
// The predefined names "db" and "direct" need no entry.
//
// Both tag families are set on purpose: the daemon's own config decoder reads
// yaml tags, but this list is read back out of viper with UnmarshalKey, whose
// decoder reads mapstructure tags -- and without them the hyphenated key
// notify-command never reached the field.
type DelegationBackendConf struct {
	Name string `yaml:"name" mapstructure:"name"`
	// Type is the historical one-word spelling, sugar for a (store, writer)
	// pair. Writing it together with Store or Writer is an error rather than
	// a precedence rule: picking a winner silently leaves the operator reading
	// one line while the server obeys another.
	Type   string `yaml:"type" mapstructure:"type"`
	Store  string `yaml:"store" mapstructure:"store"`   // sqlite | direct | external-db (default sqlite)
	Writer string `yaml:"writer" mapstructure:"writer"` // none | zonefile | ddns (default none)

	Directory     string `yaml:"directory" mapstructure:"directory"`           // zonefile writer
	NotifyCommand string `yaml:"notify-command" mapstructure:"notify-command"` // zonefile writer

	DDNS DdnsWriterConf `yaml:"ddns" mapstructure:"ddns"` // ddns writer

	ExternalDB ExternalDBConf `yaml:"external-db" mapstructure:"external-db"` // external-db store
}

// ExternalDBConf configures the external-db store: a shared MariaDB holding
// delegation data for a provisioning consumer to read. Data only -- the
// store, and the driver it needs, live in the v2/externaldb module, which
// registers the store in the binaries whose main imports it (amendment A-3).
type ExternalDBConf struct {
	Driver string `yaml:"driver" mapstructure:"driver"` // mysql (MariaDB)
	// DSN in the driver's format, e.g. tdns:@tcp(db.example.net:3306)/reg.
	// It may carry the password; SensitiveString keeps it out of every
	// rendering of the config.
	DSN      SensitiveString `yaml:"dsn" mapstructure:"dsn"`
	Password SensitiveString `yaml:"password" mapstructure:"password"`
	// TLS to the database. nil means on for any non-loopback address.
	TLS    *bool  `yaml:"tls" mapstructure:"tls"`
	CAFile string `yaml:"ca-file" mapstructure:"ca-file"`
	// TablePrefix defaults to tdns_.
	TablePrefix string `yaml:"table-prefix" mapstructure:"table-prefix"`
	// AutoMigrate creates the tables if absent. Off by default: tdns ships
	// the DDL and the DBA runs it. It never alters an existing table.
	AutoMigrate  bool          `yaml:"auto-migrate" mapstructure:"auto-migrate"`
	MaxOpenConns int           `yaml:"max-open-conns" mapstructure:"max-open-conns"`
	Timeout      time.Duration `yaml:"timeout" mapstructure:"timeout"`
}

// DdnsWriterConf configures the ddns writer: RFC 2136 UPDATEs, TSIG-signed,
// to the primary of the parent zone this server is a secondary of.
type DdnsWriterConf struct {
	// Targets are the primaries to update, addr or addr:port (53 assumed).
	// Empty means the zone's own primaries: the machine this server already
	// transfers from is, in every sane deployment, the machine to update.
	Targets []string `yaml:"targets" mapstructure:"targets"`
	// Key names the TSIG key, from the keystore, that signs the UPDATE.
	Key string `yaml:"key" mapstructure:"key"`
	// AllowInsecure permits an UNSIGNED UPDATE. A lab convenience, never a
	// production setting: the parent's update-policy is the only thing
	// bounding what this server may write, and an unsigned UPDATE is
	// whoever can spoof the source address.
	AllowInsecure bool `yaml:"allow-insecure" mapstructure:"allow-insecure"`
	// RetryInterval and MaxAttempts bound the push engine's retries after a
	// transport failure or a SERVFAIL. Zero means the engine's defaults.
	RetryInterval time.Duration `yaml:"retry-interval" mapstructure:"retry-interval"`
	MaxAttempts   int           `yaml:"max-attempts" mapstructure:"max-attempts"`
}

var delegationBackendTypeSugar = map[string][2]string{
	"db":          {DelegationStoreSqlite, DelegationWriterNone},
	"direct":      {DelegationStoreDirect, DelegationWriterNone},
	"zonefile":    {DelegationStoreSqlite, DelegationWriterZonefile},
	"upstream":    {DelegationStoreSqlite, DelegationWriterDDNS},
	"external-db": {DelegationStoreExternalDB, DelegationWriterNone},
}

// DelegationBackendSpec is a backend name resolved to its two axes.
type DelegationBackendSpec struct {
	Name   string
	Store  string
	Writer string
	Conf   DelegationBackendConf
}

// errDelegationBackendUnknown marks a name with no definition. Validation
// lets that case through to the wiring step, which has always been where an
// undefined backend is reported; every other resolution failure is a
// contradiction in a definition that does exist, and is reported wherever it
// is met.
var errDelegationBackendUnknown = errors.New("not found in delegationbackends config")

// resolveDelegationBackendSpec turns a backend name into a (store, writer)
// pair, applying the type sugar and checking that the pair can exist. Pure:
// confs is the delegationbackends list, and nothing is constructed.
func resolveDelegationBackendSpec(name string, confs []DelegationBackendConf) (DelegationBackendSpec, error) {
	spec := DelegationBackendSpec{Name: name}
	if pair, predefined := delegationBackendTypeSugar[name]; predefined && (name == "db" || name == "direct") {
		spec.Store, spec.Writer = pair[0], pair[1]
		return spec, nil
	}

	var bc *DelegationBackendConf
	for i := range confs {
		if confs[i].Name == name {
			bc = &confs[i]
			break
		}
	}
	if bc == nil {
		return spec, fmt.Errorf("delegation backend %q: %w", name, errDelegationBackendUnknown)
	}
	spec.Conf = *bc

	store := strings.ToLower(strings.TrimSpace(bc.Store))
	writer := strings.ToLower(strings.TrimSpace(bc.Writer))
	if typ := strings.ToLower(strings.TrimSpace(bc.Type)); typ != "" {
		if store != "" || writer != "" {
			return spec, fmt.Errorf("delegation backend %q: type: %q cannot be combined with store: or writer:;"+
				" type is shorthand for a (store, writer) pair, so write one or the other", name, bc.Type)
		}
		pair, ok := delegationBackendTypeSugar[typ]
		if !ok {
			return spec, fmt.Errorf("delegation backend %q: unknown type %q", name, bc.Type)
		}
		store, writer = pair[0], pair[1]
	}
	switch store {
	case "", "db":
		store = DelegationStoreSqlite
	}
	switch writer {
	case "", "manual":
		writer = DelegationWriterNone
	}
	spec.Store, spec.Writer = store, writer

	// direct is the one combination that is not free-form: the in-memory
	// zone IS the delivery, so there is nothing for a writer to deliver to.
	// Judged before the writer's own rules, because it is the more basic
	// contradiction.
	if store == DelegationStoreDirect && writer != DelegationWriterNone {
		return spec, fmt.Errorf("delegation backend %q: store direct accepts only writer none;"+
			" the served zone is the delivery, there is nothing for a %s writer to deliver to", name, writer)
	}
	if _, ok := delegationStoreFactory(store); !ok {
		return spec, fmt.Errorf("delegation backend %q: store %q is not compiled into %s (available: %s)",
			name, store, appBinaryName(), strings.Join(RegisteredDelegationStores(), ", "))
	}
	if store == DelegationStoreExternalDB && bc.ExternalDB.DSN.Value() == "" {
		return spec, fmt.Errorf("delegation backend %q: store external-db requires external-db.dsn", name)
	}
	switch writer {
	case DelegationWriterNone:
	case DelegationWriterDDNS:
		if bc.DDNS.Key == "" && !bc.DDNS.AllowInsecure {
			return spec, fmt.Errorf("delegation backend %q (writer ddns): set ddns.key (a TSIG key from the keystore)"+
				" or ddns.allow-insecure (lab only); an unsigned UPDATE to the parent primary is refused otherwise", name)
		}
	case DelegationWriterZonefile:
		if bc.Directory == "" {
			return spec, fmt.Errorf("delegation backend %q (writer zonefile): directory is required", name)
		}
	default:
		return spec, fmt.Errorf("delegation backend %q: unknown writer %q (none, zonefile, ddns)", name, bc.Writer)
	}
	return spec, nil
}

func appBinaryName() string {
	if Globals.App.Name != "" {
		return Globals.App.Name
	}
	return "this binary"
}

// loadDelegationBackendConfs reads the delegationbackends list from the
// running configuration.
func loadDelegationBackendConfs() ([]DelegationBackendConf, error) {
	var backends []DelegationBackendConf
	if err := viper.UnmarshalKey("delegationbackends", &backends); err != nil {
		return nil, fmt.Errorf("failed to parse delegationbackends config: %w", err)
	}
	return backends, nil
}

// DelegationStoreFactory builds a store for one zone. spec carries the
// backend's config block; kdb and zd are the zone's, either of which a
// particular store may or may not need.
type DelegationStoreFactory func(spec DelegationBackendSpec, kdb *KeyDB, zd *ZoneData) (DelegationStore, error)

var delegationStores = struct {
	sync.RWMutex
	factories map[string]DelegationStoreFactory
}{factories: map[string]DelegationStoreFactory{}}

// RegisterDelegationStore makes a store available under a name in the
// config's store: axis. The built-in stores register themselves at init; a
// store that lives in its own module (external-db) registers from that
// module's init, so it exists in exactly the binaries whose main imports the
// module -- the same shape database/sql uses for its drivers, and what keeps
// that module's driver out of every other binary.
func RegisterDelegationStore(name string, f DelegationStoreFactory) {
	delegationStores.Lock()
	defer delegationStores.Unlock()
	if _, dup := delegationStores.factories[name]; dup {
		panic(fmt.Sprintf("delegation store %q registered twice", name))
	}
	delegationStores.factories[name] = f
}

func delegationStoreFactory(name string) (DelegationStoreFactory, bool) {
	delegationStores.RLock()
	defer delegationStores.RUnlock()
	f, ok := delegationStores.factories[name]
	return f, ok
}

// RegisteredDelegationStores lists the store names this binary can build.
func RegisteredDelegationStores() []string {
	delegationStores.RLock()
	defer delegationStores.RUnlock()
	names := make([]string, 0, len(delegationStores.factories))
	for n := range delegationStores.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func init() {
	RegisterDelegationStore(DelegationStoreSqlite, func(_ DelegationBackendSpec, kdb *KeyDB, _ *ZoneData) (DelegationStore, error) {
		if kdb == nil {
			return nil, fmt.Errorf("the sqlite delegation store needs a KeyDB and there is none")
		}
		return &DBDelegationBackend{kdb: kdb}, nil
	})
	RegisterDelegationStore(DelegationStoreDirect, func(_ DelegationBackendSpec, kdb *KeyDB, zd *ZoneData) (DelegationStore, error) {
		if zd == nil {
			return nil, fmt.Errorf("the direct delegation store needs a zone and there is none")
		}
		return &DirectDelegationBackend{zd: zd, kdb: kdb}, nil
	})
}

// composedDelegationBackend is what LookupDelegationBackend returns: a store
// and, optionally, a writer, under the name the operator wrote.
type composedDelegationBackend struct {
	name   string
	store  DelegationStore
	writer ParentZoneWriter // nil for writer: none
	// async: the writer speaks to the network and runs through
	// ParentPushEngine rather than inline. zd is the zone the engine
	// reconciles for.
	async bool
	zd    *ZoneData
}

func (b *composedDelegationBackend) Name() string { return b.name }

// ApplyChildUpdate records the change (durable on return) and then hands it
// to the writer. Returning the STORE's outcome is what acceptance means
// (design D-2): the child's NOERROR says "recorded by the parent's delegation
// service", as it already did for the db and zonefile backends.
//
// An inline writer -- zonefile, whose writes are local files -- runs here, as
// the zonefile backend always did. A writer that speaks to the network is
// handed to ParentPushEngine with a non-blocking enqueue naming the affected
// children; a full queue is logged and not an error, because the engine
// recomputes the delta from the store and the next refresh recovers a
// dropped push (§5.4).
func (b *composedDelegationBackend) ApplyChildUpdate(parentZone string, ur UpdateRequest) error {
	if err := b.store.ApplyChildUpdate(parentZone, ur); err != nil {
		return err
	}
	if b.writer == nil {
		return nil
	}
	if b.async {
		enqueueParentPush(ParentPushRequest{
			Kind:     ParentPushChildren,
			ZoneData: b.zd,
			Children: affectedChildren(parentZone, ur.Actions),
			Reason:   "child update",
		})
		return nil
	}
	return b.writer.Write(context.Background(), parentZone, ur.Actions, ur.Description)
}

func (b *composedDelegationBackend) GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error) {
	return b.store.GetDelegationData(parentZone, childZone)
}

func (b *composedDelegationBackend) ListChildren(parentZone string) ([]string, error) {
	return b.store.ListChildren(parentZone)
}

// AdoptChildDelegation implements DelegationAdopter by forwarding to the
// store when it keeps one. A store that does not (direct: the zone IS the
// store) adopts nothing, which is the truthful answer.
func (b *composedDelegationBackend) AdoptChildDelegation(parentZone, childZone string, rrs []dns.RR) (int, error) {
	if a, ok := b.store.(DelegationAdopter); ok {
		return a.AdoptChildDelegation(parentZone, childZone, rrs)
	}
	return 0, nil
}

// LookupDelegationBackend resolves a backend name to a DelegationBackend for
// one zone. "db" and "direct" are predefined; any other name is looked up in
// the delegationbackends config list.
func LookupDelegationBackend(name string, kdb *KeyDB, zd *ZoneData) (DelegationBackend, error) {
	confs, err := loadDelegationBackendConfs()
	if err != nil {
		return nil, err
	}
	spec, err := resolveDelegationBackendSpec(name, confs)
	if err != nil {
		return nil, err
	}
	return newDelegationBackend(spec, kdb, zd)
}

func newDelegationBackend(spec DelegationBackendSpec, kdb *KeyDB, zd *ZoneData) (DelegationBackend, error) {
	factory, ok := delegationStoreFactory(spec.Store)
	if !ok {
		return nil, fmt.Errorf("delegation backend %q: store %q is not compiled into %s", spec.Name, spec.Store, appBinaryName())
	}
	store, err := factory(spec, kdb, zd)
	if err != nil {
		return nil, fmt.Errorf("delegation backend %q: %w", spec.Name, err)
	}
	writer, err := newDelegationWriter(spec, store, zd)
	if err != nil {
		return nil, err
	}
	return &composedDelegationBackend{
		name:   spec.Name,
		store:  store,
		writer: writer,
		async:  spec.Writer == DelegationWriterDDNS,
		zd:     zd,
	}, nil
}

func newDelegationWriter(spec DelegationBackendSpec, store DelegationStore, zd *ZoneData) (ParentZoneWriter, error) {
	switch spec.Writer {
	case DelegationWriterNone:
		return nil, nil
	case DelegationWriterZonefile:
		return &zonefileWriter{
			directory:     spec.Conf.Directory,
			notifyCommand: spec.Conf.NotifyCommand,
			store:         store,
		}, nil
	case DelegationWriterDDNS:
		return newDdnsParentZoneWriter(spec, store, zd)
	}
	return nil, fmt.Errorf("delegation backend %q: unknown writer %q", spec.Name, spec.Writer)
}

// ExportDelegationData writes all delegation data for a parent zone to a file
// in DNS zone file format. Called from the /delegation API handler.
// defaultTTL is applied to any RR with TTL=0.
func ExportDelegationData(backend DelegationBackend, parentZone, outfile string, defaultTTL uint32) error {
	children, err := backend.ListChildren(parentZone)
	if err != nil {
		return fmt.Errorf("ListChildren: %w", err)
	}

	sort.Strings(children)

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("; Delegation data for parent zone %s\n", parentZone))
	buf.WriteString(fmt.Sprintf("; Exported: %s\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("; Backend: %s\n", backend.Name()))
	buf.WriteString(fmt.Sprintf("; Children: %d\n", len(children)))
	buf.WriteString(";\n")

	for _, child := range children {
		data, err := backend.GetDelegationData(parentZone, child)
		if err != nil {
			buf.WriteString(fmt.Sprintf("; ERROR: %s: %v\n", child, err))
			continue
		}

		buf.WriteString(fmt.Sprintf("; --- %s ---\n", child))

		// Collect and sort by owner then rrtype
		type ownerType struct {
			owner  string
			rrtype uint16
		}
		var keys []ownerType
		for owner, rrtypes := range data {
			for rrtype := range rrtypes {
				keys = append(keys, ownerType{owner, rrtype})
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].owner != keys[j].owner {
				return keys[i].owner < keys[j].owner
			}
			return keys[i].rrtype < keys[j].rrtype
		})

		for _, k := range keys {
			for _, rr := range data[k.owner][k.rrtype] {
				rrOut := rr
				if rr.Header().Ttl == 0 && defaultTTL > 0 {
					rrOut = dns.Copy(rr)
					rrOut.Header().Ttl = defaultTTL
				}
				buf.WriteString(rrOut.String())
				buf.WriteString("\n")
			}
		}
	}

	// Atomic write
	tmpfile := outfile + ".tmp"
	if err := os.WriteFile(tmpfile, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpfile, outfile); err != nil {
		os.Remove(tmpfile)
		return fmt.Errorf("rename: %w", err)
	}

	lg.Info("ExportDelegationData: wrote file", "zone", parentZone, "file", outfile, "children", len(children))
	return nil
}
