module github.com/johanix/tdns/v2

go 1.25.2

replace (
	github.com/johanix/tdns/v2/cache => ./cache
	github.com/johanix/tdns/v2/core => ./core
	github.com/johanix/tdns/v2/edns0 => ./edns0
)

require (
	github.com/go-playground/validator/v10 v10.22.1
	github.com/gookit/goutil v0.6.15
	github.com/gorilla/mux v1.8.1
	github.com/johanix/dnssec-algorithms v0.0.0-20260513135759-676b5158decd
	github.com/johanix/tdns/v2/cache v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/v2/core v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/v2/edns0 v0.0.0-00010101000000-000000000000
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/miekg/dns v1.1.70
	github.com/mitchellh/mapstructure v1.5.0
	github.com/quic-go/quic-go v0.59.1
	github.com/spf13/pflag v1.0.6
	github.com/spf13/viper v1.16.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// Pinned at johanix/dns:algorithm-registry tip — provides the
// pluggable Algorithm interface. ML-DSA-44 itself lives out-of-tree
// in github.com/johanix/dnssec-algorithms/mldsa44 and is wired in by
// blank import from each binary's main package.
replace github.com/miekg/dns => github.com/johanix/dns v0.0.0-20260608092609-2a28f8f1484d
