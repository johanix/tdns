module tdns-combiner

go 1.24.0

replace (
	github.com/johanix/tdns/v1.0/tdns => ../v1.0/tdns
	github.com/johanix/tdns/v1.0/tdns/cache => ../v1.0/tdns/cache
	github.com/johanix/tdns/v1.0/tdns/core => ../v1.0/tdns/core
	github.com/johanix/tdns/v1.0/tdns/edns0 => ../v1.0/tdns/edns0
)

require (
	github.com/go-playground/validator/v10 v10.22.1 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.16 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/spf13/viper v1.16.0 // indirect
)

require github.com/johanix/tdns/v1.0/tdns v0.0.0-00010101000000-000000000000

require (
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gookit/goutil v0.6.15 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/johanix/tdns/v1.0/tdns/cache v0.0.0-00010101000000-000000000000 // indirect
	github.com/johanix/tdns/v1.0/tdns/core v0.0.0-00010101000000-000000000000 // indirect
	github.com/johanix/tdns/v1.0/tdns/edns0 v0.0.0-00010101000000-000000000000 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/quic-go/quic-go v0.58.0 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/twotwotwo/sorts v0.0.0-20160814051341-bf5c1f2b8553 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
