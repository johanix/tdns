module github.com/johanix/tdns/v1.0/tdns/cli

go 1.24.0

replace (
	github.com/johanix/tdns/v1.0/tdns => ../
	github.com/johanix/tdns/v1.0/tdns/cache => ../cache
	github.com/johanix/tdns/v1.0/tdns/core => ../core
	github.com/johanix/tdns/v1.0/tdns/edns0 => ../edns0
)

require (
	github.com/c-bata/go-prompt v0.2.6
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/go-playground/validator/v10 v10.22.1
	github.com/gookit/goutil v0.6.15
	github.com/johanix/tdns/v1.0/tdns v0.0.0-20251115235005-48e48cb765aa
	github.com/johanix/tdns/v1.0/tdns/cache v0.0.0-20251209183459-2d9962c12f9f
	github.com/johanix/tdns/v1.0/tdns/core v0.0.0-20251122130747-9c54a3943883
	github.com/johanix/tdns/v1.0/tdns/edns0 v0.0.0-20251121102720-aa307d56701e
	github.com/miekg/dns v1.1.68
	github.com/ryanuber/columnize v2.1.2+incompatible
	github.com/spf13/cobra v1.8.1
	github.com/spf13/viper v1.16.0
	golang.org/x/term v0.37.0
	gopkg.in/yaml.v3 v3.0.1
	zgo.at/acidtab v1.1.0
)

require (
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-sqlite3 v1.14.16 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/pkg/term v1.2.0-beta.2 // indirect
	github.com/quic-go/quic-go v0.58.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
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
	zgo.at/runewidth v0.1.0 // indirect
	zgo.at/termtext v1.5.0 // indirect
)
