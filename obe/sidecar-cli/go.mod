module sidecar-cli

go 1.24.0

replace (
	github.com/johanix/tdns/music => ../music
	github.com/johanix/tdns/music/cmd => ../music/cmd
	github.com/johanix/tdns/tdns => ../tdns
	github.com/johanix/tdns/tdns/cache => ../tdns/cache
	github.com/johanix/tdns/tdns/cli => ../tdns/cli
	github.com/johanix/tdns/tdns/core => ../tdns/core
	github.com/johanix/tdns/tdns/edns0 => ../tdns/edns0
)

require (
	github.com/johanix/tdns/music v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/music/cmd v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/tdns v0.0.0-20251115235005-48e48cb765aa
	github.com/johanix/tdns/tdns/cli v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/c-bata/go-prompt v0.2.6 // indirect
	github.com/chzyer/logex v1.1.10 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/chzyer/test v0.0.0-20180213035817-a1ea475d72b1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.22.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gookit/goutil v0.6.15 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/johanix/tdns/tdns/cache v0.0.0-20251209183459-2d9962c12f9f // indirect
	github.com/johanix/tdns/tdns/core v0.0.0-20251122130747-9c54a3943883 // indirect
	github.com/johanix/tdns/tdns/edns0 v0.0.0-20251121102720-aa307d56701e // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-sqlite3 v1.14.16 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pkg/term v1.2.0-beta.2 // indirect
	github.com/quic-go/quic-go v0.57.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/ryanuber/columnize v2.1.2+incompatible // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/twotwotwo/sorts v0.0.0-20160814051341-bf5c1f2b8553 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/term v0.37.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	zgo.at/acidtab v1.1.0 // indirect
	zgo.at/runewidth v0.1.0 // indirect
	zgo.at/termtext v1.5.0 // indirect
)
