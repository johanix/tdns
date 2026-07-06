## tdns-cli completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	tdns-cli completion fish | source

To load completions for every new session, execute once:

	tdns-cli completion fish > ~/.config/fish/completions/tdns-cli.fish

You will need to start a new shell for this setup to take effect.


```
tdns-cli completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli completion](tdns-cli_completion.md)	 - Generate the autocompletion script for the specified shell

