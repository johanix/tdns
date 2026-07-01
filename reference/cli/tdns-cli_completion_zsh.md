## tdns-cli completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(tdns-cli completion zsh)

To load completions for every new session, execute once:

#### Linux:

	tdns-cli completion zsh > "${fpath[1]}/_tdns-cli"

#### macOS:

	tdns-cli completion zsh > $(brew --prefix)/share/zsh/site-functions/_tdns-cli

You will need to start a new shell for this setup to take effect.


```
tdns-cli completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

