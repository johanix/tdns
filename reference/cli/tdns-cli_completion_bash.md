## tdns-cli completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(tdns-cli completion bash)

To load completions for every new session, execute once:

#### Linux:

	tdns-cli completion bash > /etc/bash_completion.d/tdns-cli

#### macOS:

	tdns-cli completion bash > $(brew --prefix)/etc/bash_completion.d/tdns-cli

You will need to start a new shell for this setup to take effect.


```
tdns-cli completion bash
```

### Options

```
  -h, --help              help for bash
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

