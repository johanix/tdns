## tdns-cli imr show-cmds

List the whole command tree below this command, one line per command

### Synopsis

List every command below this point in the tree, one per line, as a
full invocation path.

Unlike -h, which only shows the immediate children of one command, this
walks the entire subtree, so the output is greppable and every line can be
copied and run as-is.

show-cmds exists on every command that has subcommands, but is only listed
in -h at the top level and under each application prefix; deeper down it is
hidden to keep the help screens clean. It still works there, e.g.
"tdns-cli auth keystore dnssec show-cmds".

```
tdns-cli imr show-cmds [flags]
```

### Options

```
      --all         also list hidden and deprecated commands
      --depth int   only descend N levels below this command (0 = no limit)
      --desc        append each command's short description, column-aligned
  -h, --help        help for show-cmds
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli imr](tdns-cli_imr.md)	 - Interact with tdns-imr via API

