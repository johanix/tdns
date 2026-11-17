## tdns-cli auth zone delegation get

Show what this parent publishes for a child (or list its children)

### Synopsis

Report the delegation records the parent currently holds for a child zone,
grouped by owner name and type.

With no --child, list the children this parent has delegation data for -- the
question that comes first when reconciling an external store against the
server.

The answer comes from the zone's delegation backend, so it is what the SERVER
considers current. For a backend that records delegations somewhere other than
the served zone those differ deliberately, and reading the zone instead would
quietly give the wrong answer.

```
tdns-cli auth zone delegation get [flags]
```

### Options

```
      --child string   Child zone to report on; omit to list the parent's children
  -h, --help           help for get
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth zone delegation](tdns-cli_auth_zone_delegation.md)	 - Inspect the delegation data a parent zone holds for its children

