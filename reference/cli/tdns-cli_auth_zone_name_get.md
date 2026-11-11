## tdns-cli auth zone name get

Show the RRsets this zone holds at one name

### Synopsis

Report the RRsets the zone currently publishes at one owner name, grouped by
type, in presentation format.

Reports the PUBLISHED view, not staged data: the question is what the server
serves, and an update still in flight is not yet an answer to it.

A name with nothing at it is an empty report, not an error -- that is what
provisioning a name for the first time returns, and it has to be
distinguishable from a read that failed. A name outside the zone IS an error,
because answering "nothing" there reads as "that name has no records".

RRSIG, NSEC, NSEC3, NSEC3PARAM and ZONEMD are never reported. They are the
signer's and the zone policy's, and returning them would invite a
read-modify-write that tries to author them.

```
tdns-cli auth zone name get [flags]
```

### Options

```
  -h, --help          help for get
      --name string   Owner name to report on (required; must be inside the zone)
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

* [tdns-cli auth zone name](tdns-cli_auth_zone_name.md)	 - Inspect what a zone publishes at a single owner name

