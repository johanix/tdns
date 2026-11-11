## tdns-cli auth dsync-api

Manage the DSYNC API scheme

### Synopsis

Operator commands for the DSYNC API scheme: the HTTPS channel a child uses to
change its delegation when it cannot sign a DNS message and therefore cannot
use the DSYNC UPDATE scheme.

These commands travel on the management API and require the operator API key.
The credentials they issue authenticate somewhere else entirely -- the DSYNC
API listener -- and every one of them is confined by the parent zone's
updatepolicy.child.

### Options

```
  -h, --help   help for dsync-api
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth dsync-api cert-credential](tdns-cli_auth_dsync-api_cert-credential.md)	 - Manage DSYNC API certificate credentials
* [tdns-cli auth dsync-api credential](tdns-cli_auth_dsync-api_credential.md)	 - Manage DSYNC API credentials

