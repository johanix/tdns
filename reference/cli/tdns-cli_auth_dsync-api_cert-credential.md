## tdns-cli auth dsync-api cert-credential

Manage DSYNC API certificate credentials

### Synopsis

Create, list, disable and delete client-certificate credentials for the DSYNC
API listener. These travel on the management API with the operator key, the
same socket as "credential".

  tdns-cli auth dsync-api cert-credential add \
      --zone example. --mech tls-pkix --identity child1.example. \
      --principal child1.example.

  tdns-cli auth dsync-api cert-credential add \
      --zone example. --mech tls-pin --cert /path/to/child.crt \
      --principal child1.example.

"list" shows both bearer and certificate credentials (one table). Bearer rows
display as mechanism "basic".

### Options

```
  -h, --help   help for cert-credential
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

* [tdns-cli auth dsync-api](tdns-cli_auth_dsync-api.md)	 - Manage the DSYNC API scheme
* [tdns-cli auth dsync-api cert-credential add](tdns-cli_auth_dsync-api_cert-credential_add.md)	 - Issue a certificate credential for one identity of one parent zone
* [tdns-cli auth dsync-api cert-credential delete](tdns-cli_auth_dsync-api_cert-credential_delete.md)	 - Delete a certificate credential outright
* [tdns-cli auth dsync-api cert-credential disable](tdns-cli_auth_dsync-api_cert-credential_disable.md)	 - Stop a certificate credential working, keeping its record
* [tdns-cli auth dsync-api cert-credential enable](tdns-cli_auth_dsync-api_cert-credential_enable.md)	 - Re-enable a disabled certificate credential
* [tdns-cli auth dsync-api cert-credential list](tdns-cli_auth_dsync-api_cert-credential_list.md)	 - List credentials, for one parent zone or for all (bearer and certificate)

