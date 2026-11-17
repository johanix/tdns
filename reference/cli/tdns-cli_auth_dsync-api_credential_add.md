## tdns-cli auth dsync-api credential add

Issue a credential for one child of one parent zone

### Synopsis

Create a <username, key> credential. The key is generated here, shown once, and
stored only as a hash -- there is no way to retrieve it afterwards. If it is
lost, delete the credential and issue another.

The username identifies the principal that the parent zone's updatepolicy.child
is evaluated against, exactly where the SIG(0) signer name goes on the DDNS
path. Name it after the child zone and the policy needs no explanation:

  tdns-cli auth dsync-api credential add --zone example. --user child1.example.

With updatepolicy.child.type "selfsub", that credential may change the allowed
RR types at or below child1.example. and nowhere else.

Use --principal when the account should have a human-readable name:

  tdns-cli auth dsync-api credential add --zone example. \
      --user acme-registrar --principal child1.example.

```
tdns-cli auth dsync-api credential add [flags]
```

### Options

```
      --comment string     Free-text note stored with the credential
      --expires string     Expiry as a duration ("720h") or RFC3339 timestamp; default: never
  -h, --help               help for add
      --principal string   DNS name the update policy is evaluated against (default: the username)
  -u, --user string        Username (required)
  -z, --zone string        Parent zone the credential is scoped to
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth dsync-api credential](tdns-cli_auth_dsync-api_credential.md)	 - Manage DSYNC API credentials

