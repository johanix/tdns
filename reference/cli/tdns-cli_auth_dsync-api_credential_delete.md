## tdns-cli auth dsync-api credential delete

Delete a credential outright

### Synopsis

Remove the credential and its row. Prefer "disable" when the question "who had
access, and when" might be asked later: disabling stops the credential working
and keeps the record.

```
tdns-cli auth dsync-api credential delete [flags]
```

### Options

```
  -h, --help          help for delete
  -u, --user string   Username (required)
  -z, --zone string   Parent zone the credential is scoped to
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

