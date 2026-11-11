## tdns-cli agent keystore sig0 bulk-convert

Convert a directory of bind9 SIG(0) keys into one tdns can pre-load

### Synopsis

Convert bind9-generated SIG(0) keys in --dir into the form keystore.preload reads.

Two things stand between dnssec-keygen output and a pre-loadable directory: the
private half is in bind's own format rather than PKCS#8 PEM, and there is no
manifest, without which pre-load refuses the directory outright.

This rewrites each .private in place as PEM, keeping the original alongside as
.private.orig, and writes the manifest. The .key files are NOT touched: they
already hold the public RR in exactly the form tdns exports.

SIG(0) keys are not managed by dnssec-policy, so there is no key state to
read: a .state file beside a key is ignored. --state names the state that
every key the run converts gets: created, published, active or retired. It is
required whenever there is a key to convert, because it is not guessed:
guessing wrong is how a retired key gets published again.

Runs entirely locally: no daemon, no API, no keystore. That is the point --
these directories are built and committed before the server that serves them
exists. Re-running is safe; already-converted keys are left alone.

```
tdns-cli agent keystore sig0 bulk-convert [flags]
```

### Options

```
      --dir string     Directory of bind9 key files to convert in place
  -h, --help           help for bulk-convert
      --no-backup      Do not keep the original bind-format key as .private.orig
      --state string   Key state for every key converted: created, published, active or retired (required)
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

* [tdns-cli agent keystore sig0](tdns-cli_agent_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

