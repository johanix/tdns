## tdns-cli agent keystore dnssec bulk-convert

Convert DNSSEC keys written by bind9 or Cascade into a directory tdns can pre-load

### Synopsis

Convert bind9-generated DNSSEC keys in --dir into the form keystore.preload reads.

Two things stand between dnssec-keygen output and a pre-loadable directory: the
private half is in bind's own format rather than PKCS#8 PEM, and there is no
manifest, without which pre-load refuses the directory outright.

This rewrites each .private in place as PEM, keeping the original alongside as
.private.orig, and writes the manifest. The .key files are NOT touched: they
already hold the public RR in exactly the form tdns exports.

Key state comes from bind's .state file (9.16+, dnssec-policy zones), mapped
onto tdns's states. A key with no .state file has no state to read, and it is
not guessed -- pass --state to say which one applies. Guessing wrong is how a
retired key gets published again.

Runs entirely locally: no daemon, no API, no keystore. That is the point --
these directories are built and committed before the server that serves them
exists. Re-running is safe; already-converted keys are left alone.

--from cascade (DNSSEC only) converts the keys of zones signed by NLnet Labs'
Cascade, so a zone moves to tdns with the same keys and the parent's DS is left
as it is. Give each zone's dnst state file with --state-file (in Cascade's
keys-dir, <zone>.state) and a NEW directory with --dest: Cascade's files are
only read, never rewritten. The state file decides each key's tdns state, and
the conversion is refused unless the result reproduces the DNSKEY RRset and DS
set Cascade serves. A key roll in progress is refused unless
--allow-roll-in-progress; another signer's key in the DNSKEY RRset is refused
unless --multi-signer (the target is tdns-mpsigner, which takes such keys from
its incoming zone). See docs/2026-09-16-cascade-key-migration.md.

```
tdns-cli agent keystore dnssec bulk-convert [flags]
```

### Options

```
      --allow-roll-in-progress   Cascade: convert a zone with a key roll in progress (tdns does not continue the roll)
      --dest string              Cascade: new directory to write the converted keys and manifest to
      --dir string               Directory of bind9 key files to convert in place (--from bind)
      --from string              Signer that wrote the keys: bind or cascade (default "bind")
  -h, --help                     help for bulk-convert
      --keys-dir string          Cascade: where the key files are, when not beside the state file
      --multi-signer             Cascade: accept other signers' keys in the DNSKEY RRset; the target is tdns-mpsigner
      --no-backup                Do not keep the original bind-format key as .private.orig (--from bind)
      --state string             Key state for keys with no .state file (required only for those; --from bind)
      --state-file stringArray   Cascade: a zone's dnst state file, <keys-dir>/<zone>.state (repeatable)
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

* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

