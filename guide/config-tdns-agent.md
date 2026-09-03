# tdns-agent configuration

> **Partial.** Only the `delegationsync:` block is documented here in full.
> Everything else the agent shares with `tdns-auth`, and is covered there; the
> gaps specific to this page are listed at the end.

`tdns-agent` is the single-provider agent for delegation synchronization. It
shares most of its configuration surface with `tdns-auth` — the same `service:`,
`listeners:`, `apiserver:`, `db:` and `log:` blocks, validated the same way — so
[tdns-auth configuration](config-tdns-auth.md) is the right starting point
today.

Two differences are worth knowing now:

- **The agent does not sign.** The `online-signing` and `inline-signing` zone
  options are rejected for `tdns-agent`, and a zone template's `dnssecpolicy:`
  is not inherited by agent zones.

- **The agent can proxy delegation sync** on behalf of a DSYNC-unaware primary
  (BIND, Knot, NSD) with the `parentsync-proxy` zone option. That path is
  already documented, as an operator how-to, in
  [Agent as a DSYNC proxy](agent-dsync-proxy.md).

## The `delegationsync:` block

On an agent this block is **child-side only**. `tdns-agent` is never a
delegation-sync parent, so nothing here ever verifies a child's key or publishes
a bootstrap advertisement: `policies:`, `parent:` and the per-zone
`delegationpolicy:` reference that selects a policy all belong on the tdns-auth
parent ([special-features 1.1](special-features.md#11-parent-publishing-dsync)).

Carrying them anyway is harmless but not free of consequence. They are still
*parsed*, so the two failure modes still apply on an agent: an unknown token
under `policies:` makes the daemon refuse to start, and a zone whose
`delegationpolicy:` names a policy that does not exist is quarantined — for a
policy that would never have been consulted.

What the agent does read:

```yaml
delegationsync:
   child:
      # Transports to try toward the parent, in preference order. The parent
      # must advertise the scheme in its DSYNC RRset for it to be used.
      schemes: [ notify, update ]
      update:
         keygen:
            algorithm: ED25519
         bootstrap:
            methods: [ at-apex, at-ns ]
         # allow-insecure: true   # lab only; see below
```

| Key | Meaning |
|-----|---------|
| `child.schemes` | which transports to try: `notify`, `update`, `api`. **Empty means nothing is ever forwarded** |
| `child.update.keygen.algorithm` | algorithm for the SIG(0) keypair the agent signs UPDATEs with |
| `child.update.bootstrap.methods` | SIG(0) bootstrap methods this agent will let a parent use; intersected with the parent's advertisement. Omitted means `[ at-apex, at-ns ]` |
| `child.update.allow-insecure` | act on parent-derived input that cannot be authenticated (an unsigned KeyState response, an unvalidated SVCB advertisement). **Lab only.** Never waives a *bogus* DNSSEC verdict |
| `child.api.*` | credentials for the HTTPS API scheme, one per parent |

`at-ns` is in the omitted default but is filtered out for every zone this agent
proxies for: it needs the child's KEY at `_sig0key.<child>._signal.<ns>`, and
those names live in the nameserver's zone. Listing it therefore costs a proxy
zone nothing.

**`child.schemes` governs the proxy too, and this is the trap.** A zone with
`parentsync-proxy` sends to the parent *as the child*, so it walks the same
plan a delegation-sync child does and reads the same setting. With `schemes:`
empty, every transport is skipped — and the zone is not quarantined. It loads,
serves, and forwards nothing, so the only symptom is silence.
`tdns-cli agent config check` fails on exactly this, and the config written by
`tdns-cli agent config mwe` sets the block for you.

`{ZONENAME}` substitution and the `parent.*` subtree are documented with the
parent side, in [tdns-auth configuration](config-tdns-auth.md) and
[special-features 1.1](special-features.md#11-parent-publishing-dsync). The
method negotiation — how the agent's `methods:` list is intersected with what
the parent advertises, and why the default is `[ at-apex ]` alone — is in
[special-features 1.5](special-features.md#15-child-pushing-changes).

## Still to document

- The proxy configurations: which combinations of NOTIFY and signed DNS UPDATE
  are supported toward the parent, and how the agent chooses between them.
- `apiserver.agent` and `apiserver.combiner` sub-blocks for multi-app
  deployments.
