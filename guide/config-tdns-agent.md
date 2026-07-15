# tdns-agent configuration

> **Placeholder.** This page is not yet written. The agent's proxy
> configurations in particular still need documenting.

`tdns-agent` is the single-provider agent for delegation synchronization. It
shares most of its configuration surface with `tdns-auth` — the same `service:`,
`dnsengine:`, `apiserver:`, `db:` and `log:` blocks, validated the same way — so
[tdns-auth configuration](config-tdns-auth.md) is the right starting point
today.

Two differences are worth knowing now:

- **The agent does not sign.** The `online-signing` and `inline-signing` zone
  options are rejected for `tdns-agent`, and a zone template's `dnssecpolicy:`
  is not inherited by agent zones.

- **The agent can proxy delegation sync** on behalf of a DSYNC-unaware primary
  (BIND, Knot, NSD) with the `delegation-sync-proxy` zone option. That path is
  already documented, as an operator how-to, in
  [Agent as a DSYNC proxy](agent-dsync-proxy.md).

## Still to document

- The `delegationsync:` block: `parent.schemes`, `parent.notify.*`,
  `parent.update.*` (including `{ZONENAME}` target substitution and the
  key-verification knobs), `child.schemes`, `child.update.keygen.*`.
- The proxy configurations: which combinations of NOTIFY and signed DNS UPDATE
  are supported toward the parent, and how the agent chooses between them.
- `apiserver.agent` and `apiserver.combiner` sub-blocks for multi-app
  deployments.
- The `keystate.*` and `verifyengine.*` key-bootstrap knobs.
