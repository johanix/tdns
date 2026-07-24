# DNSSEC config restructure + per-role algorithm policy gating

Status legend: [done] landed on branch dnssec-config-restructure;
[next] not yet started; [merge] handled when merging into #257.

Branch: dnssec-config-restructure (off main @ f5dec38).
Target: merge into the #257 feature branch
imr-transport-selection-wip (NOT main) once the #257 enum is tested.


## Purpose

Two threads, executed together because they touch the same files:

1. Per-role KSK/ZSK algorithm support is usable but ungated: a policy
   could name any KSK algorithm with any ZSK algorithm. We add a
   deployment-wide allowlist for which mixed pairs are permitted.

2. The DNSSEC config had grown several top-level keys
   (dnssecpolicies:, kasp:, dnssec:). We consolidate everything under
   one dnssec: block and make the algorithm-naming and error-handling
   consistent and resilient.

The guiding principle throughout: the server must START even with
config errors. A bad policy or zone is quarantined with a visible
error, never fatal. See
2026-06-16 note in the resilient-startup memory; the same rule already
governs zones (Zone.Errors, visible in `auth zone list`).


## Decisions (and why)

- **Nest under dnssec:** — dnssecpolicies: -> dnssec.policies:, and
  kasp: -> dnssec.kasp:. Config-breaking, acceptable under the
  no-backwards-compat rule (operator migrates own config). The
  split_algorithms / large_algorithms guardrails were already under
  dnssec:; this puts the policies and KASP there too, so DNSSEC config
  is one block.

- **Keep the name large_algorithms (do NOT rename)** — an earlier idea
  was to rename it (e.g. large_dnskey_hints) because the name reads as
  "large KSK" when it is really an IMR transport-decision input. PR
  #257's transport-selection design resolves this differently and
  better: the field stays, and becomes ONE input among several
  transport-selection policy values. Its design doc states plainly:
  "The dnssec.large_algorithms list stays (it is what use_ds_signal
  consults)." Renaming now would fight the direction we are merging
  into. So: keep the name.

- **Algorithm NAMES, not codepoints, in config** — both
  large_algorithms and split_algorithms list algorithms by name
  (RSASHA512, FALCON512), resolved through the running binary's
  registry. Two reasons this is load-bearing, not cosmetic:
    1. Codepoints structurally defeat validation. A bare uint8 dropped
       into a lookup map is never checked against the registry, so
       "reject unknown algorithm" is impossible with codepoints. Names
       route through dns.StringToAlgorithm, which is where the check
       lives.
    2. Non-standardized PQ codepoints are assigned per deployment at
       runtime by algorithms.Register (e.g. an auth+liboqs build gives
       FALCON512 = 201). A bare [201] could mean different algorithms
       on the IMR and the signer — a silent, dangerous mismatch. A name
       resolves through each binary's own registry: consistent, or a
       loud failure.

- **Unknown-algorithm handling differs by site** ("hard fail only
  where used"):
    - large_algorithms: unknown name -> HARD config error, server
      refuses to start. It actively drives the IMR's transport
      decision, so a typo must not silently disable TCP.
    - split_algorithms: unknown name -> WARN + skip. Pure allowlist
      data; an unregistered algorithm can never be requested, so a
      missing entry is harmless. (Runtime-only: registration is known
      only inside the daemon.)
    - policy algorithm: / ksk.algorithm: / zsk.algorithm: unknown ->
      the POLICY gets an error state (it is kept, marked broken). The
      server still starts; zones referencing it are quarantined.

- **Broken policies carry an Error field, kept in the one map** — a
  rejected policy is NOT dropped from Internal.DnssecPolicies; it is
  stored there with Name + Error set (other fields possibly
  incomplete). Rationale: one map is the single source of truth, so
  the `keystore dnssec policies` listing ranges one map and sees every
  policy — healthy or broken — with its status, instead of unioning a
  separate errors map and risking dropping a broken one. Mirrors the
  zone-error pattern.

- **Zone propagation distinguishes missing vs broken** — a zone
  referencing a policy that does not exist gets "DNSSEC policy %q does
  not exist"; one referencing a broken policy gets "configured DNSSEC
  policy %q is broken: <reason>". The operator can tell a typo from a
  genuinely broken policy.

- **A broken `default` stays broken** — not silently replaced by the
  builtin default. We surface the operator's error rather than
  papering over it.

- **The policies CLI is server-API only** — no offline mode. The thing
  worth verifying is whether an algorithm name is actually REGISTERED
  in THIS server binary, which is unknowable offline (registration is
  a runtime, per-build-tag property). The existing
  `keystore dnssec policy validate -f file` remains an offline
  syntax/structure check only; it cannot verify algorithm
  availability, and its help must say so (it is not a full checkconf).


## New config shape

    dnssec:
       # IMR: DNSKEY-over-non-UDP when a referral DS uses one of these.
       # Names, not codepoints. Unknown name = hard config error.
       large_algorithms: [ RSASHA512 ]

       # Which mixed KSK/ZSK algorithm pairs a policy may use.
       # kskAlg -> permitted zskAlgs. Same-alg policies always pass.
       # Differing pair must be listed or the policy is rejected.
       split_algorithms:
          RSASHA512: [ ED25519, ECDSAP256SHA256 ]

       # Named policies a zone references via dnssec_policy.
       policies:
          default:   { ... }
          fastroll:  { ... }

       # Key and Signing Policy for the KeyStateWorker.
       kasp:
          propagation_delay: 1h
          standby_zsk_count: 1


## Steps

1. [done] **Config restructure.** dnssec.policies: + dnssec.kasp:;
   removed top-level Config.DnssecPolicies and Config.Kasp; all
   conf.Kasp.* -> conf.Dnssec.Kasp.*; offline validators
   (dnssecPoliciesYAML, minimalConfigForValidate) moved policies under
   dnssec:. Samples migrated (auth, agent). Commit 491bb05.

2. [done] **split_algorithms gate (fail closed).** New
   dnssec.split_algorithms allowlist; validateSplitAlgorithm rejects a
   mixed pair not listed; same-alg always passes. Wired into runtime
   load, ParseDnssecPolicyConf, and the offline validator. Also fixed
   the automated KSK-rollover pipeline-fill bug (was generating rolled
   KSKs with pol.Algorithm instead of pol.KSKAlgorithm). Commit
   491bb05.

3. [done] **large_algorithms -> names + hard-fail.** Field is now
   []string; buildLargeAlgorithmSet resolves via the registry and
   returns an error on an unknown name; ParseConfig propagates it.
   Samples (auth/imr/agent) updated to names. Commit 3dc9909.

4. [done] **Broken-policy error state + zone propagation.**
   DnssecPolicy.Error field; markBroken closure keeps a rejected policy
   in the map; resolveZonePolicyRef quarantines zones with a
   missing/broken-distinct message. Fixed the empty-%q bug and the
   stray "policy accepted" log. Commit 39c3fd8.

   (The originally-separate "unknown-alg semantics" step folded in
   here: split_algorithms warn+skip and policy-error-state were already
   the behavior; this step added the visible error record.)

5. [done] **CLI `tdns-cli auth keystore dnssec policies`.** Server-API
   command (mirrors `keystore dnssec algorithms`): queries the running
   daemon (Command:"list-policies"), renders a table of all policies;
   broken ones show STATUS=ERROR with the reason listed below the table
   (kept out of the tab columns so a long reason doesn't stretch them).
   New wire type DnssecPolicyInfo + DnssecPolicyToInfo projection (algs
   as names, lifetimes as strings, "forever"/"none" rendered).
   RolloverMethod.String() added. Server handler case in APIkeystore
   ranges conf.Internal.DnssecPolicies. CLI in cli/policies.go.
   LIVE-VERIFIED against a modern auth server: default/fastroll healthy,
   large-ksk (RSASHA512 KSK + ED25519 ZSK) ok via split_algorithms, a
   "broken" policy (alg FOOBAR) shows ERROR + reason, server started
   regardless (resilient startup confirmed end-to-end).

6. [next] **Docs + samples.** Finalize this doc; ensure the validate
   command help states it cannot verify algorithm availability.

7. [merge] **Merge into #257 (imr-transport-selection-wip).** With
   explicit operator approval. Reconcile the overlapping files: convert
   #257's `large_algorithms: [ 10 ]` sample to names; settle the metric
   rename (#257 renames DNSKEYLookupForcedTCP -> DNSKEYLookupBypassed);
   adopt #257's enum vocabulary where the two diffs touch the same
   hunks (config.go DnssecConf/InternalConf, parseconfig.go around the
   buildLargeAlgorithmSet call, large_ksk.go, large_ksk_test.go).


## Key files

- v2/config.go — DnssecConf (large_algorithms []string, split_algorithms,
  policies, kasp), InternalConf.
- v2/structs.go — DnssecPolicy (Error field), DnssecPolicyConf.
- v2/large_ksk.go — buildLargeAlgorithmSet (names, hard-fail),
  buildSplitAlgorithmSet (warn+skip), validateSplitAlgorithm,
  resolvePolicyRoleAlgorithms.
- v2/parseconfig.go — policy parse loop (markBroken), ParseZones policy
  ref check (resolveZonePolicyRef).
- v2/ksk_rollover_policy.go — ParseDnssecPolicyConf,
  ValidateDnssecPoliciesFromFile, dnssecPoliciesYAML root.
- v2/large_ksk_test.go — gate, hard-fail, and zone-ref tests.
- Samples: cmdv2/auth/tdns-auth.sample.yaml,
  cmdv2/imr/tdns-imr.sample.yaml, cmdv2/agent/tdns-agent.sample.yaml.
- Related design: 2026-05-21-large-ksk-distinct-algs-and-imr-tcp-signal.md
  (A.3.9 documents the split_algorithms gate).
