# ADR 0052: Controlled PIDs CREATE observations

Status: accepted test-source contract; complete and fresh native qualification remain required.

## Context

Native run 41309338424 at exact candidate 7dce5174 reproduced explicit-null PidsLimit on both
owned rendered/API Unlimited CREATE controls. The preceding finite controls passed. Historical
run 41297794023 at f45327b reproduced that readback on both CLI Unlimited controls. Neither
run reached PIDs effect measurement; neither establishes enforcement or admission.

Exact source review establishes intentional CREATE normalization in both reviewed Engines.
Moby `docker-v29.8.1`, commit `464cd50c3d9e92877d56940ea160de6fca7bea23`, clears nonpositive
PidsLimit pointers before backend creation in its [CREATE route](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/server/router/container/container_routes.go#L772).
Exact Debian `docker.io 20.10.5+dfsg1-1+deb11u2` does the same in its
[packaged CREATE route](https://sources.debian.org/src/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/api/server/router/container/container_routes.go/#L515),
whose relevant source matches Moby `363e9a88a11be517d9e8c65c998ff56f774eb4dc`.
Inspect exposes HostConfig, and the nullable pointer has no omission tag, producing explicit
JSON null. UPDATE has a different pointer-to-zero contract and is outside this decision.
Unsupported-controller handling can also clear a supplied pointer: null alone establishes
neither authorship nor enforcement.

## Decision

Amend only the controlled CREATE readback and nested acquisition representation in ADRs
[0041](0041-original-owner-pids-experiment.md) and
[0044](0044-typed-pids-source-and-proof-v2.md):

1. Both identity-bound, independently authored Unlimited CREATE slots continue to request
   numeric -1 in CLI argv and the complete literal/renderer comparison. Their configured
   readback requires the PidsLimit member to be explicitly present and null. Finite 16/64
   remain present exact integers. Missing, other sentinels/types, foreign identities and every
   other configuration mismatch refuse. The closed witness uses that same predicate.
2. Actual read-only acquisition retains finite Present/16 or Present/64 and Unlimited-slot
   Null/no value, all Effective. Exact six bound IDs, uniqueness, identity availability/origin
   and per-ID value correlation are mandatory. Never replace observed null with authored -1.
   The public decoder, its Missing/Null distinction and its handling of raw numeric sentinels
   remain unchanged; no general unknown source is interpreted as unlimited intent.
3. Keep outer private schema 2/`pids-v2`, filename and root/worker/controller wire-v1. Only
   `measured.decoded` gains schema_version 2 and contract `pids-create-observations-v2`. Its
   closed `observations` map is keyed by the six owned IDs. Every row has exactly availability,
   value and origin: present/16/effective, present/64/effective, or null/JSON-null/effective.
   The independent Python reader verifies exact keys, discriminator, types, ID set and values
   against canonical owned case definitions. Unknown, missing, stale numeric and mixed
   representations refuse. Historical records retain their original bytes and candidate SHA;
   they are not relabelled or silently upgraded to this contract.
4. Authored request definitions remain separate from those acquisition observations. All actual
   finite EAGAIN/local-event attribution, 64/unlimited controls, reuse, ancestor/headroom,
   thread/custody checks, measurements, 32 invocation ordering, budgets, deadlines, cleanup
   authority and independent rereading remain unchanged. Null does not discharge any kernel
   effect or destination obligation. No capability/catalogue/publication admission follows.

## Provenance and ownership

Source review used read-only GitHub commit/Contents API queries, including
`gh api repos/moby/moby/git/ref/tags/docker-v29.8.1` and
`gh api repos/moby/moby/contents/daemon/server/router/container/container_routes.go?ref=464cd50c3d9e92877d56940ea160de6fca7bea23`,
and exact-version `sources.debian.org/data/main/d/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/`
GETs for the route, inspect/type and license files. Source URLs/line anchors above identify the
reviewed versions; corresponding inspect/type references are
[Moby inspect](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/inspect.go#L80),
[Moby type](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/api/types/container/hostconfig.go#L397),
[Debian inspect](https://sources.debian.org/src/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/daemon/inspect.go/#L129)
and [Debian type](https://sources.debian.org/src/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/api/types/container/host_config.go/#L370).
Both Engine sources are Apache-2.0; the independently verified LICENSE SHA-256 is
`7c87873291f289713ac5df48b1f2010eb6963752bbd6b530416ab99fc37914a8`.
No external oracle code is copied, translated into implementation or redistributed. Private
research copies and immutable source hashes support the semantic review only.

Renovate no-change evidence: this changes test-source expectations/private observation data and
docs only. Existing Cargo/lockfile/toolchain, runtime image pins, workflow/transport definitions,
native source keys and registries are unchanged. `renovate.json` continues to own Cargo,
GitHub Actions, toolchain and native-image updates at their existing paths; no software pin,
operational consumer, extraction/grouping/approval rule or new manager is added or moved.

## Verification

Require all-six positive/refusal controls, missing versus null, finite uncertainty, identity
mismatches/duplicates, outbound-minus-one versus readback separation, honest decoder states and
strict nested reader version/key/type refusal. Original effect/custody/cleanup validation must
remain byte-identical. Complete primary and independent gates, then fresh exact-candidate native
qualification remain separate requirements; focused or synthetic checks prove no native support.
