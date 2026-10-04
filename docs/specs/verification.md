# Cairn v2 — Verification Engine Spec

Cairn v2 is the independent verifier downstream of Strix. Strix hunts and
emits findings **with PoCs**; Cairn ingests each finding as an **untrusted
claim**, stands the target up in a sandbox, executes the PoC, **independently
observes the effect**, and emits a verdict with replayable evidence.

```
Ingest ─► Bring-up ─► Execute ─► Observe (oracle) ─► Verdict
(untrusted)  (auto)              (effect, not echo)
```

The engine stays domain-agnostic: oracles and bring-up strategies are
pluggable packs. The core knows only Facts / Intents / Hints and a sandbox.
There is **no fourth primitive** — a claim is a Fact, a verdict is a Fact,
steering is a Hint.

## Lifecycle

1. **Ingest** (`POST /claims`). A Strix finding JSON is validated as a typed
   `ClaimPayload` (`cairn/server/claims.py`): strict fields, capped sizes,
   PoC as a `script | http | command` union. The claim becomes a project:
   - *origin fact* — the claim rendering. It carries repo, commit, class,
     and the **sealed** PoC digest (`sha256:…`). It never carries the PoC
     payload or the contents of Strix's claimed oracle.
   - *goal fact* — the verification contract: `reproduced |
     not_reproduced | inconclusive (+sub_reason)` backed by a
     Cairn-controlled marker observed out-of-band.
   - `run_hints` become real Hint rows (steering is a Hint).
   - The full validated claim JSON is persisted in the `claims` table for
     execution, audit, and export — payloads stay sealed away from the
     board. Verification projects do **not** run the generic bootstrap task;
     their first intents come from the verification pipeline.
2. **Bring-up** *(planned, Phase 2)* — discovery worker reads the pinned
   checkout, ranks boot strategies (compose → Dockerfile → make → bin/* →
   README), boots in the sandbox, records the live endpoint as a Fact.
3. **Execute** *(planned, Phase 3)* — the claim's PoC runs against the live
   endpoint from inside the sandbox. A PoC that errors before reaching the
   target is `POC_ERROR` (inconclusive), *not* `not_reproduced`.
4. **Observe** *(planned, Phase 4)* — the oracle pack plants an unforgeable
   runtime marker (a fresh nonce, chosen post-boot, never reused) and
   watches the collector for it.
5. **Verdict** *(planned, Phase 5)* — terminal Fact: `reproduced` only when
   the marker fired; `not_reproduced` when booted + PoC ran clean + marker
   never fired within bounds; otherwise `inconclusive` with a sub-reason
   (`BRING_UP_FAILED | POC_ERROR | ORACLE_AMBIGUOUS | BUDGET_EXHAUSTED`).
   Default is inconclusive; a false `reproduced` is the worst failure mode.
6. **Handback** *(planned, Phase 5.5)* — non-`reproduced` terminals are
   handed back to Strix shaped by the sub-reason, with the replay manifest
   so Strix retries against the identical environment.

## Effect, not echo

Cairn **never trusts a success signal from Strix**. The claim records
`strix_claimed_oracle` verbatim for audit, but:

- it is never rendered onto the board,
- verdict logic is forbidden from reading it as proof,
- the only signal that can upgrade a claim to `reproduced` is a
  Cairn-chosen marker (nonce) observed on the Cairn-controlled collector.

## Sandbox (Phase 1 — implemented)

Attacker-authored code from claims executes **only** inside the sandbox.
Containment is **Docker-native** (an agreed deviation from the original
plan sketch of hand-rolled Landlock/seccomp — the same kernel primitives,
orchestrated by the Docker daemon the dispatcher already drives):

| Invariant | Mechanism |
|---|---|
| no egress except the collector | per-run **internal** Docker network (`cairn-sbxnet-<run>`, no external route); collector is the only peer worth reaching |
| no writes outside scratch | read-only rootfs; `/scratch` bind mount is the single writable path and doubles as the evidence directory |
| resource-capped | cgroup `mem_limit`, `pids_limit`, `nano_cpus`; `cap_drop=ALL`; `no-new-privileges`; uid 65534 |

Components (`cairn/sandbox/`):

- `SandboxManager` — networks, collector lifecycle, payload execution,
  teardown-by-run-id, nonce observation (`wait_for_nonce`).
- **Collector** — the only permitted egress: a stdlib-only HTTP service
  attached to each run network under the alias `collector`. Every request
  is recorded as a JSONL hit (`ts`, `method`, `path`, `src`) to a
  bind-mounted evidence file the dispatcher reads. `/healthz` is excluded
  from nonce matching.
- Payload containers are anonymous, ephemeral, and labeled
  `cairn.sandbox.run=<run_id>` for teardown.

Run composition: **sandbox network = target + collector + payload**. The
target (Phase 2) attaches with `SandboxManager.attach`; from inside, the
world is exactly the target and the collector.

### Threat model notes

- The claim is untrusted input end to end: schema-validated, size-capped,
  unknown fields rejected.
- The PoC payload is sealed (digest on the board; full payload only in the
  claims table, never in exported reports — hashes only).
- Targets boot pinned to the claimed commit; a verdict against the wrong
  version is meaningless.
- Bring-up must use the project's own default/playground config; real
  secrets never enter a sandboxed target.
- Docker networking provides the egress boundary; DNS inside the run
  network resolves only its own members. No host publishing, no gateway
  route on internal networks.
- The dispatcher host's Docker socket is the trust anchor; sandbox
  containers never get access to it (no socket bind, caps dropped).

### Testing

- `tests/test_sandbox_unit.py` — Docker-free: archive building, hit
  parsing, nonce matching, config, path/naming logic.
- `tests/test_sandbox_hostile.py` — real containers, opt-in via
  `CAIRN_SANDBOX_INTEGRATION=1`: hostile payloads attempt external egress,
  cross-network reach, filesystem escapes, fork bombs, memory exhaustion,
  and capability abuse — all contained. Requires `python:3.13-slim`.

## Configuration (dispatcher integration — Phase 3)

`SandboxConfig` (`cairn/sandbox/config.py`) holds the knobs (`image`,
`collector_image`, `mem_mb`, `pids_limit`, `cpus`, timeouts, scratch/hits
roots). The dispatcher will gain a `sandbox:` section in `dispatch.yaml`
when the `execute` task type lands; until then the manager is usable as a
library.

## Status

- Phase 0 — claim ingestion: **done** (`POST /claims`, sealed PoCs,
  claims table, 16 tests).
- Phase 1 — sandbox core: **done** (internal networks, contained payload
  execution, nonce collector, 10 unit + 5 hostile container tests).
- Phases 2–8 — planned per `plan.md` (bring-up discovery, PoC harness,
  oracle pack, verdict + evidence, handback, budgets, console, auto mode).
