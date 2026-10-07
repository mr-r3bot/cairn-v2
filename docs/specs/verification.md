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

All phases implemented and tested (see `cairn/tests/`):

- Phase 0 — claim ingestion: **done** (`POST /claims`, sealed PoCs, claims
  table). 
- Phase 1 — sandbox core: **done** (internal networks, contained payload
  execution, nonce collector; hostile container suite proves the three
  invariants).
- Phase 2 — bring-up auto-discovery: **done** (ranked strategies: prebuilt
  image, compose, Dockerfile executed through socket-driving helper
  containers; make/script/README detected and recorded as dead-ends; health
  probing on the run network; `target` alias pinned to the answering
  service).
- Phase 3 — PoC execution harness: **done** (script/http/command PoCs run
  inside the sandbox; rc≠0 or timeout = `POC_ERROR`, never
  `not_reproduced`).
- Phase 4 — effect oracles: **done** (`rce/nonce-callback` and
  `ssrf/nonce-callback` via `CAIRN_CMD`/`CAIRN_URL` instrumentation hooks;
  `sqli/seeded-row` and `sentinel/planted-file` via `run_hints` hooks;
  everything else leans `ambiguous`).
- Phase 5 — verdict + evidence: **done** (conservative decision table;
  server-side guardrail: `reproduced` without a marker is rejected,
  exactly one terminal per project; replayable evidence bundle).
- Phase 5.5 — Strix handback: **done** (shaped by sub-reason, carries the
  replay manifest; `GET /projects/{id}/handback`, `GET /claims/{id}/handback`).
- Phase 6 — budgets + stop conditions: **done** (wall-clock/steps/payload-
  runs/cost ledger; stall detection; runs always terminate).
- Phase 7 — console + export: **done** (`/verify` worklist + run console,
  hint box as the only write surface; report / badge / exit-code /
  evidence exporters). The console also **ingests claims** (guided form +
  raw JSON → `POST /claims`): creating a new run is a public-API write,
  distinct from the mid-run single-writer surface, so operators never
  need curl to start a verification.
- Phase 8 — full-auto: **done** (`cairn auto --claim …`, sandbox guard,
  exit codes 1/0/2).

End-to-end tests (`test_verification_e2e.py`, real Docker) cover the five
terminal outcomes against compose- and Dockerfile-shipping fixture targets:
`reproduced` (nonce observed out-of-band), `not_reproduced`, `POC_ERROR`,
`BRING_UP_FAILED`, `BUDGET_EXHAUSTED`.

## Oracle contracts for PoC authors (Strix side)

Effect-not-echo requires the PoC to be *parameterisable* — the oracle
chooses the payload of the proof:

- **rce / deserialization** — the PoC must execute the command in the
  `CAIRN_CMD` environment variable on the target (this is the "attacker
  command" the claimed RCE executes). Cairn sets it to a nonce beacon.
- **ssrf** — the PoC must fetch the URL in `CAIRN_URL` through the target.
- **sqli** — optional hooks: `run_hints.seed_command` runs inside the
  target container with `{SEED}` replaced by a Cairn-chosen secret; the PoC
  must return that exact value (env `CAIRN_SEED` carries it for reference).
- **authbypass / pathtraversal** — optional hooks: `run_hints.plant_command`
  (with `{NONCE}`) + `run_hints.sentinel_path`; the PoC must return the
  planted content.
- PoCs always run with `CAIRN_TARGET` (live endpoint) and
  `CAIRN_COLLECTOR_URL` (the only egress) in their environment.

A PoC that cannot honour the hook for its class still runs — the oracle
leans `ambiguous` and the verdict stays `inconclusive`. Honest uncertainty
beats a rubber stamp.

## Deployment (Cairn in Docker)

`docker-compose.yaml` runs server + dispatcher, both sharing `./datas/cairn`:

- **server** mounts it at `/root/.local/share/cairn` (db + evidence).
- **dispatcher** mounts it at `/cairn-datas` and talks to the Docker daemon
  through the mounted socket; the verification section of `dispatch.yaml`
  points `evidence_home`/`sandbox.data_home` at `/cairn-datas/...` and
  `sandbox.host_data_home` at the **host-side** path of the same directory
  (`CAIRN_HOST_DATA` from `.env`). The daemon — not the dispatcher —
  resolves bind-mount sources; that duality is why both views exist.
- Rootless-docker hosts: adjust the socket mount in compose
  (`/run/user/<uid>/docker.sock`) and export `DOCKER_HOST` accordingly.

## Testing

- Docker-free: `uv run --project cairn --group dev pytest`
- Everything in a container: `./test-in-docker.sh`
- With container + e2e suites: `CAIRN_SANDBOX_INTEGRATION=1
  ./test-in-docker.sh` (needs `python:3.13-slim`, `docker:cli`, `alpine/git`
  images and a reachable Docker socket).
