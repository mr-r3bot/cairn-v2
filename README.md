<div align="center">

<img src="./README/banner.png" alt="Cairn Banner"/>

# Cairn
### More Than Just AI Penetration Testing — Towards General State-Space Search

<p>
  <a href="https://zc.tencent.com/hackathon" target="_blank" rel="noopener noreferrer">
    <img src="./README/tencent.png" alt="Tencent" height="55" />
  </a>
  <a href="https://zc.tencent.com/hackathon" target="_blank" rel="noopener noreferrer">
    <img src="./README/tch.png" alt="TCH" height="55" />
  </a>
  <a href="https://wiki.chainreactors.red" target="_blank" rel="noopener noreferrer">
    <img src="./README/c.png" alt="ChainReactors" height="45" />
  </a>
</p>

Cairn is a general-purpose problem-solving engine. <br/>It defines no roles, no workflows. Given an origin and a goal, it searches for a path through an unknown state space. <br/>AI Penetration Testing is one such problem — and a proven one.

<p>
  <a href="https://discord.gg/nDSy4NZVP" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/Discord-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord" />
  </a>
  <a href="https://x.com/le1xia0" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white" alt="X" />
  </a>
</p>

</div>

<p align="center">
  <a href="https://www.bilibili.com/video/BV1a8R5BhEVi/" target="_blank" rel="noopener noreferrer">
    <img src="./README/cairn.png" alt="Cairn runtime screenshot" width="900" />
  </a>
</p>

## What is Cairn?

Penetration testing is fundamentally a **directed search through a near-infinite state space**:

- **Origin**: known (target IP, target system)
- **Goal**: defined (get a shell, capture the flag)
- **Path**: unknown

This structure is not unique to penetration testing. Vulnerability research, mathematical proof, CTF challenges — any problem with a clear starting point, a clear success condition, and an unknown path in between shares the same shape.

Cairn is built for this class of problems. Penetration testing is the first domain it has been validated on.

The engine is built on a **Blackboard Architecture** with an explicit fact-intent graph. Three primitives are all it needs:

| Concept | Meaning |
|---------|---------|
| **Fact** | A confirmed, objective finding written to the board |
| **Intent** | A declared direction of exploration, not yet executed |
| **Hint** | Human judgment injected at any time; absorbed by agents on the next read |

The graph grows from `origin` toward `goal`. Every new Fact is a stepping stone; every Intent is a step into the unknown.

Agent Workers run an OODA loop — Observe the full graph, Orient to the current state, Decide on next intents, Act to explore — and write their findings back as new Facts. Workers have no fixed roles. Tasks are generated at runtime from the graph's current state, not from predefined job descriptions.

Agents coordinate exclusively through the shared board (Stigmergy). No direct communication. No information silos.

## Cairn in Action

https://github.com/user-attachments/assets/e557b1ac-dda4-41cb-87dd-9d56dbf05133


## How It Works

Three task types, all executed by the same Worker:

| Task | What it does | Output |
|------|-------------|--------|
| **Bootstrap** | At project start, attempts to solve the problem directly | Fact + possible Complete |
| **Reason** | Reads the full graph: is the goal met? What should be explored next? | Complete / new Intents / no-op |
| **Explore** | Claims one Intent, executes the exploration, reports findings | One Fact |

System architecture:

```
          ┌──────────────────────────────────┐
          │           Cairn Server           │
          │    Facts + Intents + Hints       │
          └─────────────────┬────────────────┘
                            │
                     Read / Write API
                            │
          ┌─────────────────┴────────────────┐
          │             Dispatcher           │
          │   Schedules tasks, manages       │
          │   containers, writes protocol    │
          └──────────┬───────────────┬───────┘
                     │               │
     ┌───────────────┴──┐     ┌──────┴──────────────┐
     │  Worker Container│     │  Worker Container   │
     │   (Project A)    │     │   (Project B)       │
     │  ┌────┐  ┌────┐  │     │  ┌────┐  ┌────┐     │
     │  │ W. │  │ W. │  │     │  │ W. │  │ W. │     │
     │  └────┘  └────┘  │     │  └────┘  └────┘     │
     └──────────────────┘     └─────────────────────┘
```

**Cairn Server** maintains graph consistency only.

**Cairn Dispatcher** reads the graph, schedules tasks, spins up and tears down worker containers, and is the sole writer to the protocol. Each project gets its own Worker Container; multiple Agent Workers run concurrently inside it. Agent Workers only receive a prompt and return structured output.

Workers can also run directly on the dispatcher host instead of in per-project containers — **local mode**, no Docker required. See [Local mode](#local-mode-no-docker) below.

Supported worker backends: **Claude Code**, **Codex**, and **Pi**.

## Results

**Tencent Cloud Hackathon · AI Penetration Testing Challenge · 2nd Edition**

610 teams · 1,345 participants · top universities and security firms across China

| Metric | Value |
|--------|-------|
| Problems solved | **54 / 54 — only team to AK** |
| Final ranking | 3rd |

> The system had never been tested before the competition. The full pipeline came online for the first time at 4 AM on race day. No training, no tuning, no domain-specific tooling. Zero MCP tools, zero RAG, zero predefined agent roles.

## Further Reading

- <a href="https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA" target="_blank" rel="noopener noreferrer">The Strongest AI Penetration Testing Agent: Postmortem of the Only Team to Achieve AK at the TCH Tencent Cloud Hackathon Intelligent Penetration Testing Challenge (2nd Edition)</a>
- <a href="https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w" target="_blank" rel="noopener noreferrer">The Pathless Path: Cairn AI from Penetration Testing to General Problem Solving</a>

## Getting Started

**Quick start:** `./start.sh` detects your Docker socket (rootless or not),
generates a verification-only `dispatch.yaml` if you don't have one, writes
`.env`, pulls the helper images, and brings the stack up on
<http://localhost:8000/> (the v2 verification console). See `./start.sh --help` for `--manual`
(host processes, dispatcher-first), `stop`, and `status`. The rest of this
section explains what it does under the hood.

**Prerequisites**
 
- macOS or Linux
- Python ≥ 3.12
- Docker (container execution; also the **v2 verification sandbox** — PoC
  verification always runs containerized, local mode does not change that)


### Pull required images
 
LLM hunt tasks (v1) need the worker container image:

```bash
docker pull --platform=linux/amd64 ghcr.io/oritera/cairn-worker-container:latest
```

**v2 verification** additionally uses three small helper images (PoC sandbox,
compose/build driver, clone driver):

```bash
docker pull python:3.13-slim docker:cli alpine/git
```

Create your local dispatcher configuration and fill in your LLM endpoints and API keys:

```bash
cp dispatch.example.yaml dispatch.yaml
```

The `verification:` section at the bottom is optional — the defaults fit a
dispatcher running directly on the host.

### Docker Compose (recommended)

Pull the base image used to build Cairn:

```bash
docker pull ghcr.io/astral-sh/uv:python3.13-trixie
```

**New in v2:** the dispatcher shares `./datas/cairn` with the server, and the
sandbox needs the *host-side* path of that directory (the Docker daemon, not
the dispatcher, resolves bind-mount sources). Create a `.env` next to
`docker-compose.yaml`:

```bash
echo "CAIRN_HOST_DATA=$(pwd)/datas/cairn" > .env
```

```bash
docker compose up --build
```

This starts `cairn-server` on port `8000` and `cairn-dispatcher` once the
server passes its health check. The dispatcher mounts `dispatch.yaml` from
the project root and connects to Docker via the host socket. Data is
persisted to `./datas/cairn/`. Consoles: the **v2 verification console on
`/`** (the product front page); the v1 fact/intent graph view remains at
`/graph` as a debug lens over the board.

Rootless-Docker hosts: change the dispatcher's socket mount to your
rootless socket (e.g. `/run/user/<uid>/docker.sock`) and export
`DOCKER_HOST` accordingly.

### Manual

```bash
# Start the server
uv run --project cairn cairn serve
 
# Run the dispatcher
uv run --project cairn cairn dispatch --config dispatch.yaml

# Run startup health checks only
uv run --project cairn cairn dispatch --config dispatch.yaml --startup-healthcheck-only
```

Unchanged from v1 — when the dispatcher runs directly on the host, the
`verification:` section needs no `host_data_home` (dispatcher and daemon see
the same paths). New in v2: the full-auto entrypoint
`uv run --project cairn cairn auto --claim finding.json` (see the v2 section
below).

### Verification-only deployment (v2)

PoC verification runs on a deterministic pipeline — it needs **no LLM
workers and no API keys**. A minimal `dispatch.yaml`:

```yaml
server: "http://127.0.0.1:8000"
runtime: {interval: 5, max_workers: 4, max_running_projects: 2, max_project_workers: 2, healthcheck_timeout: 20, worker_healthcheck: "disabled", prompt_group: "default"}
tasks:
  bootstrap: {timeout: 300, conclude_timeout: 90}
  reason: {timeout: 300, max_intents: 2}
  explore: {timeout: 300, conclude_timeout: 90}
workers: []          # allowed because verification is enabled
verification:
  enabled: true
```

Start the server, start the dispatcher, then `POST /claims` (or run
`cairn auto`) and watch the console on `/`.

### Local mode (no Docker)

Instead of one container per project, workers can run directly on the dispatcher host, reusing the machine's already-configured `claude` / `codex` / `pi` CLIs — no Docker, and no API keys in the config.

```bash
cp dispatch.local.example.yaml dispatch.yaml

# Start the server
uv run --project cairn cairn serve

# Run the dispatcher on the same host, where the CLIs are installed and logged in
uv run --project cairn cairn dispatch --config dispatch.yaml
```

Local mode is selected by `runtime.execution: local` (see `dispatch.local.example.yaml`). On startup the dispatcher checks each configured worker CLI is installed and runnable, and reminds you they must already be logged in. Each project gets an isolated working directory under `local.workspace_root` (default: the dispatcher's current directory). Run the dispatcher directly on the host — not inside Docker — since the agents run with your user's permissions and no sandbox. **v2 note:** local mode only changes how *workers* run; PoC verification always goes through the Docker sandbox — that is the product, not a wrapper.

### Tests

Run the fast regression suite without Docker or live model endpoints:

```bash
uv run --project cairn --group dev pytest
```

The whole suite can also run inside a container (host stays clean):

```bash
./test-in-docker.sh                       # Docker-free suites
CAIRN_SANDBOX_INTEGRATION=1 ./test-in-docker.sh   # + container/e2e suites (needs a docker socket)
```

---

## Cairn v2 — Independent PoC Verification Engine

Cairn v2 sits downstream of a hunter (e.g. [Strix](https://github.com/usestrix/strix)).
A finding + PoC arrives as an **untrusted claim**; Cairn boots the target in a
sandbox, executes the PoC, **independently observes the effect** (never the
hunter's success string), and emits a conservative verdict with a replayable
evidence bundle.

```
Ingest ─► Bring-up ─► Execute ─► Observe (oracle) ─► Verdict ─► Handback (on failure)
(untrusted)  (auto)               (effect, not echo)
```

### Ingest a claim

```bash
curl -X POST :8000/claims -H 'content-type: application/json' -d '{
  "source": "strix",
  "target_repo": "apache/gravitino",
  "target_commit": "<vulnerable commit sha>",
  "poc": {"type": "script", "language": "python", "payload": "..."},
  "vuln_class": "rce",
  "strix_claimed_oracle": {"expect": "recorded, never trusted"}
}'
```

The claim becomes a project: origin fact = the sealed claim (digest only),
goal fact = the verification contract. `run_hints` become hints. The
dispatcher walks the spine on the board — every stage is an intent concluded
with a fact you can watch.

### Verdicts

`reproduced` (only when a Cairn-chosen nonce lands on the out-of-band
collector — no marker, no upgrade), `not_reproduced` (booted, PoC ran clean,
effect never fired), `inconclusive` with a sub-reason
(`BRING_UP_FAILED | POC_ERROR | ORACLE_AMBIGUOUS | BUDGET_EXHAUSTED`).
Failure hands back to Strix shaped by the sub-reason, with a replay manifest
of the exact environment.

### Console, exports, CI

- `:8000/` — verification console (worklist + live run view, hint box as the only write surface; alias `/verify`, graph debug view at `/graph`)
- `GET /projects/{id}/verdict|report|badge.svg|exit-code|handback`
- `GET /projects/{id}/evidence/{manifest|boot|poc_output|observation|collector_hits}.json`

Full-auto (CI): `cairn auto --claim finding.json` → exit code `1` on
`reproduced` (CI fails on a confirmed live vuln), `0` otherwise, `2` on
operational failure. Refuses to run without the sandbox unless
`--allow-no-sandbox`.

### Containment (the sandbox is mandatory)

Docker-native: per-run **internal** networks (no external route — the nonce
collector is the only egress), read-only payload containers with a
scratch-only writable path, dropped capabilities, no-new-privileges, and
cgroup memory/pids/cpu caps. Bring-up drives `docker compose` / `docker
build` through socket-mounted helper containers; the booted target joins the
run network as `target`. See `docs/specs/verification.md` for the threat
model, oracle contracts (`CAIRN_CMD` / `CAIRN_URL` hooks for Strix PoC
authors), and deployment notes (incl. the `host_data_home` path duality when
the dispatcher itself runs in a container).

## Disclaimer

Cairn is a general-purpose problem-solving engine. Although it supports penetration testing, CTF solving, security assessment, and vulnerability research workflows, it is intended to be used only in environments where you have explicit authorization to operate.

You are solely responsible for how you use this project. Do not use Cairn against systems, networks, applications, or data without clear prior permission from the owner or operator. Unauthorized security testing, exploitation, or data access may be illegal and may cause harm.

The developers and contributors of this project do not endorse or accept responsibility for any misuse, abuse, damage, loss, or legal consequences arising from its use. By using this project, you agree to ensure that your activities comply with all applicable laws, regulations, contractual obligations, and professional or organizational policies in your jurisdiction.

## Star History

<a href="https://www.star-history.com/#oritera/Cairn&Date" target="_blank" rel="noopener noreferrer">
  <img src="https://api.star-history.com/svg?repos=oritera/Cairn&type=Date" alt="Star History Chart" />
</a>

## ⚖️ License
This project is licensed under **GNU AGPLv3** for personal and educational use.

**Commercial Use**: If you wish to use this project in a commercial or proprietary environment without the AGPL-3.0 open-source obligations, **please contact me to obtain a commercial license.**

**Contributions**: By submitting a Pull Request, you agree that your contributions may be used under both the AGPL-3.0 and the project's commercial license.
