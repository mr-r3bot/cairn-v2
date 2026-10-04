"""Docker-native sandbox manager (Cairn v2, Phase 1).

Per verification run the manager stands up:

- an **internal** Docker network `cairn-sbxnet-<run>` — Docker gives it no
  external route, so nothing on it can reach anything outside the network;
- a **collector** container attached to that network under the alias
  ``collector`` — the only peer worth talking to and the only way a nonce
  ever leaves the sandbox;
- **payload** containers that execute untrusted PoC code with: read-only
  rootfs, bind-mounted scratch (evidence survives), dropped capabilities,
  no-new-privileges, cgroup memory/pids/cpu caps, non-root uid.

The target (Phase 2) joins the same network via :meth:`attach`, which makes
"sandbox network = target + collector + payload" the whole world.

Targets (Phase 2) attach with :meth:`attach`; teardown removes everything
by run id.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.models.networks import Network

from cairn.sandbox.collector_script import collector_command, parse_hits
from cairn.sandbox.config import SandboxConfig

LOG = logging.getLogger(__name__)

_NETWORK_PREFIX = "cairn-sbxnet-"
_COLLECTOR_PREFIX = "cairn-sbxcollector-"
_POC_PREFIX = "cairn-sbxpoc-"

_SCRATCH_MOUNT = "/scratch"
_RUN_LABEL = "cairn.sandbox.run"


def _sanitize(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "-", name).strip("-")
    if not cleaned:
        raise ValueError(f"run id {name!r} has no usable characters")
    return cleaned[:48]


@dataclass
class PayloadResult:
    """Outcome of one sandboxed payload execution."""

    run_id: str
    argv: list[str]
    rc: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    container_name: str = ""
    hits: list[dict] = field(default_factory=list)


class SandboxManager:
    def __init__(self, config: SandboxConfig | None = None, client=None):
        self.config = config or SandboxConfig()
        self._client = client  # lazy: connect on first use, not construction

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------------
    # naming / paths

    def network_name(self, run_id: str) -> str:
        return f"{_NETWORK_PREFIX}{_sanitize(run_id)}"

    def collector_name(self, run_id: str) -> str:
        return f"{_COLLECTOR_PREFIX}{_sanitize(run_id)}"

    def scratch_dir(self, run_id: str) -> Path:
        path = self.config.scratch_root / _sanitize(run_id)
        path.mkdir(parents=True, exist_ok=True)
        # payload runs as uid 65534; scratch must be writable by it
        path.chmod(0o777)
        return path

    def hits_path(self, run_id: str) -> Path:
        path = self.config.hits_root / _sanitize(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def collector_url(self) -> str:
        return f"http://collector:{self.config.collector_port}"

    # ------------------------------------------------------------------
    # network

    def ensure_network(self, run_id: str) -> Network:
        name = self.network_name(run_id)
        try:
            return self.client.networks.get(name)
        except NotFound:
            pass
        LOG.info("creating sandbox network run=%s name=%s (internal)", run_id, name)
        return self.client.networks.create(name, internal=True, labels={_RUN_LABEL: run_id})

    def attach(self, run_id: str, container: Container | str, aliases: list[str] | None = None) -> None:
        """Attach a container (e.g. the Phase 2 target) to the run network."""
        network = self.ensure_network(run_id)
        network.connect(container, aliases=aliases or [])
        LOG.info("attached container=%s to sandbox network run=%s", container, run_id)

    # ------------------------------------------------------------------
    # collector

    def ensure_collector(self, run_id: str) -> str:
        name = self.collector_name(run_id)
        existing = self._get_container(name)
        if existing is not None:
            if self._container_state(existing) == "running":
                return name
            existing.remove(force=True)

        hits = self.hits_path(run_id)
        hits.touch(exist_ok=True)
        host_hits = self.config.host_path(hits)

        LOG.info("starting nonce collector run=%s hits=%s", run_id, hits)
        container = self.client.containers.run(
            self.config.collector_image,
            collector_command(self.config.collector_port),
            name=name,
            detach=True,
            read_only=True,
            tmpfs={"/tmp": "rw,size=8m"},
            volumes={str(host_hits): {"bind": "/collector/hits.jsonl", "mode": "rw"}},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit="128m",
            pids_limit=32,
            labels={_RUN_LABEL: run_id},
        )
        self._wait_collector_healthy(container, name)
        self.ensure_network(run_id).connect(container, aliases=["collector"])
        return name

    def _wait_collector_healthy(self, container: Container, name: str) -> None:
        deadline = time.monotonic() + self.config.collector_startup_timeout_s
        probe = (
            "import urllib.request,sys;"
            f"sys.exit(0 if urllib.request.urlopen("
            f"'http://127.0.0.1:{self.config.collector_port}/healthz', timeout=1).status == 200 else 1)"
        )
        while time.monotonic() < deadline:
            state = self._container_state(container)
            if state != "running":
                raise RuntimeError(f"collector {name} exited during startup (state={state})")
            exit_code, _ = container.exec_run(["python3", "-c", probe])
            if exit_code == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(f"collector {name} did not become healthy in time")

    # ------------------------------------------------------------------
    # payload execution

    def run_payload(
        self,
        run_id: str,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout_s: int | None = None,
    ) -> PayloadResult:
        """Execute an untrusted payload inside the sandbox and report the outcome."""
        timeout = timeout_s or self.config.payload_timeout_s
        scratch = self.scratch_dir(run_id)
        host_scratch = self.config.host_path(scratch)
        network = self.ensure_network(run_id)

        merged_env = {
            "CAIRN_COLLECTOR_URL": self.collector_url(),
            "CAIRN_SCRATCH": _SCRATCH_MOUNT,
        }
        merged_env.update(env or {})

        name = f"{_POC_PREFIX}{_sanitize(run_id)}-{uuid.uuid4().hex[:8]}"
        cfg = self.config
        started = time.monotonic()
        container = self.client.containers.run(
            cfg.image,
            argv,
            name=name,
            detach=True,
            network=network.name,
            read_only=True,
            volumes={str(host_scratch): {"bind": _SCRATCH_MOUNT, "mode": "rw"}},
            tmpfs={"/tmp": "rw,size=64m"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=f"{cfg.mem_mb}m",
            pids_limit=cfg.pids_limit,
            nano_cpus=int(cfg.cpus * 1_000_000_000),
            user="65534:65534",
            environment=merged_env,
            labels={_RUN_LABEL: run_id},
        )

        timed_out = False
        deadline = started + timeout
        while True:
            state = self._container_state(container)
            if state in ("exited", "dead"):
                break
            if time.monotonic() > deadline:
                LOG.warning("payload timed out run=%s after %ss — killing", run_id, timeout)
                timed_out = True
                try:
                    container.kill()
                except APIError:
                    pass
                break
            time.sleep(0.2)

        container.reload()
        rc = container.attrs.get("State", {}).get("ExitCode")
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
        duration = time.monotonic() - started

        failed = timed_out or rc not in (0, None)
        if not (failed and cfg.keep_on_failure):
            try:
                container.remove(force=True)
            except NotFound:
                pass

        return PayloadResult(
            run_id=run_id,
            argv=argv,
            rc=rc,
            stdout=stdout,
            stderr=stderr,
            duration_s=round(duration, 3),
            timed_out=timed_out,
            container_name=name,
            hits=self.hits(run_id),
        )

    # ------------------------------------------------------------------
    # observation

    def hits(self, run_id: str) -> list[dict]:
        path = self.hits_path(run_id)
        if not path.exists():
            return []
        return parse_hits(path.read_text(encoding="utf-8"))

    def wait_for_nonce(self, nonce: str, *, run_id: str, timeout_s: float = 20.0) -> dict | None:
        """Poll the collector evidence file until the nonce shows up."""
        from cairn.sandbox.collector_script import nonce_seen

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            hit = nonce_seen(self.hits(run_id), nonce)
            if hit is not None:
                return hit
            time.sleep(0.5)
        return None

    # ------------------------------------------------------------------
    # teardown

    def teardown(self, run_id: str) -> None:
        net_name = self.network_name(run_id)
        for container in self.client.containers.list(all=True, filters={"label": f"{_RUN_LABEL}={run_id}"}):
            LOG.info("removing sandbox container run=%s container=%s", run_id, container.name)
            try:
                container.remove(force=True)
            except (NotFound, APIError) as exc:
                LOG.warning("failed removing container=%s: %s", container.name, exc)
        collector = self._get_container(self.collector_name(run_id))
        if collector is not None:
            try:
                collector.remove(force=True)
            except (NotFound, APIError) as exc:
                LOG.warning("failed removing collector: %s", exc)
        try:
            network = self.client.networks.get(net_name)
            network.remove()
        except NotFound:
            pass
        except APIError as exc:
            LOG.warning("failed removing network=%s: %s", net_name, exc)

    def close(self) -> None:
        self.client.close()

    # ------------------------------------------------------------------
    # internals

    def _get_container(self, name: str) -> Container | None:
        try:
            return self.client.containers.get(name)
        except NotFound:
            return None

    @staticmethod
    def _container_state(container: Container) -> str | None:
        container.reload()
        state = container.attrs.get("State", {}).get("Status")
        return str(state) if state else None
