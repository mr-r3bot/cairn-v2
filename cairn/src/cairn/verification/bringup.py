"""Target bring-up by auto-discovery (Cairn v2, Phase 2).

Reads the pinned checkout (commit from the claim) and ranks boot
strategies:

    image (claim offers a prebuilt image)  →  rank 0
    docker-compose*.y*ml                   →  rank 10
    Dockerfile                             →  rank 20
    Makefile run-ish targets               →  rank 30 (detected only)
    bin/* or scripts/*start*               →  rank 40 (detected only)
    README run block                       →  rank 50 (detected only)

Executable strategies (image, compose, dockerfile) run through throwaway
helper containers that drive the Docker daemon over its socket; the booted
target is attached to the run's internal sandbox network under the alias
``target`` (plus its compose service name).  Health is established by
probing candidate ports from a probe container on the same network.

Detected-but-not-executed strategies are recorded as dead-ends ("requires
interactive boot") so the run never re-treads them and the failure mode is
actionable (BRING_UP_FAILED tells Strix to supply a run recipe instead of
re-hunting).

All container argv are passed as lists — untrusted repo/claim strings never
touch a shell.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import NotFound

from cairn.sandbox.manager import SandboxManager, _sanitize
from cairn.verification.config import VerificationConfig

LOG = logging.getLogger(__name__)

COMPOSE_GLOBS = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")
MAKE_TARGET_RE = re.compile(r"^(run|up|start|dev|serve)\b|^[a-zA-Z0-9_-]+:(run|up|start|dev|serve)\b", re.M)
RUN_BLOCK_RE = re.compile(r"```(bash|sh|shell)?\s*\n(.*(docker|make|python|npm|java).*)\n```", re.I)

_SOCKET_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()\n"
    "    sys.exit(0)\n"
    "except OSError:\n"
    "    sys.exit(1)\n"
)
_HTTP_PROBE = (
    "import sys, urllib.request\n"
    "try:\n"
    "    r = urllib.request.urlopen(sys.argv[1], timeout=3)\n"
    "    print(r.status)\n"
    "except urllib.error.HTTPError as e:\n"
    "    print(e.code)\n"
    "except Exception:\n"
    "    sys.exit(1)\n"
)


@dataclass
class BringUpResult:
    ok: bool
    endpoint: str | None = None
    strategy: str | None = None
    recipe: dict = field(default_factory=dict)
    attempts: list[dict] = field(default_factory=list)
    log: str = ""
    duration_s: float = 0.0


def daemon_socket() -> str:
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://"):]
    return "/var/run/docker.sock"


class BringUpService:
    def __init__(
        self,
        sandbox: SandboxManager,
        config: VerificationConfig | None = None,
        client=None,
    ):
        self.sandbox = sandbox
        self.config = config or VerificationConfig()
        self._client = client  # lazy: inherit the sandbox client on first use

    @property
    def client(self):
        if self._client is None:
            self._client = self.sandbox.client
        return self._client

    # ------------------------------------------------------------------
    # checkout

    def ensure_checkout(self, run_id: str, claim: dict) -> Path:
        hints = claim.get("run_hints") or {}
        if hints.get("checkout_dir"):
            path = Path(str(hints["checkout_dir"]))
            if not path.is_dir():
                raise RuntimeError(f"run_hints.checkout_dir does not exist: {path}")
            return path

        checkout = self.config.checkout_root() / _sanitize(run_id)
        if (checkout / ".git").exists():
            return checkout

        repo_url = hints.get("repo_url") or f"https://github.com/{claim['target_repo']}"
        checkout.parent.mkdir(parents=True, exist_ok=True)
        target = _sanitize(run_id)
        LOG.info("cloning %s@%s for run=%s", repo_url, claim["target_commit"], run_id)
        with self._git_helper(run_id) as git:
            rc, out = self._exec(git, ["git", "clone", "--", str(repo_url), target], timeout_s=900)
            if rc != 0:
                raise RuntimeError(f"git clone failed rc={rc}: {out[-500:]}")
            rc, out = self._exec(
                git,
                ["git", "-C", target, "checkout", "--", str(claim["target_commit"])],
                timeout_s=120,
            )
            if rc != 0:
                raise RuntimeError(f"git checkout {claim['target_commit']} failed rc={rc}: {out[-500:]}")
        return checkout

    # ------------------------------------------------------------------
    # discovery

    def discover(self, checkout: Path, claim: dict) -> list[tuple[int, str, dict]]:
        found: list[tuple[int, str, dict]] = []

        if claim.get("target_image"):
            found.append((0, "image", {"image": claim["target_image"]}))

        compose_files = sorted(
            path for glob in COMPOSE_GLOBS for path in checkout.glob(glob) if path.is_file()
        )
        for path in compose_files:
            found.append((10, "compose", {"file": path.name, "path": str(path)}))

        if (checkout / "Dockerfile").is_file():
            found.append((20, "dockerfile", {"path": str(checkout / "Dockerfile")}))

        makefile = next(
            (p for p in ("Makefile", "makefile", "GNUmakefile") if (checkout / p).is_file()), None
        )
        if makefile and MAKE_TARGET_RE.search((checkout / makefile).read_text(errors="replace")):
            found.append((30, "make", {"file": makefile, "note": "requires interactive boot"}))

        scripts = [
            p.name
            for pattern in ("bin/*", "scripts/*start*", "scripts/*")
            for p in sorted(checkout.glob(pattern))
            if p.is_file()
        ][:5]
        if scripts:
            found.append((40, "script", {"files": scripts, "note": "requires interactive boot"}))

        for readme in sorted(checkout.glob("README*")):
            if RUN_BLOCK_RE.search(readme.read_text(errors="replace")):
                found.append((50, "readme", {"file": readme.name, "note": "requires interactive boot"}))
                break

        return sorted(found, key=lambda item: item[0])

    # ------------------------------------------------------------------
    # bring-up

    def bring_up(self, run_id: str, claim: dict) -> BringUpResult:
        started = time.monotonic()
        result = BringUpResult(ok=False)
        log_lines: list[str] = []

        try:
            checkout = self.ensure_checkout(run_id, claim)
        except Exception as exc:  # noqa: BLE001 - bring-up dead-ends must not crash runs
            LOG.warning("checkout failed run=%s: %s", run_id, exc)
            result.attempts.append({"strategy": "checkout", "ok": False, "detail": str(exc)})
            result.log = "\n".join(log_lines)
            result.duration_s = round(time.monotonic() - started, 3)
            return result

        strategies = self.discover(checkout, claim)
        log_lines.append(f"discovered: {[(rank, name) for rank, name, _ in strategies]}")

        for rank, name, spec in strategies:
            log_lines.append(f"trying strategy {name} (rank {rank})")
            try:
                if name == "image":
                    ok = self._boot_image(run_id, spec, result, log_lines)
                elif name == "compose":
                    ok = self._boot_compose(run_id, checkout, spec, claim, result, log_lines)
                elif name == "dockerfile":
                    ok = self._boot_dockerfile(run_id, checkout, result, log_lines)
                else:
                    result.attempts.append(
                        {"strategy": name, "ok": False, "detail": f"detected, not auto-executable ({spec.get('note', '')})", "rank": rank}
                    )
                    continue
            except Exception as exc:  # noqa: BLE001 - fall through ranked strategies
                LOG.warning("strategy %s failed run=%s: %s", name, run_id, exc)
                result.attempts.append({"strategy": name, "ok": False, "detail": str(exc), "rank": rank})
                continue

            if ok:
                result.ok = True
                result.strategy = name
                result.recipe["rank"] = rank
                break
            self._teardown_target(run_id, result.recipe)

        result.log = "\n".join(log_lines)
        result.duration_s = round(time.monotonic() - started, 3)
        return result

    # ------------------------------------------------------------------
    # strategies

    def _boot_image(self, run_id: str, spec: dict, result: BringUpResult, log_lines: list[str]) -> bool:
        image = spec["image"]
        tag = f"cairn-sbx-target-{_sanitize(run_id)}"
        log_lines.append(f"docker run image={image}")
        container = self.client.containers.run(
            image,
            name=tag,
            detach=True,
            labels={"cairn.sandbox.run": run_id},
        )
        self.sandbox.attach(run_id, container, aliases=["target"])
        result.recipe.update({"strategy": "image", "image": image, "target_container": tag})
        return self._finish_with_health(run_id, claim_hint_ports={}, result=result, log_lines=log_lines)

    def _boot_compose(
        self, run_id: str, checkout: Path, spec: dict, claim: dict, result: BringUpResult, log_lines: list[str]
    ) -> bool:
        project = self.config.compose_project(run_id)
        compose_file = spec["path"]
        rc, out = self._builder_run(
            run_id,
            ["docker", "compose", "-p", project, "-f", f"/src/{spec['file']}", "up", "-d", "--build"],
            volumes=[(self._host(checkout), {"bind": "/src", "mode": "ro"})],
            workdir="/src",
            log_lines=log_lines,
        )
        log_lines.append(f"compose up rc={rc}\n{out[-800:]}")
        if rc != 0:
            result.attempts.append({"strategy": "compose", "ok": False, "detail": f"compose up rc={rc}"})
            self._builder_run(
                run_id,
                ["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
                log_lines=log_lines,
            )
            return False

        services = self._compose_service_containers(project)
        log_lines.append(f"compose services: {[c.name for c in services]}")
        if not services:
            result.attempts.append({"strategy": "compose", "ok": False, "detail": "no service containers found"})
            return False

        for container in services:
            service = (container.labels.get("com.docker.compose.service") or container.name)
            self.sandbox.attach(run_id, container, aliases=[service])

        hint_ports = self._compose_ports(Path(compose_file)) + self._claim_ports(claim)
        result.recipe.update(
            {
                "strategy": "compose",
                "compose_file": spec["file"],
                "compose_project": project,
                "services": {
                    c.labels.get("com.docker.compose.service", c.name): c.name for c in services
                },
            }
        )
        return self._finish_with_health(
            run_id,
            claim_hint_ports={"extra": hint_ports},
            result=result,
            log_lines=log_lines,
            aliases=None,  # "target" alias assigned to whichever service answers health
            service_containers=services,
        )

    def _boot_dockerfile(self, run_id: str, checkout: Path, result: BringUpResult, log_lines: list[str]) -> bool:
        tag = f"cairn-sbx-target-img-{_sanitize(run_id)}"
        rc, out = self._builder_run(
            run_id,
            ["docker", "build", "-t", tag, "/src"],
            volumes=[(self._host(checkout), {"bind": "/src", "mode": "ro"})],
            workdir="/src",
            log_lines=log_lines,
        )
        log_lines.append(f"docker build rc={rc}\n{out[-800:]}")
        if rc != 0:
            result.attempts.append({"strategy": "dockerfile", "ok": False, "detail": f"docker build rc={rc}"})
            return False

        container = self.client.containers.run(
            tag,
            name=f"cairn-sbx-target-{_sanitize(run_id)}",
            detach=True,
            labels={"cairn.sandbox.run": run_id},
        )
        self.sandbox.attach(run_id, container, aliases=["target"])
        result.recipe.update({"strategy": "dockerfile", "image": tag, "target_container": container.name})
        return self._finish_with_health(run_id, claim_hint_ports={}, result=result, log_lines=log_lines)

    # ------------------------------------------------------------------
    # health

    def _finish_with_health(
        self,
        run_id: str,
        *,
        claim_hint_ports: dict,
        result: BringUpResult,
        log_lines: list[str],
        service_containers: list | None = None,
    ) -> bool:
        candidates: list[str] = []
        for value in claim_hint_ports.values():
            if isinstance(value, list):
                candidates.extend(str(p) for p in value)
            elif value is not None:
                candidates.append(str(value))
        candidates.extend(str(p) for p in self.config.health_ports)

        hosts = ["target"]
        if service_containers:
            hosts = [
                (c.labels.get("com.docker.compose.service") or c.name) for c in service_containers
            ] + ["target"]

        healthy = self._wait_health(run_id, hosts, candidates, log_lines)
        if healthy is None:
            result.attempts.append(
                {"strategy": result.recipe.get("strategy", "?"), "ok": False, "detail": "no healthy port within timeout"}
            )
            return False

        host, port, http_status = healthy
        if service_containers and host != "target":
            # pin the alias to the service that actually answered
            for container in service_containers:
                service = container.labels.get("com.docker.compose.service") or container.name
                if service == host:
                    self.sandbox.attach(run_id, container, aliases=["target"])

        result.endpoint = f"http://target:{port}"
        result.recipe.update({"endpoint": result.endpoint, "port": port, "http_status": http_status})
        result.attempts.append(
            {"strategy": result.recipe.get("strategy", "?"), "ok": True, "detail": f"healthy on {host}:{port}"}
        )
        log_lines.append(f"healthy: {host}:{port} http={http_status}")
        return True

    def _wait_health(self, run_id: str, hosts: list[str], ports: list[str], log_lines: list[str]):
        probe = self.client.containers.run(
            self.config.probe_image,
            ["sleep", "infinity"],
            name=f"cairn-sbxprobe-{_sanitize(run_id)}",
            detach=True,
            network=self.sandbox.network_name(run_id),
            labels={"cairn.sandbox.run": run_id},
        )
        deadline = time.monotonic() + self.config.healthcheck_timeout_s
        try:
            while time.monotonic() < deadline:
                for host in hosts:
                    for port in ports:
                        rc, _ = probe.exec_run(["python3", "-c", _SOCKET_PROBE, host, port])
                        if rc == 0:
                            _, out = probe.exec_run(["python3", "-c", _HTTP_PROBE, f"http://{host}:{port}/"])
                            status = out.decode().strip() or "?"
                            return host, int(port), status
                time.sleep(self.config.healthcheck_interval_s)
            log_lines.append(f"health probe timed out after {self.config.healthcheck_timeout_s}s")
            return None
        finally:
            try:
                probe.remove(force=True)
            except NotFound:
                pass

    # ------------------------------------------------------------------
    # teardown

    def teardown(self, run_id: str, recipe: dict) -> None:
        self._teardown_target(run_id, recipe)

    def _teardown_target(self, run_id: str, recipe: dict) -> None:
        if recipe.get("strategy") == "compose" and recipe.get("compose_project"):
            project = recipe["compose_project"]
            try:
                self._builder_run(
                    run_id,
                    ["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
                    log_lines=[],
                )
            except Exception as exc:  # noqa: BLE001 - teardown is best effort
                LOG.warning("compose down failed run=%s: %s", run_id, exc)
        for container in self.client.containers.list(all=True, filters={"label": f"cairn.sandbox.run={run_id}"}):
            try:
                container.remove(force=True)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("failed removing %s: %s", container.name, exc)
        image = recipe.get("image")
        if image and str(image).startswith("cairn-sbx-target-img-"):
            try:
                self.client.images.remove(image, force=True)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("failed removing image %s: %s", image, exc)

    # ------------------------------------------------------------------
    # helpers

    def _host(self, path: Path) -> Path:
        return self.config.sandbox.host_path(path)

    def _claim_ports(self, claim: dict) -> list[int]:
        hints = claim.get("run_hints") or {}
        port = hints.get("port")
        if isinstance(port, list):
            return [int(p) for p in port if str(p).isdigit()]
        if port is not None and str(port).isdigit():
            return [int(port)]
        return []

    @staticmethod
    def _compose_ports(compose_file: Path) -> list[int]:
        import yaml

        try:
            doc = yaml.safe_load(compose_file.read_text(errors="replace")) or {}
        except yaml.YAMLError:
            return []
        ports: list[int] = []
        for service in (doc.get("services") or {}).values():
            if not isinstance(service, dict):
                continue
            for entry in service.get("ports") or []:
                text = str(entry)
                container = text.rsplit(":", 1)[-1].split("/")[0]
                if container.isdigit():
                    ports.append(int(container))
            for entry in service.get("expose") or []:
                if str(entry).isdigit():
                    ports.append(int(entry))
        return ports

    def _compose_service_containers(self, project: str):
        return list(
            self.client.containers.list(
                filters={"label": f"com.docker.compose.project={project}"}
            )
        )

    def _git_helper(self, run_id: str):
        return self._helper(
            run_id,
            self.config.git_image,
            name=f"cairn-sbx-git-{_sanitize(run_id)}",
            volumes=[(self._host(self.config.checkout_root()), {"bind": "/git", "mode": "rw"})],
        )

    def _builder_run(
        self,
        run_id: str,
        argv: list[str],
        *,
        volumes: list | None = None,
        workdir: str = "/",
        log_lines: list[str] | None = None,
        timeout_s: int | None = None,
    ) -> tuple[int, str]:
        timeout = timeout_s or max(self.config.healthcheck_timeout_s, 300)
        socket = daemon_socket()
        mounts = list(volumes or [])
        mounts.append((socket, {"bind": "/var/run/docker.sock", "mode": "rw"}))
        return self._one_shot(
            self.config.builder_image,
            argv,
            mounts=mounts,
            workdir=workdir,
            timeout_s=timeout,
            log_lines=log_lines,
        )

    def _one_shot(
        self,
        image: str,
        argv: list[str],
        *,
        mounts: list,
        workdir: str,
        timeout_s: int,
        log_lines: list[str] | None,
    ) -> tuple[int, str]:
        volumes = {str(src): bind for src, bind in mounts}
        container = self.client.containers.run(
            image,
            argv,
            detach=True,
            volumes=volumes,
            workdir=workdir,
            labels={"cairn.sandbox.run": "helper"},
        )
        deadline = time.monotonic() + timeout_s
        timed_out = False
        while True:
            container.reload()
            if container.attrs.get("State", {}).get("Status") in ("exited", "dead"):
                break
            if time.monotonic() > deadline:
                timed_out = True
                container.kill()
                break
            time.sleep(0.5)
        rc = container.attrs.get("State", {}).get("ExitCode")
        logs = container.logs().decode("utf-8", "replace")
        container.remove(force=True)
        if timed_out:
            if log_lines is not None:
                log_lines.append(f"helper {argv[:3]} timed out after {timeout_s}s")
            return 124, logs
        return int(rc or 0), logs

    def _helper(self, run_id: str, image: str, *, name: str, volumes: list):
        class _Helper:
            def __init__(self, outer):
                self._outer = outer
                self._container = None

            def __enter__(self):
                self._container = self._outer._client.containers.run(
                    image,
                    ["sleep", "infinity"],
                    name=name,
                    detach=True,
                    entrypoint=["sleep", "infinity"],
                    volumes={str(src): bind for src, bind in volumes},
                    labels={"cairn.sandbox.run": run_id},
                )
                return self._container

            def __exit__(self, *exc):
                if self._container is not None:
                    try:
                        self._container.remove(force=True)
                    except NotFound:
                        pass
                return False

        return _Helper(self)

    @staticmethod
    def _exec(container, argv: list[str], timeout_s: int) -> tuple[int, str]:
        """docker exec with a wall-clock cap (exec_run has none)."""
        import threading

        result: dict = {"rc": None, "out": b""}

        def run() -> None:
            rc, out = container.exec_run(argv)
            result["rc"], result["out"] = rc, out

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout_s)
        if thread.is_alive():
            return 124, "exec timed out"
        return int(result["rc"] if result["rc"] is not None else 1), result["out"].decode("utf-8", "replace")
