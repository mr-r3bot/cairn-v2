"""End-to-end verification runs against real Docker containers.

Opt in with CAIRN_SANDBOX_INTEGRATION=1 (see test-in-docker.sh, which also
mounts the docker socket and a host-shared data root so the daemon and the
tests see the same paths).  Each case drives the REAL pipeline — discovery,
compose/dockerfile boot, sandboxed PoC execution, oracle, verdict, handback
— against a small local fixture target.  No live LLM, no external network.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("CAIRN_SANDBOX_INTEGRATION") != "1",
        reason="set CAIRN_SANDBOX_INTEGRATION=1 (and a docker socket) to run e2e",
    ),
]

IT_ROOT = Path(os.environ.get("CAIRN_IT_ROOT", "/tmp/cairn-it"))
COMPOSE_TARGET = """\
services:
  app:
    image: python:3.13-slim
    command: >-
      python3 -c "import http.server;
      http.server.HTTPServer(('0.0.0.0', 8080),
      http.server.SimpleHTTPRequestHandler).serve_forever()"
    expose: ['8080']
"""
DOCKERFILE_TARGET = """\
FROM python:3.13-slim
CMD ["python3", "-c", "import http.server; http.server.HTTPServer(('0.0.0.0', 8080), http.server.SimpleHTTPRequestHandler).serve_forever()"]
EXPOSE 8080
"""


def _it_dir(name: str) -> Path:
    root = IT_ROOT / f"{name}-{uuid.uuid4().hex[:8]}"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture(scope="module")
def docker_ready():
    try:
        client = docker.from_env()
        client.ping()
        for image in ("python:3.13-slim", "docker:cli", "alpine/git"):
            client.images.get(image)
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"docker not ready for e2e ({exc}); pull python:3.13-slim, docker:cli, alpine/git first")
    return client


class _E2E:
    """One full environment: server (TestClient) + real sandbox + pipeline."""

    def __init__(self, case_dir: Path):
        from fastapi.testclient import TestClient

        from cairn.sandbox.config import SandboxConfig
        from cairn.sandbox.manager import SandboxManager
        from cairn.server import db
        from cairn.server.app import app
        from cairn.verification.config import BudgetConfig, VerificationConfig
        from cairn.verification.pipeline import ServerGateway, VerificationPipeline

        self.dir = case_dir
        db._db_path = None  # noqa: SLF001
        db.configure(case_dir / "server" / "cairn.db")
        self.client = TestClient(app)

        self.config = VerificationConfig(
            sandbox=SandboxConfig(data_home=case_dir / "data"),
            budget=BudgetConfig(wall_clock_s=600, max_steps=20, max_payload_runs=10),
            healthcheck_timeout_s=90,
        )
        # evidence must land where the server serves it from
        self.config.evidence_home = db.evidence_root()
        self.sandbox = SandboxManager(self.config.sandbox)
        self.pipeline = VerificationPipeline(
            ServerGateway(self.client, ""), self.sandbox, self.config
        )

    def ingest(self, claim: dict) -> tuple[str, str]:
        response = self.client.post("/claims", json=claim)
        assert response.status_code == 201, response.text
        data = response.json()
        return data["claim"]["id"], data["project_id"]

    def drive(self, project_id: str, max_steps: int = 15) -> dict:
        for _ in range(max_steps):
            summary = self.pipeline.step(project_id)
            if summary.get("action") in ("verdict", "already-terminal", "verdict-write-failed"):
                return summary
        raise AssertionError("run did not terminate")

    def cleanup(self, project_id: str) -> None:
        try:
            self.sandbox.teardown(project_id)
        except Exception:  # noqa: BLE001 - best effort
            pass
        try:
            self.sandbox.client.containers.prune()
        except Exception:  # noqa: BLE001
            pass


def _claim(fixture_repo: Path, *, poc: dict, vuln_class: str = "rce", run_hints: dict | None = None) -> dict:
    return {
        "source": "strix",
        "target_repo": "fixture/local-target",
        "target_commit": "0123456789abcdef0123456789abcdef01234567",
        "run_hints": {"checkout_dir": str(fixture_repo), **(run_hints or {})},
        "poc": poc,
        "vuln_class": vuln_class,
        "strix_claimed_oracle": {"expect": "echoed proof — must be ignored"},
    }


HAPPY_POC = {
    "type": "script",
    "language": "bash",
    "payload": (
        'python3 -c "import os,urllib.request; urllib.request.urlopen(os.environ[\'CAIRN_TARGET\'], timeout=5)"\n'
        'eval "$CAIRN_CMD"\n'
    ),
}


def test_e2e_reproduced_via_compose_target(docker_ready, tmp_path):
    case = _it_dir("reproduced")
    repo = case / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text(COMPOSE_TARGET)

    e2e = _E2E(case)
    claim_id, pid = e2e.ingest(_claim(repo, poc=HAPPY_POC, run_hints={"port": 8080}))
    try:
        summary = e2e.drive(pid)
        assert summary["verdict"] == "reproduced", summary
        assert summary["marker"]

        verdict = e2e.client.get(f"/projects/{pid}/verdict").json()
        assert verdict["oracle_id"] == "rce/nonce-callback"
        assert verdict["marker"]

        # the board tells the whole story
        facts = [f["description"] for f in e2e.client.get(f"/projects/{pid}").json()["facts"]]
        assert any(f.startswith("BRING-UP OK — compose") for f in facts)
        assert any(f.startswith("EFFECT CONFIRMED") for f in facts)
        assert any(f.startswith("VERDICT — REPRODUCED") for f in facts)

        # evidence is replayable and served
        manifest = e2e.client.get(f"/projects/{pid}/evidence/replay_manifest.json").json()
        assert manifest["boot_recipe"]["strategy"] == "compose"
        assert manifest["poc"]["sealed"] is True
        observation = e2e.client.get(f"/projects/{pid}/evidence/observation.json").json()
        assert observation["status"] == "confirmed"

        assert e2e.client.get(f"/projects/{pid}/exit-code").text == "1"
        assert e2e.client.get(f"/projects/{pid}/handback").status_code == 404
        assert e2e.client.get(f"/projects/{pid}").json()["project"]["status"] == "completed"
    finally:
        e2e.cleanup(pid)


def test_e2e_not_reproduced_when_poc_does_nothing(docker_ready, tmp_path):
    case = _it_dir("notrepro")
    repo = case / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text(COMPOSE_TARGET)

    e2e = _E2E(case)
    claim_id, pid = e2e.ingest(_claim(repo, poc={"type": "script", "language": "bash", "payload": "true\n"}))
    try:
        summary = e2e.drive(pid)
        assert (summary["verdict"], summary.get("sub_reason")) == ("not_reproduced", None)

        handback = e2e.client.get(f"/projects/{pid}/handback").json()
        assert handback["status"] == "not_reproduced"
        assert handback["live_endpoint"] == "http://target:8080"
        assert "effect never fired" in handback["message"]
        assert handback["replay_manifest_ref"]
        assert e2e.client.get(f"/projects/{pid}/exit-code").text == "0"
    finally:
        e2e.cleanup(pid)


def test_e2e_poc_error_is_inconclusive(docker_ready, tmp_path):
    case = _it_dir("pocerror")
    repo = case / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text(COMPOSE_TARGET)

    e2e = _E2E(case)
    claim_id, pid = e2e.ingest(_claim(repo, poc={"type": "script", "language": "bash", "payload": "echo boom >&2\nexit 3\n"}))
    try:
        summary = e2e.drive(pid)
        assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "POC_ERROR")
        handback = e2e.client.get(f"/projects/{pid}/handback").json()
        assert "crashed" in handback["message"]
        assert handback["poc_output"]["rc"] == 3
    finally:
        e2e.cleanup(pid)


def test_e2e_bring_up_failed_on_unbootable_repo(docker_ready, tmp_path):
    case = _it_dir("bringupfail")
    repo = case / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# toy\n\n```bash\ndocker run -it toy\n```\n")

    e2e = _E2E(case)
    claim_id, pid = e2e.ingest(_claim(repo, poc=HAPPY_POC))
    try:
        summary = e2e.drive(pid)
        assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "BRING_UP_FAILED")

        handback = e2e.client.get(f"/projects/{pid}/handback").json()
        assert "never fairly tested" in handback["message"]
        boot = e2e.client.get(f"/projects/{pid}/evidence/boot.json").json()
        strategies = {a["strategy"]: a for a in boot["attempts"]}
        assert "readme" in strategies and not strategies["readme"]["ok"]
    finally:
        e2e.cleanup(pid)


def test_e2e_dockerfile_strategy_boots_and_verdicts(docker_ready, tmp_path):
    case = _it_dir("dockerfile")
    repo = case / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(DOCKERFILE_TARGET)

    e2e = _E2E(case)
    claim_id, pid = e2e.ingest(_claim(repo, poc=HAPPY_POC, run_hints={"port": 8080}))
    try:
        summary = e2e.drive(pid)
        assert summary["verdict"] == "reproduced", summary
        manifest = e2e.client.get(f"/projects/{pid}/evidence/replay_manifest.json").json()
        assert manifest["boot_recipe"]["strategy"] == "dockerfile"
    finally:
        e2e.cleanup(pid)


def test_e2e_budget_exhausted(docker_ready, tmp_path):
    from cairn.verification.config import BudgetConfig

    case = _it_dir("budget")
    repo = case / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text(COMPOSE_TARGET)

    e2e = _E2E(case)
    e2e.config.budget = BudgetConfig(wall_clock_s=600, max_steps=1, max_payload_runs=1)
    claim_id, pid = e2e.ingest(_claim(repo, poc=HAPPY_POC, run_hints={"port": 8080}))
    try:
        summary = e2e.drive(pid)
        assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "BUDGET_EXHAUSTED")
    finally:
        e2e.cleanup(pid)
