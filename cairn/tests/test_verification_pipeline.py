"""Pipeline state-machine tests: real server (TestClient) + fake sandbox.

Bring-up is monkeypatched to canned results so the machine itself is under
test: stage transitions, facts on the board, verdict/handback/complete
writes, budget and stall terminations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from cairn.sandbox.config import SandboxConfig
from cairn.sandbox.manager import PayloadResult
from cairn.server import db
from cairn.server.app import app
from cairn.verification.bringup import BringUpResult
from cairn.verification.config import BudgetConfig, VerificationConfig
from cairn.verification.pipeline import ServerGateway, VerificationPipeline

CLAIM = {
    "source": "strix",
    "target_repo": "fixture/app",
    "target_commit": "deadbee1234567890deadbee1234567890deadbe",
    "run_hints": {},
    "poc": {"type": "script", "language": "bash", "payload": "eval \"$CAIRN_CMD\""},
    "vuln_class": "rce",
    "strix_claimed_oracle": {"expect": "ignored"},
}


@dataclass
class FakeSandbox:
    """Duck-typed SandboxManager: records calls, scripted payload results."""

    tmp: Path | None = None
    nonce_hits: set = field(default_factory=set)
    payload_results: list = field(default_factory=list)  # consumed per run
    torn_down: int = 0
    payloads_run: int = 0

    def scratch_dir(self, run_id):
        path = self.tmp / "scratch" / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def network_name(self, run_id):
        return f"cairn-sbxnet-{run_id}"

    def ensure_network(self, run_id):
        return None

    def ensure_collector(self, run_id):
        return "collector"

    def collector_url(self):
        return "http://collector:9931"

    def run_payload(self, run_id, argv, *, env=None, timeout_s=None):
        self.payloads_run += 1
        scripted = self.payload_results.pop(0) if self.payload_results else {"rc": 0}
        return PayloadResult(
            run_id=run_id, argv=argv, rc=scripted.get("rc", 0),
            stdout=scripted.get("stdout", ""), stderr=scripted.get("stderr", ""),
            duration_s=0.1, timed_out=scripted.get("timed_out", False),
        )

    def hits(self, run_id):
        return [{"path": f"/beacon/{n}", "ts": 1, "method": "GET", "src": "x"} for n in self.nonce_hits]

    def wait_for_nonce(self, nonce, *, run_id, timeout_s=5.0):
        return {"path": f"/beacon/{nonce}"} if nonce in self.nonce_hits else None

    def teardown(self, run_id):
        self.torn_down += 1

    def close(self):
        return None


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "cairn.db")
    with TestClient(app) as test_client:
        yield test_client


def _pipeline(client: TestClient, tmp_path, fake: FakeSandbox, *, budget: BudgetConfig | None = None):
    config = VerificationConfig(
        sandbox=SandboxConfig(data_home=tmp_path / "data"),
        budget=budget or BudgetConfig(wall_clock_s=600, max_steps=20, max_payload_runs=10),
    )
    # evidence must land where the server serves it from
    config.evidence_home = db.evidence_root()
    gateway = ServerGateway(client, "")
    return VerificationPipeline(gateway, fake, config), config


def _bringup(monkeypatch, ok: bool, endpoint="http://target:8090"):
    def fake_bring_up(self, run_id, claim):
        return BringUpResult(
            ok=ok, endpoint=endpoint if ok else None,
            strategy="compose" if ok else None,
            recipe={"strategy": "compose", "endpoint": endpoint} if ok else {},
            attempts=[{"strategy": "compose", "ok": ok, "detail": "x"}],
            log="discovered: compose",
        )

    monkeypatch.setattr("cairn.verification.bringup.BringUpService.bring_up", fake_bring_up)
    monkeypatch.setattr(
        "cairn.verification.bringup.BringUpService.teardown", lambda self, run_id, recipe: None
    )


def _drive(pipeline, pid, max_steps=12):
    for _ in range(max_steps):
        summary = pipeline.step(pid)
        if summary.get("action") in ("verdict", "already-terminal", "gone", "verdict-write-failed"):
            return summary
    raise AssertionError("pipeline did not terminate")


def _facts(client, pid):
    return [f["description"] for f in client.get(f"/projects/{pid}").json()["facts"]]


# =====================================================================
# the five terminal outcomes
# =====================================================================


def test_reproduced_happy_path(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path)
    pipeline, _ = _pipeline(client, tmp_path, fake)
    _bringup(monkeypatch, ok=True)

    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    # arm confirmation: whatever nonce the oracle picked gets observed
    original_run_payload = fake.run_payload
    def capture(run_id, argv, *, env=None, timeout_s=None):
        fake.nonce_hits.add(env["CAIRN_NONCE"])
        return original_run_payload(run_id, argv, env=env, timeout_s=timeout_s)
    fake.run_payload = capture

    summary = _drive(pipeline, pid)
    assert summary["verdict"] == "reproduced"
    assert summary["marker"] is not None

    facts = _facts(client, pid)
    assert any(f.startswith("BRING-UP OK") for f in facts)
    assert any(f.startswith("EXECUTE — PoC ran clean") for f in facts)
    assert any(f.startswith("EFFECT CONFIRMED") for f in facts)
    assert any(f.startswith("VERDICT — REPRODUCED") for f in facts)

    verdict = client.get(f"/projects/{pid}/verdict").json()
    assert verdict["status"] == "reproduced" and verdict["marker"]
    assert client.get(f"/projects/{pid}/handback").status_code == 404  # nothing to hand back
    assert client.get(f"/projects/{pid}/exit-code").text == "1"
    assert client.get(f"/projects/{pid}").json()["project"]["status"] == "completed"

    # evidence served end to end
    manifest = client.get(f"/projects/{pid}/evidence/replay_manifest.json")
    assert manifest.status_code == 200 and manifest.json()["verdict"]["status"] == "reproduced"
    observation = client.get(f"/projects/{pid}/evidence/observation.json")
    assert observation.json()["status"] == "confirmed"
    assert fake.torn_down >= 1


def test_not_reproduced_when_marker_never_fires(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path)  # nonce_hits stays empty
    pipeline, _ = _pipeline(client, tmp_path, fake)
    _bringup(monkeypatch, ok=True)
    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    summary = _drive(pipeline, pid)
    assert summary["verdict"] == "not_reproduced"

    handback = client.get(f"/projects/{pid}/handback").json()
    assert handback["status"] == "not_reproduced"
    assert handback["live_endpoint"] == "http://target:8090"
    assert handback["replay_manifest_ref"] == "replay_manifest.json"
    assert client.get(f"/projects/{pid}/exit-code").text == "0"


def test_poc_error_is_inconclusive_not_failed(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path, payload_results=[{"rc": 3, "stderr": "Traceback"}])
    pipeline, _ = _pipeline(client, tmp_path, fake)
    _bringup(monkeypatch, ok=True)
    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    summary = _drive(pipeline, pid)
    assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "POC_ERROR")

    handback = client.get(f"/projects/{pid}/handback").json()
    assert "crashed" in handback["message"]
    assert handback["poc_output"]["rc"] == 3
    facts = _facts(client, pid)
    assert any("POC_ERROR" in f for f in facts)


def test_bring_up_failed(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path)
    pipeline, _ = _pipeline(client, tmp_path, fake)
    _bringup(monkeypatch, ok=False)
    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    summary = _drive(pipeline, pid)
    assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "BRING_UP_FAILED")

    handback = client.get(f"/projects/{pid}/handback").json()
    assert "never fairly tested" in handback["message"]
    assert handback["live_endpoint"] is None
    assert fake.payloads_run == 0  # no PoC ever ran


def test_budget_exhausted(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path)
    # bring-up ok, but the budget allows a single step
    pipeline, _ = _pipeline(
        client, tmp_path, fake, budget=BudgetConfig(wall_clock_s=600, max_steps=1, max_payload_runs=1)
    )
    _bringup(monkeypatch, ok=True)
    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    summary = _drive(pipeline, pid)
    assert (summary["verdict"], summary["sub_reason"]) == ("inconclusive", "BUDGET_EXHAUSTED")


def test_stall_terminates_as_ambiguous(client, tmp_path, monkeypatch):
    """A bring-up that never progresses ends the run instead of hanging."""
    fake = FakeSandbox(tmp=tmp_path)
    pipeline, _ = _pipeline(client, tmp_path, fake)

    calls = {"n": 0}
    def stuck_bring_up(self, run_id, claim):
        calls["n"] += 1
        raise RuntimeError(f"transient docker error {calls['n']}")
    monkeypatch.setattr("cairn.verification.bringup.BringUpService.bring_up", stuck_bring_up)
    monkeypatch.setattr(
        "cairn.verification.bringup.BringUpService.teardown", lambda self, run_id, recipe: None
    )

    pid = client.post("/claims", json=CLAIM).json()["project_id"]
    summary = _drive(pipeline, pid)
    # the bring-up stage failed hard (not a strategy dead-end) — repeated
    # failures trip the stall stop-condition and the run still terminates
    assert summary["action"] == "verdict"
    verdict = client.get(f"/projects/{pid}/verdict").json()
    assert verdict["status"] == "inconclusive"
    assert verdict["sub_reason"] in ("ORACLE_AMBIGUOUS", "BUDGET_EXHAUSTED", "BRING_UP_FAILED")


# =====================================================================
# resume + idempotence
# =====================================================================


def test_pipeline_resumes_from_saved_state(client, tmp_path, monkeypatch):
    fake = FakeSandbox(tmp=tmp_path)
    pipeline, _ = _pipeline(client, tmp_path, fake)
    _bringup(monkeypatch, ok=True)
    pid = client.post("/claims", json=CLAIM).json()["project_id"]

    first = pipeline.step(pid)
    assert first["action"] == "bringup"

    # a "restart": fresh pipeline instance, same evidence root
    pipeline2, _ = _pipeline(client, tmp_path, fake)
    second = pipeline2.step(pid)
    assert second["action"] == "execute"  # not bringup again

    # non-claim projects are ignored
    other = client.post(
        "/projects", json={"title": "t", "origin": "o", "goal": "g"}
    ).json()["project"]["id"]
    assert pipeline2.step(other)["action"] == "not-a-claim"
