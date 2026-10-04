"""Auto-mode tests (Phase 8) — guard, exit codes, timeout."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from cairn.server import db
from cairn.server.app import app
from cairn.verification.auto import AutoError, AutoRunner


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "cairn.db")
    with TestClient(app) as test_client:
        yield test_client


CLAIM = {
    "source": "strix",
    "target_repo": "apache/gravitino",
    "target_commit": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    "poc": {"type": "command", "argv": ["echo", "hi"]},
    "vuln_class": "rce",
}


def test_auto_refuses_without_sandbox(client: TestClient):
    runner = AutoRunner(client, "")
    with pytest.raises(AutoError, match="refuses to run"):
        runner.check_sandbox()


def test_auto_guard_override_and_full_cycle(client: TestClient):
    client.post("/verification/system", json={"sandbox_available": True, "note": "ready"})
    runner = AutoRunner(client, "", timeout_s=10, poll_s=0.05)
    runner.check_sandbox()  # guard passes

    claim_id, pid = runner.ingest(CLAIM)
    assert claim_id == "claim_001"

    # the "dispatcher" concludes with a reproduced verdict while we wait
    import threading
    import time

    def conclude():
        time.sleep(0.2)
        client.post(
            f"/projects/{pid}/verdict",
            json={
                "claim_id": claim_id,
                "status": "reproduced",
                "marker": "cafe1234",
                "oracle_id": "rce/nonce-callback",
                "detail": "marker observed",
            },
        )

    threading.Thread(target=conclude).start()
    verdict = runner.wait_verdict(pid)
    assert verdict["status"] == "reproduced"
    assert AutoRunner.exit_code(verdict) == 1


def test_auto_exit_code_zero_for_non_reproduced(client: TestClient):
    client.post("/verification/system", json={"sandbox_available": True})
    runner = AutoRunner(client, "", timeout_s=10, poll_s=0.05)
    runner.check_sandbox()
    claim_id, pid = runner.ingest(CLAIM)
    import threading
    import time

    def conclude():
        time.sleep(0.2)
        client.post(
            f"/projects/{pid}/verdict",
            json={"claim_id": claim_id, "status": "inconclusive", "sub_reason": "POC_ERROR"},
        )

    threading.Thread(target=conclude).start()
    verdict = runner.wait_verdict(pid)
    assert verdict["status"] == "inconclusive"
    assert AutoRunner.exit_code(verdict) == 0


def test_auto_timeout_is_operational_failure(client: TestClient):
    client.post("/verification/system", json={"sandbox_available": True})
    runner = AutoRunner(client, "", timeout_s=0.3, poll_s=0.05)
    claim_id, pid = runner.ingest(CLAIM)  # no verdict will ever arrive
    with pytest.raises(AutoError, match="no verdict"):
        runner.wait_verdict(pid)


def test_auto_rejects_malformed_claim(client: TestClient):
    client.post("/verification/system", json={"sandbox_available": True})
    runner = AutoRunner(client, "")
    bad = dict(CLAIM, target_repo="not a repo!")
    with pytest.raises(AutoError, match="claim rejected"):
        runner.ingest(bad)
