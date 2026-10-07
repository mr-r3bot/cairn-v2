"""Server-side verification surface tests (no Docker)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
import pytest

from cairn.server import db
from cairn.server.app import app


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
    "run_hints": {"port": 8090},
    "poc": {"type": "script", "language": "python", "payload": "print('boom')"},
    "vuln_class": "rce",
    "strix_claimed_oracle": {"expect": "echo proof"},
}


def _ingest(client: TestClient) -> tuple[str, str]:
    response = client.post("/claims", json=CLAIM)
    assert response.status_code == 201
    data = response.json()
    return data["claim"]["id"], data["project_id"]


def _verdict_body(claim_id: str, **overrides) -> dict:
    body = {"claim_id": claim_id, "status": "not_reproduced", "detail": "effect never fired"}
    body.update(overrides)
    return body


# ---------------------------------------------------------------- guardrails


def test_reproduced_requires_marker_and_oracle(client: TestClient):
    claim_id, pid = _ingest(client)
    response = client.post(f"/projects/{pid}/verdict", json=_verdict_body(claim_id, status="reproduced"))
    assert response.status_code == 422
    response = client.post(
        f"/projects/{pid}/verdict", json=_verdict_body(claim_id, status="reproduced", marker="cafe")
    )
    assert response.status_code == 422
    ok = client.post(
        f"/projects/{pid}/verdict",
        json=_verdict_body(claim_id, status="reproduced", marker="cafe", oracle_id="rce/nonce-callback"),
    )
    assert ok.status_code == 201


def test_verdict_exactly_once(client: TestClient):
    claim_id, pid = _ingest(client)
    assert client.post(f"/projects/{pid}/verdict", json=_verdict_body(claim_id)).status_code == 201
    assert client.post(f"/projects/{pid}/verdict", json=_verdict_body(claim_id)).status_code == 409


def test_inconclusive_requires_known_sub_reason(client: TestClient):
    claim_id, pid = _ingest(client)
    bad = client.post(
        f"/projects/{pid}/verdict", json=_verdict_body(claim_id, status="inconclusive", sub_reason="MEH")
    )
    assert bad.status_code == 422
    good = client.post(
        f"/projects/{pid}/verdict",
        json=_verdict_body(claim_id, status="inconclusive", sub_reason="BRING_UP_FAILED"),
    )
    assert good.status_code == 201


def test_claim_execution_view_never_exposes_strix_oracle(client: TestClient):
    claim_id, pid = _ingest(client)
    response = client.get(f"/projects/{pid}/claim")
    assert response.status_code == 200
    body = response.json()
    assert body["claim_id"] == claim_id
    assert body["poc"]["payload"] == "print('boom')"
    assert body["run_hints"] == {"port": 8090}
    assert "strix_claimed_oracle" not in body
    assert client.get("/projects/proj_999/claim").status_code == 404


# ---------------------------------------------------------------- handback


def test_handback_only_after_non_reproduced_verdict(client: TestClient):
    claim_id, pid = _ingest(client)
    assert client.post(f"/projects/{pid}/handback", json={"payload": {}}).status_code == 409
    assert client.post(f"/projects/{pid}/verdict", json=_verdict_body(claim_id)).status_code == 201
    created = client.post(
        f"/projects/{pid}/handback", json={"payload": {"message": "booted fine, effect never fired"}}
    )
    assert created.status_code == 201
    assert client.post(f"/projects/{pid}/handback", json={"payload": {}}).status_code == 409

    fetched = client.get(f"/projects/{pid}/handback")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["claim_id"] == claim_id and body["status"] == "not_reproduced"
    assert body["message"].startswith("booted fine")

    by_claim = client.get(f"/claims/{claim_id}/handback")
    assert by_claim.status_code == 200


def test_handback_forbidden_on_reproduced(client: TestClient):
    claim_id, pid = _ingest(client)
    client.post(
        f"/projects/{pid}/verdict",
        json=_verdict_body(claim_id, status="reproduced", marker="cafe", oracle_id="rce/nonce-callback"),
    )
    assert client.post(f"/projects/{pid}/handback", json={"payload": {}}).status_code == 409


# ---------------------------------------------------------------- overview / evidence / exporters


def test_overview_joins_claims_projects_verdicts(client: TestClient):
    claim_id, pid = _ingest(client)
    overview = client.get("/verification/overview").json()
    item = next(c for c in overview["claims"] if c["claim_id"] == claim_id)
    assert item["target_repo"] == "apache/gravitino"
    assert item["poc_type"] == "script"
    assert item["verdict_status"] is None
    client.post(f"/projects/{pid}/verdict", json=_verdict_body(claim_id))
    overview = client.get("/verification/overview").json()
    item = next(c for c in overview["claims"] if c["claim_id"] == claim_id)
    assert item["verdict_status"] == "not_reproduced"


def test_evidence_serving_whitelist_and_content(client: TestClient):
    _, pid = _ingest(client)
    assert client.get(f"/projects/{pid}/evidence/replay_manifest.json").status_code == 404  # not written
    assert client.get(f"/projects/{pid}/evidence/../../etc/passwd".replace("../..", "x")).status_code == 404
    assert client.get(f"/projects/{pid}/evidence/_state.json").status_code == 404  # internal, never served
    assert client.get(f"/projects/{pid}/evidence/secret").status_code == 404

    manifest = db.evidence_root() / pid / "replay_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"verdict": {"status": "reproduced"}}))
    served = client.get(f"/projects/{pid}/evidence/replay_manifest.json")
    assert served.status_code == 200
    assert served.json()["verdict"]["status"] == "reproduced"


def test_exit_code_badge_and_report(client: TestClient):
    claim_id, pid = _ingest(client)
    assert client.get(f"/projects/{pid}/exit-code").text == "0"  # no verdict yet → 0
    client.post(
        f"/projects/{pid}/verdict",
        json=_verdict_body(claim_id, status="reproduced", marker="cafe", oracle_id="rce/nonce-callback"),
    )
    assert client.get(f"/projects/{pid}/exit-code").text == "1"

    badge = client.get(f"/projects/{pid}/badge.svg")
    assert badge.status_code == 200 and "svg" in badge.headers["content-type"]
    assert "reproduced" in badge.text and "#F0603E" in badge.text

    report = client.get(f"/projects/{pid}/report")
    assert report.status_code == 200
    assert "REPRODUCED" in report.text
    assert "apache/gravitino" in report.text
    # PoC payload stays sealed in reports
    assert "print('boom')" not in report.text


def test_system_state_roundtrip(client: TestClient):
    assert client.get("/verification/system").json()["sandbox_available"] is False
    client.post("/verification/system", json={"sandbox_available": True, "note": "ready"})
    state = client.get("/verification/system").json()
    assert state["sandbox_available"] is True and state["note"] == "ready"


def test_verify_console_page_served(client: TestClient):
    response = client.get("/verify")
    assert response.status_code == 200
    assert "alpine.min.js" in response.text
    assert "verification/overview" in response.text
    # claim ingestion UI: operators never need curl to start a run
    assert "Ingest an untrusted claim" in response.text
    assert "iform" in response.text  # guided form state shipped with the page
