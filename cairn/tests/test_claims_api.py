from __future__ import annotations

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


def _claim_body(**overrides) -> dict:
    body = {
        "source": "strix",
        "target_repo": "apache/gravitino",
        "target_commit": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        "run_hints": {"profile": "playground"},
        "poc": {
            "type": "script",
            "language": "python",
            "payload": "import requests\nrequests.post(TARGET + '/api', json=CMD)\n",
        },
        "vuln_class": "rce",
        "strix_claimed_oracle": {"expect_stdout": "uid=0"},
    }
    body.update(overrides)
    return body


def test_ingest_claim_creates_project_with_sealed_origin(client: TestClient) -> None:
    response = client.post("/claims", json=_claim_body())
    assert response.status_code == 201
    data = response.json()

    assert data["claim"]["id"] == "claim_001"
    assert data["claim"]["poc_digest"].startswith("sha256:")
    assert data["project_id"].startswith("proj_")
    assert data["project"]["project"]["status"] == "active"
    # verification projects do not run the generic bootstrap task
    assert data["project"]["project"]["bootstrap_enabled"] is False

    origin = next(f for f in data["project"]["facts"] if f["id"] == "origin")
    goal = next(f for f in data["project"]["facts"] if f["id"] == "goal")

    # the board sees repo/commit/class and the digest — never the payload
    assert "apache/gravitino" in origin["description"]
    assert "a1b2c3d" in origin["description"]
    assert data["claim"]["poc_digest"][:14] in origin["description"]
    assert "requests.post" not in origin["description"]
    # strix's claimed oracle is flagged as recorded-only, contents never rendered
    assert "never treated as proof" in origin["description"]
    assert "uid=0" not in origin["description"]
    # the goal states the verdict contract and the effect-not-echo rule
    assert "reproduced | not_reproduced | inconclusive" in goal["description"]
    assert "not evidence" in goal["description"]

    # run_hints ride along as real hints credited to the claim source
    assert len(data["project"]["hints"]) == 1
    assert data["project"]["hints"][0]["creator"] == "strix"
    assert "playground" in data["project"]["hints"][0]["content"]


def test_ingest_claim_seals_http_poc_body(client: TestClient) -> None:
    body = _claim_body(
        poc={
            "type": "http",
            "method": "POST",
            "url": "http://target:8090/api/connectors",
            "headers": {"Content-Type": "application/json"},
            "body": '{"config": {"command": "cat /etc/passwd"}}',
        },
        vuln_class="ssrf",
    )
    response = client.post("/claims", json=body)
    assert response.status_code == 201
    origin = next(
        f for f in response.json()["project"]["facts"] if f["id"] == "origin"
    )
    assert "http" in origin["description"]
    assert "/etc/passwd" not in origin["description"]


def test_claims_list_and_get_round_trip_without_payload(client: TestClient) -> None:
    client.post("/claims", json=_claim_body())
    client.post("/claims", json=_claim_body(target_repo="redis/redis", vuln_class="sqli"))

    listed = client.get("/claims")
    assert [c["id"] for c in listed.json()] == ["claim_001", "claim_002"]

    single = client.get("/claims/claim_002")
    assert single.status_code == 200
    record = single.json()
    assert record["target_repo"] == "redis/redis"
    assert record["vuln_class"] == "sqli"
    assert record["poc_digest"].startswith("sha256:")
    assert "payload" not in record
    assert "payload_json" not in record
    assert "strix_claimed_oracle" not in record

    assert client.get("/claims/claim_999").status_code == 404


def test_ingested_claim_project_runs_on_the_board(client: TestClient) -> None:
    response = client.post("/claims", json=_claim_body())
    project_id = response.json()["project_id"]

    # a run can start from it: the origin fact is claimable like any other
    detail = client.get(f"/projects/{project_id}")
    assert detail.status_code == 200
    assert detail.json()["project"]["title"].startswith("verify/apache/gravitino@")

    intent = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "bring up target", "creator": "dispatcher.bringup"},
    )
    assert intent.status_code == 201

    # hint endpoint still works — one steering surface for humans
    hint = client.post(
        f"/projects/{project_id}/hints", json={"content": "use playground", "creator": "human"}
    )
    assert hint.status_code == 201


def test_deleting_claim_project_cascades_claim_row(client: TestClient) -> None:
    response = client.post("/claims", json=_claim_body())
    project_id = response.json()["project_id"]
    assert client.delete(f"/projects/{project_id}").status_code == 204
    assert client.get("/claims/claim_001").status_code == 404


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_repo": "not a repo!"},
        {"target_repo": "apache"},
        {"target_commit": "HEAD~1"},
        {"target_commit": "xyz123"},
        {"vuln_class": "quantum"},
        {"poc": {"type": "telnet"}},
        {"poc": {"type": "script", "payload": ""}},
        {"poc": {"type": "http", "method": "POST"}},  # missing url
        {"source": ""},
        {"extra_field": 1},
    ],
)
def test_ingest_claim_rejects_malformed_untrusted_input(client: TestClient, overrides) -> None:
    response = client.post("/claims", json=_claim_body(**overrides))
    assert response.status_code == 422
    assert client.get("/claims").json() == []


def test_ingest_claim_rejects_oversize_poc(client: TestClient) -> None:
    body = _claim_body(poc={"type": "command", "argv": ["python", "-c", "A" * (256 * 1024 + 1)]})
    assert client.post("/claims", json=body).status_code == 422
