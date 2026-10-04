"""Claim ingestion endpoints (Cairn v2, Phase 0).

``POST /claims`` turns an untrusted Strix finding into a project whose
origin fact is the claim (sealed) and whose goal fact is the verification
goal.  ``run_hints`` ride along as real Hint rows — hints are the steering
primitive, so no new mechanism is invented for them.

The full validated claim JSON (including the sealed PoC payload and Strix's
claimed oracle) is persisted in the claims table for later phases
(execution, audit, export) — never onto the board.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from cairn.server.claims import (
    ClaimIngestResponse,
    ClaimPayload,
    ClaimRecord,
)
from cairn.server.db import get_conn
from cairn.server.models import Fact, Hint, ProjectDetail, ProjectMeta
from cairn.server.services import next_hint_id, next_project_id, utcnow

router = APIRouter(tags=["claims"])

_MAX_HINT_ROWS = 8


def _next_claim_id(conn) -> str:
    conn.execute("UPDATE counters SET value = value + 1 WHERE name = 'claim'")
    row = conn.execute("SELECT value FROM counters WHERE name = 'claim'").fetchone()
    return f"claim_{row['value']:03d}"


def _claim_row_to_record(row) -> ClaimRecord:
    return ClaimRecord(
        id=row["id"],
        project_id=row["project_id"],
        source=row["source"],
        target_repo=row["target_repo"],
        target_commit=row["target_commit"],
        target_image=row["target_image"],
        vuln_class=row["vuln_class"],
        poc_digest=row["poc_digest"],
        created_at=row["created_at"],
    )


def get_claim_or_404(conn, claim_id: str):
    row = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Claim not found")
    return row


@router.post("/claims", response_model=ClaimIngestResponse, status_code=201)
def ingest_claim(body: ClaimPayload):
    with get_conn() as conn:
        claim_id = _next_claim_id(conn)
        pid = next_project_id(conn)
        now = utcnow()

        title = f"verify/{body.target_repo}@{body.target_commit[:7]}-{body.vuln_class}"
        origin = body.to_origin_description(claim_id)
        goal = body.to_goal_description(claim_id)

        conn.execute(
            "INSERT INTO projects (id, title, status, bootstrap_enabled, created_at) "
            "VALUES (?, ?, 'active', 0, ?)",
            (pid, title, now),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES ('origin', ?, ?)",
            (pid, origin),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES ('goal', ?, ?)",
            (pid, goal),
        )

        # run_hints become real hints; each value is rendered as guidance text
        hints = []
        for key, value in sorted(body.run_hints.items())[:_MAX_HINT_ROWS]:
            hid = next_hint_id(conn, pid)
            content = f"[claim {claim_id}] run_hint {key}: {json.dumps(value)}"
            conn.execute(
                "INSERT INTO hints (id, project_id, content, creator, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (hid, pid, content, body.source, now),
            )
            hints.append(Hint(id=hid, content=content, creator=body.source, created_at=now))

        conn.execute(
            "INSERT INTO claims (id, project_id, source, target_repo, target_commit, "
            "target_image, vuln_class, poc_digest, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                claim_id,
                pid,
                body.source,
                body.target_repo,
                body.target_commit,
                body.target_image,
                body.vuln_class,
                body.seal(),
                body.model_dump_json(),
                now,
            ),
        )

        return ClaimIngestResponse(
            claim=ClaimRecord(
                id=claim_id,
                project_id=pid,
                source=body.source,
                target_repo=body.target_repo,
                target_commit=body.target_commit,
                target_image=body.target_image,
                vuln_class=body.vuln_class,
                poc_digest=body.seal(),
                created_at=now,
            ),
            project=ProjectDetail(
                project=ProjectMeta(
                    id=pid,
                    title=title,
                    status="active",
                    bootstrap_enabled=False,
                    created_at=now,
                    reason=None,
                ),
                facts=[Fact(id="origin", description=origin), Fact(id="goal", description=goal)],
                intents=[],
                hints=hints,
            ),
            project_id=pid,
        )


@router.get("/claims", response_model=list[ClaimRecord])
def list_claims():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM claims ORDER BY created_at").fetchall()
        return [_claim_row_to_record(row) for row in rows]


@router.get("/claims/{claim_id}", response_model=ClaimRecord)
def get_claim(claim_id: str):
    with get_conn() as conn:
        return _claim_row_to_record(get_claim_or_404(conn, claim_id))
