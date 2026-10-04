"""Verification server surface (Cairn v2, Phases 5/5.5/7).

Write endpoints are for the dispatcher pipeline (sole writer); everything
the console touches is read-only except hints.

Server-side guardrails:

- a verdict is exactly-once per project (409 on a second terminal),
- ``reproduced`` requires a marker — no marker, no upgrade, ever,
- ``inconclusive`` requires one of the known sub-reasons,
- handbacks only exist on non-``reproduced`` terminals,
- the execution view of a claim omits ``strix_claimed_oracle`` entirely —
  the execution path cannot read it even by accident.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field, field_validator

from cairn.server import db
from cairn.server.db import get_conn
from cairn.server.routers.claims import get_claim_or_404
from cairn.server.services import get_project_or_404, utcnow

router = APIRouter(tags=["verification"])

VERDICT_STATUSES = ("reproduced", "not_reproduced", "inconclusive")
SUB_REASONS = ("BRING_UP_FAILED", "POC_ERROR", "ORACLE_AMBIGUOUS", "BUDGET_EXHAUSTED")
EVIDENCE_FILES = (
    "replay_manifest.json",
    "boot.json",
    "poc_output.json",
    "observation.json",
    "collector_hits.json",
)


class VerdictRequest(BaseModel):
    claim_id: str
    status: str
    sub_reason: str | None = None
    marker: str | None = None
    oracle_id: str | None = None
    cost_usd: float = 0.0
    duration_s: float = 0.0
    detail: str = ""
    evidence_dir: str = ""

    @field_validator("claim_id", "detail", "evidence_dir")
    @classmethod
    def cap_str(cls, value: str) -> str:
        return value[:4096]


class HandbackRequest(BaseModel):
    payload: dict


class SystemStateRequest(BaseModel):
    sandbox_available: bool = False
    note: str = ""


def _verdict_row(conn, project_id: str):
    return conn.execute(
        "SELECT * FROM verdicts WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
    ).fetchone()


def _verdict_dict(row) -> dict:
    return {
        "claim_id": row["claim_id"],
        "project_id": row["project_id"],
        "status": row["status"],
        "sub_reason": row["sub_reason"],
        "marker": row["marker"],
        "oracle_id": row["oracle_id"],
        "cost_usd": row["cost_usd"],
        "duration_s": row["duration_s"],
        "detail": row["detail"],
        "evidence_dir": row["evidence_dir"],
        "created_at": row["created_at"],
    }


# ----------------------------------------------------------------------
# writes (dispatcher pipeline only)


@router.post("/projects/{project_id}/verdict", status_code=201)
def post_verdict(project_id: str, body: VerdictRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        if _verdict_row(conn, project_id) is not None:
            raise HTTPException(409, "Verdict already recorded — a run ends in exactly one terminal")

        if body.status not in VERDICT_STATUSES:
            raise HTTPException(422, f"status must be one of {VERDICT_STATUSES}")
        if body.status == "reproduced":
            if not body.marker:
                raise HTTPException(422, "reproduced requires the oracle marker — effect, not echo")
            if not body.oracle_id:
                raise HTTPException(422, "reproduced requires the oracle id")
        if body.status == "inconclusive":
            if body.sub_reason not in SUB_REASONS:
                raise HTTPException(422, f"inconclusive requires a sub-reason from {SUB_REASONS}")
        if body.status == "not_reproduced" and body.sub_reason:
            raise HTTPException(422, "not_reproduced does not take a sub-reason")

        conn.execute(
            "INSERT INTO verdicts (project_id, claim_id, status, sub_reason, marker, oracle_id, "
            "cost_usd, duration_s, detail, evidence_dir, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                project_id,
                body.claim_id,
                body.status,
                body.sub_reason,
                body.marker,
                body.oracle_id,
                body.cost_usd,
                body.duration_s,
                body.detail,
                body.evidence_dir,
                utcnow(),
            ),
        )
        return {"project_id": project_id, "status": body.status}


@router.post("/projects/{project_id}/handback", status_code=201)
def post_handback(project_id: str, body: HandbackRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        verdict = _verdict_row(conn, project_id)
        if verdict is None:
            raise HTTPException(409, "No verdict yet — handback follows a terminal")
        if verdict["status"] == "reproduced":
            raise HTTPException(409, "Nothing to hand back: the effect was reproduced")
        existing = conn.execute(
            "SELECT 1 FROM handbacks WHERE project_id = ?", (project_id,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Handback already recorded")
        payload = dict(body.payload)
        payload.setdefault("claim_id", verdict["claim_id"])
        payload.setdefault("status", verdict["status"])
        payload.setdefault("sub_reason", verdict["sub_reason"])
        conn.execute(
            "INSERT INTO handbacks (project_id, claim_id, payload_json, created_at) VALUES (?,?,?,?)",
            (project_id, verdict["claim_id"], json.dumps(payload, default=str), utcnow()),
        )
        return {"project_id": project_id, "claim_id": verdict["claim_id"]}


@router.post("/verification/system", status_code=201)
def post_system_state(body: SystemStateRequest):
    value = json.dumps({"sandbox_available": body.sandbox_available, "note": body.note})
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO system_state (key, value) VALUES ('verification.sandbox', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (value,),
        )
        return {"ok": True}


# ----------------------------------------------------------------------
# reads (console, Strix, CI)


@router.get("/projects/{project_id}/claim")
def get_project_claim(project_id: str):
    """Execution view of a claim: poc + run_hints, never the claimed oracle."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM claims WHERE project_id = ?", (project_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Not a claim project")
        payload = json.loads(row["payload_json"])
        return {
            "claim_id": row["id"],
            "source": row["source"],
            "target_repo": row["target_repo"],
            "target_commit": row["target_commit"],
            "target_image": row["target_image"],
            "vuln_class": row["vuln_class"],
            "poc_digest": row["poc_digest"],
            "created_at": row["created_at"],
            "poc": payload.get("poc"),
            "run_hints": payload.get("run_hints") or {},
        }


@router.get("/projects/{project_id}/verdict")
def get_verdict(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = _verdict_row(conn, project_id)
        if row is None:
            raise HTTPException(404, "No verdict yet")
        return _verdict_dict(row)


@router.get("/projects/{project_id}/handback")
def get_project_handback(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM handbacks WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "No handback")
        return json.loads(row["payload_json"])


@router.get("/claims/{claim_id}/handback")
def get_claim_handback(claim_id: str):
    with get_conn() as conn:
        get_claim_or_404(conn, claim_id)
        row = conn.execute(
            "SELECT * FROM handbacks WHERE claim_id = ? ORDER BY id DESC LIMIT 1", (claim_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "No handback")
        return json.loads(row["payload_json"])


@router.get("/verification/system")
def get_system_state():
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM system_state WHERE key = 'verification.sandbox'"
        ).fetchone()
        if row is None:
            return {"sandbox_available": False, "note": "no dispatcher has registered"}
        return json.loads(row["value"])


@router.get("/verification/overview")
def verification_overview():
    """Worklist: every claim with its project state and verdict, if any."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT c.id AS claim_id, c.project_id, c.target_repo, c.target_commit,
                   c.vuln_class, c.created_at, c.payload_json,
                   p.title, p.status AS project_status,
                   v.status AS verdict_status, v.sub_reason, v.marker,
                   (SELECT description FROM facts f WHERE f.project_id = c.project_id
                    ORDER BY f.rowid DESC LIMIT 1) AS last_fact
            FROM claims c
            JOIN projects p ON p.id = c.project_id
            LEFT JOIN verdicts v ON v.project_id = c.project_id
            ORDER BY c.created_at
            """
        ).fetchall()
        items = []
        for row in rows:
            try:
                poc_type = (json.loads(row["payload_json"]).get("poc") or {}).get("type")
            except json.JSONDecodeError:
                poc_type = None
            items.append(
                {
                    "claim_id": row["claim_id"],
                    "project_id": row["project_id"],
                    "target_repo": row["target_repo"],
                    "target_commit": row["target_commit"],
                    "vuln_class": row["vuln_class"],
                    "poc_type": poc_type,
                    "created_at": row["created_at"],
                    "title": row["title"],
                    "project_status": row["project_status"],
                    "verdict_status": row["verdict_status"],
                    "sub_reason": row["sub_reason"],
                    "marker": row["marker"],
                    "last_fact": row["last_fact"],
                }
            )
        return {"claims": items}


@router.get("/projects/{project_id}/evidence/{name}")
def get_evidence(project_id: str, name: str):
    if name not in EVIDENCE_FILES:
        raise HTTPException(404, f"Unknown evidence file; one of {EVIDENCE_FILES}")
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
    path = _evidence_path(project_id, name)
    if not path.is_file():
        raise HTTPException(404, "Evidence file not written yet")
    return PlainTextResponse(path.read_text(errors="replace"), media_type="application/json")


def _evidence_path(project_id: str, name: str) -> Path:
    # project ids are server-generated (proj_NNN); keep the path airtight anyway
    safe = "".join(ch for ch in project_id if ch.isalnum() or ch in "-_")
    return db.evidence_root() / safe / name


# ----------------------------------------------------------------------
# exporters (Phase 7): report, CI exit code, badge


@router.get("/projects/{project_id}/exit-code")
def get_exit_code(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = _verdict_row(conn, project_id)
    code = 1 if row and row["status"] == "reproduced" else 0
    return PlainTextResponse(str(code), media_type="text/plain")


@router.get("/projects/{project_id}/badge.svg")
def get_badge(project_id: str):
    with get_conn() as conn:
        row = _verdict_row(conn, project_id)
    if row is None:
        label, color = "verifying", "#52635E"
    elif row["status"] == "reproduced":
        label, color = "reproduced", "#F0603E"
    elif row["status"] == "not_reproduced":
        label, color = "not reproduced", "#48C98A"
    else:
        label = f"inconclusive · {row['sub_reason'] or '?'}".lower()
        color = "#E3A93C"
    return _shield_svg(label, color)


def _shield_svg(label: str, color: str) -> Response:
    left, right = "cairn", label
    width_left, width_right = 6 * len(left) + 14, 6.2 * len(right) + 14
    total = int(width_left + width_right)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img">
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
 <rect width="{int(width_left)}" height="20" fill="#243034"/>
 <rect x="{int(width_left)}" width="{int(width_right) + 1}" height="20" fill="{color}"/>
 <rect width="{total}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="10">
 <text x="{int(width_left / 2) + 1}" y="14">{left}</text>
 <text x="{int(width_left + width_right / 2) + 1}" y="14">{right}</text>
</g>
</svg>"""
    return Response(svg, media_type="image/svg+xml")


@router.get("/projects/{project_id}/report")
def get_report(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        claim_row = conn.execute(
            "SELECT * FROM claims WHERE project_id = ?", (project_id,)
        ).fetchone()
        verdict = _verdict_row(conn, project_id)
        handback = conn.execute(
            "SELECT payload_json FROM handbacks WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    lines = ["# Cairn v2 — Verification Report", ""]
    if claim_row:
        lines += [
            f"- **Claim**: {claim_row['id']} from {claim_row['source']} (untrusted)",
            f"- **Target**: {claim_row['target_repo']} @ {claim_row['target_commit']}",
            f"- **Class**: {claim_row['vuln_class']} · PoC sealed ({claim_row['poc_digest'][:20]}…)",
            "",
        ]
    if verdict is None:
        lines += ["_No verdict yet — run in progress._"]
        return PlainTextResponse("\n".join(lines), media_type="text/markdown")

    lines += [
        f"## Verdict: **{verdict['status'].upper()}**"
        + (f" · {verdict['sub_reason']}" if verdict["sub_reason"] else ""),
        "",
        verdict["detail"] or "",
        "",
    ]
    if verdict["marker"]:
        lines += [f"- marker `{verdict['marker']}` observed out-of-band (oracle `{verdict['oracle_id']}`)", ""]
    lines += [f"- cost: ${verdict['cost_usd']:.2f} · duration: {verdict['duration_s']:.1f}s", ""]

    manifest = _read_evidence_json(project_id, "replay_manifest.json")
    if manifest:
        lines += ["## Replay manifest", "", "```json", json.dumps(manifest, indent=2), "```", ""]
    observation = _read_evidence_json(project_id, "observation.json")
    if observation:
        lines += ["## Independent observation", "", "```json", json.dumps(observation, indent=2), "```", ""]
    poc = _read_evidence_json(project_id, "poc_output.json")
    if poc:
        sealed = dict(poc)
        sealed.pop("stdout", None)
        sealed.pop("stderr", None)
        lines += ["## PoC outcome (output sealed)", "", "```json", json.dumps(sealed, indent=2), "```", ""]
    if handback:
        lines += ["## Handback to Strix", "", "```json", handback["payload_json"], "```", ""]
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


def _read_evidence_json(project_id: str, name: str) -> dict | None:
    path = _evidence_path(project_id, name)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
