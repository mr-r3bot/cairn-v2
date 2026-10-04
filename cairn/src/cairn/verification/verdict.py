"""Verdict logic + evidence bundles (Cairn v2, Phase 5) and the Strix
handback (Phase 5.5).

Verdicts are conservative by construction:

- ``reproduced`` — ONLY when the oracle marker fired (Cairn-controlled,
  chosen post-boot, observed out-of-band).  Nothing else upgrades a claim.
- ``not_reproduced`` — target booted, PoC ran clean (rc == 0), marker never
  fired within bounds.
- ``inconclusive`` with a sub-reason otherwise:
  ``BRING_UP_FAILED | POC_ERROR | ORACLE_AMBIGUOUS | BUDGET_EXHAUSTED``.

Default is inconclusive; ambiguity never upgrades.  A false ``reproduced``
is the worst failure mode.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUB_BRING_UP_FAILED = "BRING_UP_FAILED"
SUB_POC_ERROR = "POC_ERROR"
SUB_ORACLE_AMBIGUOUS = "ORACLE_AMBIGUOUS"
SUB_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
SUB_REASONS = (SUB_BRING_UP_FAILED, SUB_POC_ERROR, SUB_ORACLE_AMBIGUOUS, SUB_BUDGET_EXHAUSTED)


@dataclass
class VerdictData:
    claim_id: str
    status: str = "inconclusive"  # default inconclusive — never assume proof
    sub_reason: str | None = None
    marker: str | None = None
    oracle_id: str | None = None
    cost_usd: float = 0.0
    duration_s: float = 0.0
    evidence_dir: str = ""
    detail: str = ""

    @property
    def terminal(self) -> bool:
        return True

    def summary_line(self) -> str:
        base = self.status.upper()
        if self.sub_reason:
            base += f" / {self.sub_reason}"
        if self.marker:
            base += f" — marker {self.marker[:8]}… observed out-of-band"
        return base


def decide(
    *,
    claim_id: str,
    bringup_ok: bool | None,
    execution_clean: bool | None,
    oracle_status: str | None,
    oracle_marker: str | None,
    oracle_id: str | None,
    budget_breach: str | None = None,
    execution_summary: str = "",
    bringup_detail: str = "",
) -> VerdictData:
    """Terminal decision from the run's raw signals. One verdict, exactly once."""
    data = VerdictData(claim_id=claim_id, oracle_id=oracle_id)

    if bringup_ok is False:
        data.status = "inconclusive"
        data.sub_reason = SUB_BRING_UP_FAILED
        data.detail = bringup_detail or "target never ran; the PoC was never fairly tested"
        return data

    if oracle_status == "confirmed":
        data.status = "reproduced"
        data.marker = oracle_marker
        data.detail = "Cairn independently achieved the claimed effect inside the sandbox"
        return data

    if budget_breach:
        data.status = "inconclusive"
        data.sub_reason = SUB_BUDGET_EXHAUSTED
        data.detail = f"run paused on budget breach: {budget_breach}"
        return data

    if execution_clean is False:
        data.status = "inconclusive"
        data.sub_reason = SUB_POC_ERROR
        data.detail = execution_summary or "PoC errored before reaching the target"
        return data

    if oracle_status == "not_confirmed":
        data.status = "not_reproduced"
        data.detail = "booted fine, PoC ran clean, effect never fired"
        return data

    data.status = "inconclusive"
    data.sub_reason = SUB_ORACLE_AMBIGUOUS
    data.detail = "something happened, effect not cleanly proven"
    return data


# ----------------------------------------------------------------------
# evidence bundle


class EvidenceWriter:
    """Writes the replayable evidence bundle for one verification run."""

    def __init__(self, root: Path, project_id: str):
        self.dir = root / project_id
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        return self.dir / name

    def write_all(
        self,
        *,
        claim: dict,
        verdict: VerdictData,
        bringup: dict | None,
        execution: dict | None,
        oracle: dict | None,
        budget: dict | None,
        hits: list[dict],
        poc_digest: str,
    ) -> Path:
        manifest = {
            "claim_id": verdict.claim_id,
            "target": {
                "repo": claim.get("target_repo"),
                "commit": claim.get("target_commit"),
                "image": claim.get("target_image"),
            },
            "boot_recipe": (bringup or {}).get("recipe"),
            "poc": {"sealed": True, "digest": poc_digest, "type": (claim.get("poc") or {}).get("type")},
            "oracle": {"id": verdict.oracle_id, "verdict_marker": verdict.marker,
                       "note": "nonce regenerated per replay — never reused"},
            "verdict": {
                "status": verdict.status,
                "sub_reason": verdict.sub_reason,
                "detail": verdict.detail,
            },
            "budget": budget,
            "cost_usd": verdict.cost_usd,
            "duration_s": verdict.duration_s,
            "generated_at_unix": round(time.time(), 3),
        }
        self._write_json("replay_manifest.json", manifest)
        if bringup is not None:
            self._write_json("boot.json", bringup)
        if execution is not None:
            self._write_json("poc_output.json", execution)
        if oracle is not None:
            self._write_json("observation.json", oracle)
        self._write_json("collector_hits.json", hits)
        return self.path("replay_manifest.json")

    def write_state(self, state: dict) -> None:
        """Pipeline machine state (robust resume across dispatcher cycles)."""
        self._write_json("_state.json", state)

    def read_state(self) -> dict:
        path = self.path("_state.json")
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_json(self, name: str, payload: Any) -> None:
        self.path(name).write_text(json.dumps(payload, indent=2, default=str))


# ----------------------------------------------------------------------
# handback (Phase 5.5) — shaped by the sub-reason


def build_handback(
    *,
    claim: dict,
    verdict: VerdictData,
    live_endpoint: str | None,
    poc_invocation: str,
    poc_output: dict | None,
    oracle_expected: str,
    wait_window_s: float,
    replay_manifest: str,
) -> dict:
    """The inverse of the ingestion contract: verdict + reproduction context."""
    status = verdict.status
    sub = verdict.sub_reason

    if sub == SUB_BRING_UP_FAILED:
        message = (
            "target never ran; your PoC was never fairly tested. This is an "
            "environment issue, not a PoC failure — supply a run recipe "
            "(run_hints) or skip; do not re-hunt."
        )
    elif sub == SUB_POC_ERROR:
        message = (
            "PoC crashed before reaching the target. Exact rc/stderr attached, "
            "plus the live endpoint it should have hit."
        )
    elif status == "not_reproduced":
        message = (
            "booted fine, PoC ran clean, effect never fired. Either not real, "
            "or the PoC is logically wrong."
        )
    else:  # ORACLE_AMBIGUOUS / BUDGET_EXHAUSTED
        message = "something happened but the effect was not cleanly proven — flag for human review or a retry."

    return {
        "kind": "handback",
        "claim_id": verdict.claim_id,
        "status": status,
        "sub_reason": sub,
        "message": message,
        "live_endpoint": live_endpoint,
        "poc_invocation": poc_invocation,
        "poc_output": poc_output or {},
        "oracle_expected": oracle_expected,
        "wait_window_s": wait_window_s,
        "replay_manifest_ref": replay_manifest,
        "repair_attempts": [],
        "oracle_id": verdict.oracle_id,
    }
