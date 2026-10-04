"""Verification pipeline (Cairn v2) — the deterministic spine on the board.

For each claim project the dispatcher walks:

    bring-up ─► execute ─► observe ─► verdict ─► (handback) ─► complete

One stage per ``step()`` call (the dispatcher loop calls it each cycle).
Every stage is a real Intent (creator ``dispatcher.verify``, worker
``cairn.verify``) concluded with a Fact, so the run tells its story on the
board and the console can render the signal path.

Machine state lives in the evidence bundle (``_state.json``) so runs resume
across dispatcher restarts; the board is the human/audit view.  Budget
breaches and stalls (no progress across cycles) terminate the run — it
never hangs.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from cairn.sandbox.manager import SandboxManager
from cairn.verification.bringup import BringUpResult, BringUpService
from cairn.verification.budget import BudgetLedger
from cairn.verification.config import VerificationConfig
from cairn.verification.execute import ExecutionOutcome, PocRunner
from cairn.verification.oracles import oracle_for
from cairn.verification.verdict import (
    EvidenceWriter,
    VerdictData,
    build_handback,
    decide,
)

LOG = logging.getLogger(__name__)

WORKER = "cairn.verify"
STAGES = ("bringup", "execute", "observe", "verdict", "done")
_STALL_LIMIT = 3


class ServerGateway:
    """Thin server client — works with requests.Session or FastAPI TestClient."""

    def __init__(self, session: Any, base_url: str = "", timeout: float | None = None):
        self.session = session
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def get(self, path: str):
        if self.timeout is None:
            return self.session.get(self._url(path))
        return self.session.get(self._url(path), timeout=self.timeout)

    def post(self, path: str, body: dict | None = None):
        if self.timeout is None:
            return self.session.post(self._url(path), json=body)
        return self.session.post(self._url(path), json=body, timeout=self.timeout)


class VerificationPipeline:
    def __init__(
        self,
        gateway: ServerGateway,
        sandbox: SandboxManager,
        config: VerificationConfig | None = None,
    ):
        self.gateway = gateway
        self.sandbox = sandbox
        self.config = config or VerificationConfig()
        self.bringup = BringUpService(sandbox, self.config)
        self.runner = PocRunner(sandbox, self.config)
        self.evidence_root = self.config.evidence_root()

    # ------------------------------------------------------------------

    def step(self, project_id: str) -> dict[str, Any]:
        """Advance one stage; returns a summary of what happened."""
        if self._get_project(project_id)[0] != 200:
            return {"project_id": project_id, "action": "gone"}

        resp = self.gateway.get(f"/projects/{project_id}/claim")
        if resp.status_code != 200:
            return {"project_id": project_id, "action": "not-a-claim"}
        claim = resp.json()

        if self.gateway.get(f"/projects/{project_id}/verdict").status_code == 200:
            return {"project_id": project_id, "action": "already-terminal"}

        evidence = EvidenceWriter(self.evidence_root, project_id)
        state: dict[str, Any] = evidence.read_state()
        ledger = self._restore_ledger(state, claim)

        # stall detection: same stage, same accumulated results, repeatedly —
        # the signature changes only when a stage actually progresses
        signature = ":".join(
            str(part)
            for part in (
                state.get("stage"),
                (state.get("bringup") or {}).get("ok"),
                (state.get("execution") or {}).get("clean"),
                (state.get("oracle") or {}).get("status"),
                state.get("verdict"),
            )
        )
        if state.get("last_signature") == signature:
            state["stall"] = int(state.get("stall", 0)) + 1
        else:
            state["stall"] = 0
            state["last_signature"] = signature

        stalled = state.get("stall", 0) >= _STALL_LIMIT
        budget_breach = ledger.breach()
        if budget_breach or stalled:
            # a confirmed marker already in hand outranks any stop condition;
            # stalls conclude ORACLE_AMBIGUOUS (decide() with no signals), real
            # breaches conclude BUDGET_EXHAUSTED
            confirmed = state.get("oracle", {}).get("status") == "confirmed"
            summary = self._finalize(
                project_id, claim, evidence, state, ledger,
                bringup_ok=state.get("bringup", {}).get("ok") if state.get("bringup") else None,
                execution=state.get("execution"),
                oracle=state.get("oracle"),
                budget_breach=None if (stalled or confirmed) else budget_breach,
            )
            return summary

        ledger.step()
        stage = state.get("stage", "bringup")
        try:
            if stage == "bringup":
                summary = self._stage_bringup(project_id, claim, evidence, state, ledger)
            elif stage == "execute":
                summary = self._stage_execute(project_id, claim, evidence, state, ledger)
            elif stage == "observe":
                summary = self._stage_observe(project_id, claim, evidence, state, ledger)
            else:
                summary = self._finalize(
                    project_id, claim, evidence, state, ledger,
                    bringup_ok=state.get("bringup", {}).get("ok") if state.get("bringup") else None,
                    execution=state.get("execution"),
                    oracle=state.get("oracle"),
                )
        except Exception as exc:  # noqa: BLE001 - one bad step must not kill the run; stall detection terminates retries
            LOG.exception("verification stage %s failed project=%s", stage, project_id)
            errors = state.setdefault("errors", [])
            errors.append(f"{stage}: {type(exc).__name__}: {exc}"[:500])
            summary = {"project_id": project_id, "action": "stage-error", "stage": stage}
        finally:
            self._save(evidence, state, ledger)
        return summary

    # ------------------------------------------------------------------
    # stages

    def _stage_bringup(self, project_id, claim, evidence, state, ledger) -> dict:
        result = self.bringup.bring_up(project_id, claim)
        state["bringup"] = {
            "ok": result.ok,
            "endpoint": result.endpoint,
            "strategy": result.strategy,
            "recipe": result.recipe,
            "attempts": result.attempts,
            "log": result.log,
            "duration_s": result.duration_s,
        }
        if result.ok:
            description = (
                f"BRING-UP OK — {result.strategy}: target healthy at {result.endpoint} "
                f"({result.duration_s:.1f}s); recipe recorded for replay"
            )
        else:
            dead_ends = "; ".join(
                f"{a['strategy']}: {a['detail']}" for a in result.attempts if not a.get("ok")
            )
            description = f"BRING-UP FAILED — no strategy produced a healthy target. Tried: {dead_ends}"
        fact_id = self._run_intent(project_id, "bring-up: discover + boot the pinned target", description)
        state.setdefault("fact_ids", {})["bringup"] = fact_id
        state["stage"] = "execute" if result.ok else "verdict"
        return {"project_id": project_id, "action": "bringup", "ok": result.ok, "endpoint": result.endpoint}

    def _stage_execute(self, project_id, claim, evidence, state, ledger) -> dict:
        oracle = oracle_for(claim.get("vuln_class", "other"))
        context = {
            "run_id": project_id,
            "sandbox": self.sandbox,
            "claim": claim,
            "recipe": (state.get("bringup") or {}).get("recipe") or {},
            "state": state.setdefault("oracle_state", {}),
        }
        extra_env = oracle.instrument(context)

        endpoint = state["bringup"]["endpoint"]
        self.sandbox.ensure_collector(project_id)
        ledger.payload_run()
        outcome = self.runner.run(project_id, claim["poc"], endpoint, extra_env=extra_env)
        state["execution"] = {
            "clean": outcome.clean,
            "summary": outcome.summary(),
            "json": self.runner.outcome_to_json(outcome),
        }
        state["oracle_id"] = oracle.id

        if outcome.clean:
            description = f"EXECUTE — PoC ran clean rc=0 in {outcome.duration_s:.1f}s against {endpoint}"
        else:
            description = f"EXECUTE — {outcome.summary()} (treated as POC_ERROR, never not_reproduced)"
        fact_id = self._run_intent(project_id, "execute: drive the claim's PoC at the live target", description)
        state.setdefault("fact_ids", {})["execute"] = fact_id
        state["stage"] = "observe" if outcome.clean else "verdict"
        return {"project_id": project_id, "action": "execute", "clean": outcome.clean}

    def _stage_observe(self, project_id, claim, evidence, state, ledger) -> dict:
        oracle = oracle_for(claim.get("vuln_class", "other"))
        context = {
            "run_id": project_id,
            "sandbox": self.sandbox,
            "claim": claim,
            "recipe": (state.get("bringup") or {}).get("recipe") or {},
            "state": state.setdefault("oracle_state", {}),
            "execution_stdout": (state.get("execution") or {}).get("json", {}).get("stdout", ""),
        }
        outcome = oracle.observe(context)
        state["oracle"] = {
            "id": oracle.id,
            "status": outcome.status,
            "marker": outcome.marker,
            "reason": outcome.reason,
            "evidence": outcome.evidence,
        }
        if outcome.status == "confirmed":
            description = (
                f"EFFECT CONFIRMED — marker {outcome.marker} observed in the collector "
                "out-of-band; Strix's claimed signal was never consulted"
            )
        elif outcome.status == "not_confirmed":
            description = f"EFFECT NOT OBSERVED — {outcome.reason}"
        else:
            description = f"ORACLE AMBIGUOUS — {outcome.reason}"
        fact_id = self._run_intent(project_id, "observe: confirm the effect via the armed oracle", description)
        state.setdefault("fact_ids", {})["observe"] = fact_id
        state["stage"] = "verdict"
        return {"project_id": project_id, "action": "observe", "status": outcome.status}

    # ------------------------------------------------------------------
    # terminal

    def _finalize(self, project_id, claim, evidence, state, ledger, *, bringup_ok, execution, oracle, budget_breach=None) -> dict:
        bringup_dict = state.get("bringup")
        execution_clean = execution.get("clean") if execution else None
        verdict = decide(
            claim_id=claim["claim_id"],
            bringup_ok=bringup_ok,
            execution_clean=execution_clean,
            oracle_status=(oracle or {}).get("status"),
            oracle_marker=(oracle or {}).get("marker"),
            oracle_id=(oracle or {}).get("id"),
            budget_breach=budget_breach,
            execution_summary=(execution or {}).get("summary", ""),
            bringup_detail=(bringup_dict or {}).get("log", "")[-2000:],
        )
        verdict.duration_s = ledger.elapsed_s()
        verdict.cost_usd = ledger.cost_usd
        verdict.evidence_dir = str(evidence.dir)

        manifest_path = evidence.write_all(
            claim=claim,
            verdict=verdict,
            bringup=bringup_dict,
            execution=(execution or {}).get("json"),
            oracle=oracle,
            budget=ledger.snapshot(),
            hits=self.sandbox.hits(project_id),
            poc_digest=claim.get("poc_digest", ""),
        )

        resp = self.gateway.post(
            f"/projects/{project_id}/verdict",
            {
                "claim_id": verdict.claim_id,
                "status": verdict.status,
                "sub_reason": verdict.sub_reason,
                "marker": verdict.marker,
                "oracle_id": verdict.oracle_id,
                "cost_usd": verdict.cost_usd,
                "duration_s": verdict.duration_s,
                "detail": verdict.detail,
                "evidence_dir": verdict.evidence_dir,
            },
        )
        if resp.status_code not in (200, 201):
            LOG.error("verdict write failed project=%s rc=%s %s", project_id, resp.status_code, resp.text)
            return {"project_id": project_id, "action": "verdict-write-failed", "detail": resp.text}

        handback = None
        if verdict.status != "reproduced":
            poc_invocation = " ".join((execution or {}).get("json", {}).get("argv", [])) or "(not reached)"
            handback = build_handback(
                claim=claim,
                verdict=verdict,
                live_endpoint=(bringup_dict or {}).get("endpoint"),
                poc_invocation=poc_invocation,
                poc_output={
                    "rc": (execution or {}).get("json", {}).get("rc"),
                    "stderr": ((execution or {}).get("json", {}).get("stderr") or "")[-2000:],
                    "sealed": True,
                },
                oracle_expected=self._oracle_expectation(claim, verdict.oracle_id),
                wait_window_s=5.0,
                replay_manifest=str(manifest_path.name),
            )
            self.gateway.post(f"/projects/{project_id}/handback", {"payload": handback})

        fact_id = self._run_intent(
            project_id,
            "verdict: terminal",
            f"VERDICT — {verdict.summary_line()}; evidence bundle written for replay",
        )
        state.setdefault("fact_ids", {})["verdict"] = fact_id
        state["stage"] = "done"
        state["verdict"] = {
            "status": verdict.status,
            "sub_reason": verdict.sub_reason,
            "marker": verdict.marker,
        }

        last_fact = fact_id or "origin"
        self.gateway.post(
            f"/projects/{project_id}/complete",
            {
                "from": [last_fact],
                "description": f"[claim {verdict.claim_id}] {verdict.summary_line()}",
                "worker": WORKER,
            },
        )

        # terminal → tear the sandbox down
        try:
            self.bringup.teardown(project_id, (bringup_dict or {}).get("recipe") or {})
            self.sandbox.teardown(project_id)
        except Exception as exc:  # noqa: BLE001 - teardown is best effort after a terminal
            LOG.warning("sandbox teardown failed project=%s: %s", project_id, exc)

        return {
            "project_id": project_id,
            "action": "verdict",
            "verdict": verdict.status,
            "sub_reason": verdict.sub_reason,
            "marker": verdict.marker,
        }

    @staticmethod
    def _oracle_expectation(claim: dict, oracle_id: str | None) -> str:
        if oracle_id and "nonce" in oracle_id:
            return "a fresh Cairn-chosen nonce observed on the collector (out-of-band)"
        if oracle_id == "sqli/seeded-row":
            return "the exact Cairn-seeded secret value returned by the PoC"
        if oracle_id and oracle_id.startswith("sentinel"):
            return "the Cairn-planted sentinel content returned by the PoC"
        return "a Cairn-controlled marker (none automated for this class)"

    # ------------------------------------------------------------------
    # board plumbing: intent lifecycle per stage

    def _run_intent(self, project_id: str, intent_description: str, fact_description: str) -> str | None:
        created = self.gateway.post(
            f"/projects/{project_id}/intents",
            {"from": ["origin"], "description": intent_description, "creator": "dispatcher.verify", "worker": None},
        )
        if created.status_code not in (200, 201):
            LOG.error("intent create failed project=%s rc=%s", project_id, created.status_code)
            return None
        intent_id = created.json()["id"]
        self.gateway.post(f"/projects/{project_id}/intents/{intent_id}/heartbeat", {"worker": WORKER})
        concluded = self.gateway.post(
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            {"worker": WORKER, "description": fact_description},
        )
        if concluded.status_code not in (200, 201):
            LOG.error("conclude failed project=%s intent=%s rc=%s", project_id, intent_id, concluded.status_code)
            return None
        return concluded.json().get("fact", {}).get("id")

    def _get_project(self, project_id: str):
        resp = self.gateway.get(f"/projects/{project_id}")
        return resp.status_code, (resp.json() if resp.status_code == 200 else {})

    # ------------------------------------------------------------------

    def _restore_ledger(self, state: dict, claim: dict) -> BudgetLedger:
        saved = state.get("ledger") or {}
        ledger = BudgetLedger(caps=self.config.budget)
        if saved:
            ledger.steps = saved.get("steps", 0)
            ledger.payload_runs = saved.get("payload_runs", 0)
            ledger.cost_usd = saved.get("cost_usd", 0.0)
            ledger.tokens = saved.get("tokens", 0)
            started = saved.get("started_at_unix")
            if started:
                ledger.started_at = started
        else:
            ledger.start()
        return ledger

    def _save(self, evidence: EvidenceWriter, state: dict, ledger: BudgetLedger) -> None:
        attempts = state.setdefault("attempts", {})
        stage = state.get("stage", "bringup")
        attempts[stage] = attempts.get(stage, 0) + 1
        state["ledger"] = {
            "steps": ledger.steps,
            "payload_runs": ledger.payload_runs,
            "cost_usd": ledger.cost_usd,
            "tokens": ledger.tokens,
            "started_at_unix": ledger.started_at,
        }
        state["updated_at_unix"] = time.time()
        evidence.write_state(state)
