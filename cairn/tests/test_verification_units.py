"""Docker-free unit tests for the verification modules (Phases 2-6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cairn.sandbox.config import SandboxConfig
from cairn.sandbox.manager import SandboxManager
from cairn.verification.bringup import BringUpService
from cairn.verification.budget import BudgetConfig, BudgetLedger
from cairn.verification.config import VerificationConfig
from cairn.verification.execute import PocRunner
from cairn.verification.oracles import (
    NoopOracle,
    RceNonceOracle,
    SeededRowOracle,
    beacon_command,
    new_nonce,
    oracle_for,
)
from cairn.verification.verdict import (
    SUB_BRING_UP_FAILED,
    SUB_BUDGET_EXHAUSTED,
    SUB_ORACLE_AMBIGUOUS,
    SUB_POC_ERROR,
    EvidenceWriter,
    build_handback,
    decide,
)


@pytest.fixture()
def sandbox(tmp_path) -> SandboxManager:
    return SandboxManager(SandboxConfig(data_home=tmp_path))


@pytest.fixture()
def config(tmp_path) -> VerificationConfig:
    return VerificationConfig(sandbox=SandboxConfig(data_home=tmp_path))


# =====================================================================
# Phase 2 — discovery ranking
# =====================================================================


def test_discovery_ranks_image_then_compose_then_dockerfile(tmp_path, sandbox, config):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {web: {image: x, ports: ['8080']}}")
    (checkout / "Dockerfile").write_text("FROM python:3.13-slim")
    (checkout / "Makefile").write_text("run:\n\tdocker compose up\n")
    (checkout / "bin").mkdir()
    (checkout / "bin" / "start.sh").write_text("#!/bin/sh\n")
    (checkout / "README.md").write_text("## Run\n```bash\ndocker compose up\n```\n")

    service = BringUpService(sandbox, config)
    ranked = service.discover(checkout, {"target_image": "registry/app:1.0"})
    order = [(rank, name) for rank, name, _ in ranked]
    assert order == [
        (0, "image"),
        (10, "compose"),
        (20, "dockerfile"),
        (30, "make"),
        (40, "script"),
        (50, "readme"),
    ]


def test_discovery_detects_compose_variants_and_skips_absent(tmp_path, sandbox, config):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "compose.yaml").write_text("services: {}")
    service = BringUpService(sandbox, config)
    ranked = service.discover(checkout, {})
    assert [(r, n) for r, n, _ in ranked] == [(10, "compose")]


def test_make_and_script_detected_only_when_matching(tmp_path, sandbox, config):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "Makefile").write_text("build:\n\tgo build\n")  # no run-ish target
    service = BringUpService(sandbox, config)
    ranked = service.discover(checkout, {})
    assert ranked == []  # nothing bootable, nothing matching


def test_checkout_hint_must_exist(tmp_path, sandbox, config):
    service = BringUpService(sandbox, config)
    with pytest.raises(RuntimeError, match="checkout_dir"):
        service.ensure_checkout("r1", {"run_hints": {"checkout_dir": str(tmp_path / "nope")}})


# =====================================================================
# Phase 3 — PoC building
# =====================================================================


def test_build_script_python(sandbox, config):
    argv, files = PocRunner(sandbox, config).build(
        {"type": "script", "language": "python", "payload": "print(1)"}, "http://target:8080"
    )
    assert argv == ["python3", "/scratch/poc.py"]
    assert files == {"poc.py": "print(1)"}


def test_build_script_bash_and_sh(sandbox, config):
    runner = PocRunner(sandbox, config)
    argv, _ = runner.build({"type": "script", "language": "bash", "payload": ":"}, "http://t:1")
    assert argv[0] == "bash"
    argv, _ = runner.build({"type": "script", "language": "sh", "payload": ":"}, "http://t:1")
    assert argv[0] == "sh"


def test_build_http_substitutes_target_placeholder(sandbox, config):
    argv, files = PocRunner(sandbox, config).build(
        {"type": "http", "method": "POST", "url": "{TARGET}/api/connectors", "body": "x=1"},
        "http://target:8090",
    )
    assert argv == ["python3", "/scratch/poc_http.py"]
    assert "'http://target:8090/api/connectors'" in files["poc_http.py"]
    assert "'POST'" in files["poc_http.py"]
    # an HTTP error response must not crash the runner (clean rc still possible)
    assert "HTTPError" in files["poc_http.py"]


def test_build_command_passthrough_and_rejects_unknown(sandbox, config):
    runner = PocRunner(sandbox, config)
    argv, files = runner.build({"type": "command", "argv": ["nmap", "-p", "80", "target"]}, "http://t:1")
    assert argv == ["nmap", "-p", "80", "target"] and files == {}
    with pytest.raises(ValueError):
        runner.build({"type": "telnet"}, "http://t:1")


# =====================================================================
# Phase 4 — oracles
# =====================================================================


def test_registry_maps_classes_to_oracles():
    assert oracle_for("rce").id == "rce/nonce-callback"
    assert oracle_for("deserialization").id == "rce/nonce-callback"
    assert oracle_for("ssrf").id == "ssrf/nonce-callback"
    assert oracle_for("sqli").id == "sqli/seeded-row"
    assert oracle_for("authbypass").id == "sentinel/planted-file"
    assert oracle_for("xss").id == "none/manual-review"
    assert oracle_for("other").id == "none/manual-review"


def test_rce_oracle_instrument_sets_beacon_command(sandbox):
    oracle = RceNonceOracle()
    context = {"sandbox": sandbox, "state": {}}
    env = oracle.instrument(context)
    nonce = context["state"]["nonce"]
    assert env["CAIRN_NONCE"] == nonce
    assert nonce in env["CAIRN_CMD"]
    assert "beacon" in env["CAIRN_CMD"]


def test_beacon_command_has_tool_fallbacks():
    cmd = beacon_command("http://collector:9931", "abcd1234")
    assert "curl" in cmd and "wget" in cmd and "urllib" in cmd
    assert "http://collector:9931/beacon/abcd1234" in cmd


def test_rce_oracle_confirms_only_on_observed_nonce(sandbox, monkeypatch):
    oracle = RceNonceOracle()
    context = {"sandbox": sandbox, "state": {}}
    env = oracle.instrument(context)
    nonce = context["state"]["nonce"]

    # no hit → not_confirmed (never "probably")
    outcome = oracle.observe({"sandbox": sandbox, "run_id": "r1", "state": context["state"]})
    assert outcome.status == "not_confirmed"

    # hit → confirmed with the marker
    monkeypatch.setattr(
        sandbox, "wait_for_nonce", lambda n, run_id, timeout_s=5.0: {"path": f"/beacon/{n}"}
    )
    outcome = oracle.observe({"sandbox": sandbox, "run_id": "r1", "state": context["state"]})
    assert outcome.status == "confirmed"
    assert outcome.marker == nonce


def test_seeded_row_leans_ambiguous_without_hook(sandbox):
    oracle = SeededRowOracle()
    context = {"sandbox": sandbox, "state": {}, "claim": {"run_hints": {}}, "recipe": {}}
    oracle.instrument(context)
    outcome = oracle.observe({**context, "execution_stdout": "whatever strix claimed"})
    assert outcome.status == "ambiguous"
    assert "seed_command" in outcome.reason


def test_noop_oracle_is_ambiguous():
    outcome = oracle_for("xss").observe({})
    assert outcome.status == "ambiguous"


def test_nonces_are_fresh():
    assert len({new_nonce() for _ in range(64)}) == 64


# =====================================================================
# Phase 5 — verdict decision table
# =====================================================================


def test_verdict_requires_boot_first():
    v = decide(claim_id="c1", bringup_ok=False, execution_clean=None, oracle_status=None, oracle_marker=None, oracle_id=None)
    assert (v.status, v.sub_reason) == ("inconclusive", SUB_BRING_UP_FAILED)


def test_verdict_confirmed_marker_beats_everything():
    v = decide(
        claim_id="c1", bringup_ok=True, execution_clean=True,
        oracle_status="confirmed", oracle_marker="deadbeef", oracle_id="rce/nonce-callback",
        budget_breach="wall clock 9999s > 10s",
    )
    assert v.status == "reproduced" and v.marker == "deadbeef"


def test_verdict_budget_breach():
    v = decide(claim_id="c1", bringup_ok=True, execution_clean=None, oracle_status=None,
               oracle_marker=None, oracle_id=None, budget_breach="steps 60 >= 60")
    assert (v.status, v.sub_reason) == ("inconclusive", SUB_BUDGET_EXHAUSTED)


def test_verdict_poc_error_before_not_reproduced():
    v = decide(claim_id="c1", bringup_ok=True, execution_clean=False, oracle_status=None,
               oracle_marker=None, oracle_id=None, execution_summary="PoC exited rc=3")
    assert (v.status, v.sub_reason) == ("inconclusive", SUB_POC_ERROR)


def test_verdict_clean_but_no_effect():
    v = decide(claim_id="c1", bringup_ok=True, execution_clean=True, oracle_status="not_confirmed",
               oracle_marker=None, oracle_id="rce/nonce-callback")
    assert (v.status, v.sub_reason) == ("not_reproduced", None)


def test_verdict_ambiguous_default():
    v = decide(claim_id="c1", bringup_ok=True, execution_clean=True, oracle_status="ambiguous",
               oracle_marker=None, oracle_id=None)
    assert (v.status, v.sub_reason) == ("inconclusive", SUB_ORACLE_AMBIGUOUS)
    v = decide(claim_id="c1", bringup_ok=None, execution_clean=None, oracle_status=None,
               oracle_marker=None, oracle_id=None)
    assert (v.status, v.sub_reason) == ("inconclusive", SUB_ORACLE_AMBIGUOUS)


# =====================================================================
# Phase 5 — evidence + handback
# =====================================================================


def test_evidence_writer_writes_manifest_and_state(tmp_path):
    writer = EvidenceWriter(tmp_path, "proj_001")
    verdict = decide(claim_id="claim_001", bringup_ok=True, execution_clean=True,
                     oracle_status="confirmed", oracle_marker="cafe", oracle_id="rce/nonce-callback")
    verdict.duration_s = 1.5
    path = writer.write_all(
        claim={"target_repo": "apache/gravitino", "target_commit": "a1b2c3d", "poc": {"type": "script"}},
        verdict=verdict,
        bringup={"ok": True, "recipe": {"strategy": "compose"}},
        execution={"clean": True, "rc": 0},
        oracle={"status": "confirmed", "marker": "cafe"},
        budget={"elapsed_s": 1.5},
        hits=[{"path": "/beacon/cafe"}],
        poc_digest="sha256:abc",
    )
    assert path.name == "replay_manifest.json"
    manifest = json.loads(path.read_text())
    assert manifest["verdict"]["status"] == "reproduced"
    assert manifest["poc"]["sealed"] is True and manifest["poc"]["digest"] == "sha256:abc"
    assert manifest["boot_recipe"]["strategy"] == "compose"

    writer.write_state({"stage": "execute"})
    assert writer.read_state()["stage"] == "execute"


def test_handback_shaped_by_sub_reason():
    def hb(sub):
        # each sub-reason corresponds to the signal combination that produces it
        signals = {
            SUB_BRING_UP_FAILED: dict(bringup_ok=False, execution_clean=None, oracle_status=None, budget_breach=None),
            SUB_POC_ERROR: dict(bringup_ok=True, execution_clean=False, oracle_status=None, budget_breach=None),
            SUB_BUDGET_EXHAUSTED: dict(bringup_ok=True, execution_clean=None, oracle_status=None, budget_breach="wall clock 9999s > 10s"),
            "not_reproduced": dict(bringup_ok=True, execution_clean=True, oracle_status="not_confirmed", budget_breach=None),
        }[sub]
        verdict = decide(claim_id="claim_001", oracle_marker=None, oracle_id="rce/nonce-callback", **signals)
        assert verdict.sub_reason == sub or (sub == "not_reproduced" and verdict.status == sub)
        return build_handback(
            claim={"target_repo": "redis/redis"},
            verdict=verdict,
            live_endpoint="http://target:8090" if sub != SUB_BRING_UP_FAILED else None,
            poc_invocation="python3 /scratch/poc.py",
            poc_output={"rc": 3, "stderr": "Traceback"},
            oracle_expected="a fresh Cairn-chosen nonce observed on the collector",
            wait_window_s=5.0,
            replay_manifest="replay_manifest.json",
        )

    bring_up = hb(SUB_BRING_UP_FAILED)
    assert "never fairly tested" in bring_up["message"]
    assert "environment issue" in bring_up["message"]
    assert bring_up["live_endpoint"] is None

    poc_error = hb(SUB_POC_ERROR)
    assert "crashed before reaching the target" in poc_error["message"]
    assert poc_error["poc_output"]["rc"] == 3

    not_repro = hb("not_reproduced")
    assert "effect never fired" in not_repro["message"]
    assert not_repro["live_endpoint"] == "http://target:8090"

    budget = hb(SUB_BUDGET_EXHAUSTED)
    assert "not cleanly proven" in budget["message"]


# =====================================================================
# Phase 6 — budget ledger
# =====================================================================


def test_budget_ledger_breaches():
    ledger = BudgetLedger(caps=BudgetConfig(wall_clock_s=10, max_steps=2, max_payload_runs=2, max_cost_usd=5.0))
    ledger.start()
    assert ledger.breach() is None
    ledger.step()
    ledger.payload_run()
    assert ledger.breach() is None  # the capped run itself is allowed
    ledger.step()
    breach = ledger.breach()
    assert "steps 2 >= 2" in breach  # breach blocks whatever comes next


def test_budget_ledger_wall_clock(monkeypatch):
    ledger = BudgetLedger(caps=BudgetConfig(wall_clock_s=10))
    ledger.started_at = 0.0
    monkeypatch.setattr("cairn.verification.budget.time.monotonic", lambda: 100.0)
    assert "wall clock" in ledger.breach()
