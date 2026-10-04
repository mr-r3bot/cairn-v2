"""PoC execution harness (Cairn v2, Phase 3).

Drives the claim's PoC (script / http / command) against the live endpoint
from inside the sandbox — never on the dispatcher host.  Raw outcome (rc,
stdout/stderr, timing) is captured for the board.

The distinction that matters: a PoC that errors before reaching the target
(rc != 0, or timeout) is ``POC_ERROR`` — *inconclusive* — never
``not_reproduced``.  Only a clean run (rc == 0) without the oracle marker
can conclude ``not_reproduced``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from cairn.sandbox.manager import SandboxManager
from cairn.verification.config import VerificationConfig

LOG = logging.getLogger(__name__)


@dataclass
class ExecutionOutcome:
    clean: bool  # rc == 0 → "ran clean"; otherwise POC_ERROR territory
    rc: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        if self.timed_out:
            return "PoC timed out before completing"
        if self.rc != 0:
            return f"PoC exited rc={self.rc} before running clean"
        return f"PoC ran clean rc=0 in {self.duration_s:.1f}s"


class PocRunner:
    def __init__(self, sandbox: SandboxManager, config: VerificationConfig | None = None):
        self.sandbox = sandbox
        self.config = config or VerificationConfig()

    # ------------------------------------------------------------------
    # payload preparation

    def build(self, poc: dict, endpoint: str) -> tuple[list[str], dict[str, str]]:
        """Map a claim PoC to (argv, files-to-drop-in-scratch)."""
        kind = poc.get("type")

        if kind == "script":
            language = poc.get("language", "bash")
            if language == "python":
                return ["python3", "/scratch/poc.py"], {"poc.py": poc["payload"]}
            shell = "bash" if language == "bash" else "sh"
            return [shell, "/scratch/poc.sh"], {"poc.sh": poc["payload"]}

        if kind == "http":
            runner = self._http_runner(poc, endpoint)
            return ["python3", "/scratch/poc_http.py"], {"poc_http.py": runner}

        if kind == "command":
            return list(poc["argv"]), {}

        raise ValueError(f"unsupported poc type: {kind!r}")

    @staticmethod
    def _http_runner(poc: dict, endpoint: str) -> str:
        url = str(poc.get("url", "")).replace("{TARGET}", endpoint)
        method = str(poc.get("method", "GET")).upper()
        headers = {str(k): str(v) for k, v in (poc.get("headers") or {}).items()}
        body = poc.get("body")
        return (
            "import urllib.request, urllib.error\n"
            f"url = {url!r}\n"
            f"method = {method!r}\n"
            f"headers = {headers!r}\n"
            f"body = {body!r}\n"
            "data = body.encode() if body is not None else None\n"
            "req = urllib.request.Request(url, data=data, headers=headers, method=method)\n"
            "try:\n"
            "    with urllib.request.urlopen(req, timeout=30) as resp:\n"
            "        print(resp.status)\n"
            "        print(resp.read().decode('utf-8', 'replace'))\n"
            "except urllib.error.HTTPError as exc:\n"
            "    print(exc.code)\n"
            "    print(exc.read().decode('utf-8', 'replace'))\n"
        )

    # ------------------------------------------------------------------
    # execution

    def run(
        self,
        run_id: str,
        poc: dict,
        endpoint: str,
        *,
        extra_env: dict[str, str] | None = None,
        timeout_s: int | None = None,
    ) -> ExecutionOutcome:
        argv, files = self.build(poc, endpoint)
        scratch = self.sandbox.scratch_dir(run_id)
        for name, content in files.items():
            (scratch / name).write_text(content)

        env = {
            "CAIRN_TARGET": endpoint,
            "CAIRN_COLLECTOR_URL": self.sandbox.collector_url(),
        }
        env.update(extra_env or {})

        LOG.info("executing PoC run=%s argv=%s", run_id, argv[:3])
        result = self.sandbox.run_payload(
            run_id,
            argv,
            env=env,
            timeout_s=timeout_s or self.config.sandbox.payload_timeout_s,
        )

        outcome = ExecutionOutcome(
            clean=(not result.timed_out) and result.rc == 0,
            rc=result.rc,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_s=result.duration_s,
            timed_out=result.timed_out,
            argv=argv,
            env={k: v for k, v in env.items() if not k.startswith("CAIRN_COLLECTOR")},
        )
        LOG.info("PoC done run=%s clean=%s rc=%s", run_id, outcome.clean, outcome.rc)
        return outcome

    # ------------------------------------------------------------------
    # serialization (evidence bundles)

    @staticmethod
    def outcome_to_json(outcome: ExecutionOutcome) -> dict[str, Any]:
        return {
            "clean": outcome.clean,
            "rc": outcome.rc,
            "timed_out": outcome.timed_out,
            "duration_s": outcome.duration_s,
            "argv": outcome.argv,
            "stdout": outcome.stdout[-20_000:],
            "stderr": outcome.stderr[-20_000:],
        }

    @staticmethod
    def outcome_from_json(data: dict[str, Any]) -> ExecutionOutcome:
        return ExecutionOutcome(
            clean=bool(data.get("clean")),
            rc=data.get("rc"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            duration_s=float(data.get("duration_s", 0.0)),
            timed_out=bool(data.get("timed_out")),
            argv=list(data.get("argv", [])),
            env=dict(data.get("env", {})),
        )


def dump_outcome(outcome: ExecutionOutcome) -> str:
    return json.dumps(PocRunner.outcome_to_json(outcome), indent=2)
