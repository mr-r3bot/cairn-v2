"""Full-auto mode (Cairn v2, Phase 8).

``claim JSON in → verdict + exit code out``, no console needed.  Exit codes:

- ``1`` — ``reproduced`` (CI fails on a confirmed live vulnerability),
- ``0`` — any other terminal verdict (per plan: zero otherwise),
- ``2`` — operational failure (sandbox guard refused, server unreachable,
  or no verdict within the wait window).

Guard: auto mode refuses to run when the server reports no sandbox
(the dispatcher registers its state at startup) unless
``allow_no_sandbox`` is set — nothing executes attacker code without the
Phase 1 substrate.
"""

from __future__ import annotations

import json
import time
from typing import Any


class AutoError(RuntimeError):
    exit_code = 2


class AutoRunner:
    def __init__(
        self,
        session: Any,
        base_url: str = "http://127.0.0.1:8000",
        *,
        allow_no_sandbox: bool = False,
        timeout_s: float = 1800.0,
        poll_s: float = 3.0,
    ):
        self.session = session
        self.base = base_url.rstrip("/")
        self.allow_no_sandbox = allow_no_sandbox
        self.timeout_s = timeout_s
        self.poll_s = poll_s

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def check_sandbox(self) -> None:
        response = self.session.get(self._url("/verification/system"))
        if response.status_code != 200:
            raise AutoError(f"cannot read verification state (HTTP {response.status_code})")
        state = response.json()
        if not state.get("sandbox_available") and not self.allow_no_sandbox:
            raise AutoError(
                "verification sandbox unavailable — auto mode refuses to run "
                "without the sandbox (override with --allow-no-sandbox): "
                + str(state.get("note", ""))
            )

    def ingest(self, claim: dict) -> tuple[str, str]:
        response = self.session.post(self._url("/claims"), json=claim)
        if response.status_code not in (200, 201):
            raise AutoError(f"claim rejected (HTTP {response.status_code}): {response.text[:400]}")
        data = response.json()
        return data["claim"]["id"], data["project_id"]

    def wait_verdict(self, project_id: str) -> dict:
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            response = self.session.get(self._url(f"/projects/{project_id}/verdict"))
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                time.sleep(self.poll_s)
                continue
            raise AutoError(f"verdict poll failed (HTTP {response.status_code})")
        raise AutoError(f"no verdict within {self.timeout_s:.0f}s — is the dispatcher running?")

    def run(self, claim: dict) -> tuple[int, dict]:
        """Full cycle: guard → ingest → wait → exit code."""
        self.check_sandbox()
        claim_id, project_id = self.ingest(claim)
        verdict = self.wait_verdict(project_id)
        return self.exit_code(verdict), verdict

    @staticmethod
    def exit_code(verdict: dict) -> int:
        """1 on reproduced (CI fails on a confirmed live vuln), 0 otherwise."""
        return 1 if verdict["status"] == "reproduced" else 0

    # ------------------------------------------------------------------

    @staticmethod
    def load_claim_file(path: str) -> dict:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
