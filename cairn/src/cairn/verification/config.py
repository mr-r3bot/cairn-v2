"""Verification pipeline configuration (Cairn v2, Phases 2-8)."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from cairn.sandbox.config import DEFAULT_DATA_HOME, SandboxConfig


class BudgetConfig(BaseModel):
    """Hard caps for one verification run (Phase 6).

    On breach the run pauses and concludes ``inconclusive / BUDGET_EXHAUSTED``
    unless a verdict is already derivable.  The deterministic pipeline costs
    no tokens, so token caps are advisory (used once worker-assisted steps
    land).
    """

    wall_clock_s: int = Field(default=1800, ge=10)
    max_steps: int = Field(default=60, ge=1)
    max_payload_runs: int = Field(default=20, ge=1)
    max_cost_usd: float = Field(default=5.0, gt=0)
    max_tokens: int = Field(default=1_500_000, ge=1)


class VerificationConfig(BaseModel):
    """Everything the verification pipeline needs besides the sandbox itself."""

    enabled: bool = True

    # alias the booted target is reachable at, from payload and probe alike
    endpoint_alias: str = "target"

    # container that drives docker compose / docker build through the socket
    builder_image: str = "docker:cli"
    # container that clones the pinned checkout
    git_image: str = "alpine/git"
    # image for health probes on the run network
    probe_image: str = "python:3.13-slim"
    # default image PoC payloads run in (script PoCs need python3+bash)
    poc_image: str = "python:3.13-slim"

    # docker socket as the daemon sees it (mounted into builder containers)
    docker_socket: str = "/var/run/docker.sock"

    healthcheck_timeout_s: int = Field(default=180, ge=5)
    healthcheck_interval_s: float = Field(default=2.0, gt=0)
    # candidate ports probed when the repo does not advertise one
    health_ports: list[int] = Field(
        default_factory=lambda: [8080, 8090, 3000, 80, 8000, 5000, 9000, 8888, 443]
    )

    # where evidence bundles are written (dispatcher side); shared with the
    # server via the datas volume so the read API can serve them
    evidence_home: Path | None = None  # default: sandbox.data_home / "evidence"
    # where pinned checkouts are cloned to (dispatcher side)
    checkout_home: Path | None = None  # default: sandbox.data_home / "checkouts"

    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    def evidence_root(self) -> Path:
        root = self.evidence_home or (self.sandbox.data_home / "evidence")
        root.mkdir(parents=True, exist_ok=True)
        return root

    def checkout_root(self) -> Path:
        root = self.checkout_home or (self.sandbox.data_home / "checkouts")
        root.mkdir(parents=True, exist_ok=True)
        return root

    def compose_project(self, run_id: str) -> str:
        cleaned = "".join(ch if ch.isalnum() else "-" for ch in run_id.lower())
        return f"cairnsbx{cleaned}"[:56]
